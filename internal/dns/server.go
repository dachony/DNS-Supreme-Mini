package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dns-supreme-mini/internal/config"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

type QueryResult struct {
	ClientIP       string
	ClientHostname string
	Domain         string
	QueryType      string
	Blocked        bool
	BlockRule       string
	ResponseIP     string
	Latency        time.Duration
	Timestamp      time.Time
	Upstream       string
	Protocol       string
}

type FilterFunc func(domain string, qtype uint16) (blocked bool, rule string)
type ResponseFilterFunc func(ip string) (blocked bool, reason string, category string)
type LogFunc func(result *QueryResult)

type Server struct {
	cfg        config.DNSConfig
	udpServer  *dns.Server
	tcpServer  *dns.Server
	dotServer  *dns.Server
	quicLn     *quic.Listener
	cache      *Cache
	filterFn   FilterFunc
	logFn      LogFunc
	forwarders []string
	tlsConfig  *tls.Config
	zoneLookup    ZoneLookupFunc
	zoneDataFn    ZoneDataFunc
	blockPageIP      net.IP
	blockPageDomain  string
	onBlock          func(domain, reason string)
	responseFilterFn ResponseFilterFunc
	acmeTxtLookup    func(fqdn string) string // lookup ACME challenge TXT records
	axfrAllowIPs     []net.IPNet
	hostnameCache    map[string]string // IP -> hostname cache
	hostnameMu       sync.RWMutex
	rateLimiter      map[string]*rateBucket
	rateLimiterMu    sync.Mutex
	mu               sync.RWMutex
}

type rateBucket struct {
	tokens    int
	lastReset time.Time
}

const (
	rateLimit  = 100 // queries per window
	rateWindow = 10 * time.Second
)

func (s *Server) checkRateLimit(clientIP string) bool {
	host, _, _ := net.SplitHostPort(clientIP)
	if host == "" {
		host = clientIP
	}

	s.rateLimiterMu.Lock()
	defer s.rateLimiterMu.Unlock()

	if s.rateLimiter == nil {
		s.rateLimiter = make(map[string]*rateBucket)
	}

	bucket, ok := s.rateLimiter[host]
	if !ok || time.Since(bucket.lastReset) > rateWindow {
		s.rateLimiter[host] = &rateBucket{tokens: 1, lastReset: time.Now()}
		return true
	}

	bucket.tokens++
	if bucket.tokens > rateLimit {
		return false
	}
	return true
}

func (s *Server) startRateLimitCleanup() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			s.rateLimiterMu.Lock()
			for ip, bucket := range s.rateLimiter {
				if time.Since(bucket.lastReset) > rateWindow*2 {
					delete(s.rateLimiter, ip)
				}
			}
			s.rateLimiterMu.Unlock()
		}
	}()
}

func (s *Server) SetAXFRAllowIPs(cidrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var nets []net.IPNet
	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, *ipnet)
		}
	}
	s.axfrAllowIPs = nets
}

func (s *Server) isAXFRAllowed(addr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.axfrAllowIPs) == 0 {
		return true // no restriction if not configured
	}
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.axfrAllowIPs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) SetResponseFilter(fn ResponseFilterFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responseFilterFn = fn
}

func (s *Server) CacheSize() int {
	return s.cache.Size()
}

func (s *Server) FlushCache() {
	s.cache.Flush()
}

func (s *Server) ReloadTLS(tlsCfg *tls.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsConfig = tlsCfg
}

func (s *Server) SetBlockPage(ip string, onBlock func(domain, reason string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockPageIP = net.ParseIP(ip)
	s.onBlock = onBlock
}

func (s *Server) SetBlockPageDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockPageDomain = strings.TrimSuffix(strings.ToLower(domain), ".")
}

func (s *Server) GetBlockPageDomain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockPageDomain
}

func (s *Server) GetBlockPageIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.blockPageIP == nil {
		return ""
	}
	return s.blockPageIP.String()
}

// SetACMETxtLookup sets the function to resolve ACME DNS-01 challenge TXT records
func (s *Server) SetACMETxtLookup(fn func(fqdn string) string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acmeTxtLookup = fn
}

func NewServer(cfg config.DNSConfig, filterFn FilterFunc, logFn LogFunc, tlsCfg *tls.Config) *Server {
	s := &Server{
		cfg:           cfg,
		cache:         NewCache(cfg.CacheSize),
		filterFn:      filterFn,
		logFn:         logFn,
		forwarders:    cfg.Forwarders,
		tlsConfig:     tlsCfg,
		hostnameCache: make(map[string]string),
		rateLimiter:   make(map[string]*rateBucket),
	}
	s.startRateLimitCleanup()
	return s
}

func (s *Server) resolveHostname(ip string) string {
	// Strip port
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}

	s.hostnameMu.RLock()
	cached, ok := s.hostnameCache[host]
	s.hostnameMu.RUnlock()
	if ok {
		return cached
	}

	// Reverse lookup with timeout to avoid blocking the query path
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, host)
	hostname := ""
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	s.hostnameMu.Lock()
	s.hostnameCache[host] = hostname
	// Limit cache size
	if len(s.hostnameCache) > 10000 {
		// Evict ~20% of entries
		count := 0
		for k := range s.hostnameCache {
			delete(s.hostnameCache, k)
			count++
			if count >= 2000 {
				break
			}
		}
	}
	s.hostnameMu.Unlock()

	return hostname
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	handler := dns.HandlerFunc(s.handleDNS)

	s.udpServer = &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	s.tcpServer = &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 4)

	go func() {
		slog.Info("UDP listener starting", "component", "dns", "addr", addr)
		errCh <- s.udpServer.ListenAndServe()
	}()
	go func() {
		slog.Info("TCP listener starting", "component", "dns", "addr", addr)
		errCh <- s.tcpServer.ListenAndServe()
	}()

	if s.tlsConfig != nil {
		// DoT on port 853
		dotAddr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, 853)
		s.dotServer = &dns.Server{
			Addr:      dotAddr,
			Net:       "tcp-tls",
			TLSConfig: s.tlsConfig,
			Handler:   dns.HandlerFunc(s.handleDoT),
		}
		go func() {
			slog.Info("DoT listener starting", "component", "dns", "addr", dotAddr)
			if err := s.dotServer.ListenAndServe(); err != nil {
				slog.Error("DoT listener error", "component", "dns", "error", err)
			}
		}()

		// DoH is handled by block page server on port 443 via SetDoHHandler()

		// DoQ on port 853/udp (RFC 9250 — same port as DoT but UDP)
		go s.startDoQ()
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed: %w", err)
	case <-time.After(500 * time.Millisecond):
		slog.Info("server running", "component", "dns", "addr", addr, "protocols", "UDP+TCP")
		if s.tlsConfig != nil {
			slog.Info("encrypted DNS listeners active", "component", "dns", "dot", ":853", "doh", ":443", "doq", ":853/udp")
		}
		return nil
	}
}

func (s *Server) Shutdown() {
	if s.udpServer != nil {
		s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		s.tcpServer.Shutdown()
	}
	if s.dotServer != nil {
		s.dotServer.Shutdown()
	}
	if s.quicLn != nil {
		s.quicLn.Close()
	}
}

// --- DoT ---

func (s *Server) handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	resp := s.processDNSMsg(r, remoteAddrStr(w), "dot")
	if resp != nil {
		w.WriteMsg(resp)
	} else {
		dns.HandleFailed(w, r)
	}
}

// --- DoH (RFC 8484) ---

// DoHHandler returns an http.Handler for DNS-over-HTTPS requests.
func (s *Server) DoHHandler() http.Handler {
	return http.HandlerFunc(s.handleDoH)
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msgBytes []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		msgBytes, err = base64.RawURLEncoding.DecodeString(param)
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "invalid content type", http.StatusUnsupportedMediaType)
			return
		}
		msgBytes, err = io.ReadAll(io.LimitReader(r.Body, 65535))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil || len(msgBytes) == 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	resp := s.processDNSMsg(msg, r.RemoteAddr, "doh")
	if resp == nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	respBytes, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// --- DoQ (RFC 9250) ---

func (s *Server) startDoQ() {
	doqAddr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, 853)
	tlsCfg := s.tlsConfig.Clone()
	tlsCfg.NextProtos = []string{"doq"}

	ln, err := quic.ListenAddr(doqAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		slog.Error("DoQ failed to start", "component", "dns", "error", err)
		return
	}
	s.quicLn = ln
	slog.Info("DoQ listener started", "component", "dns", "addr", doqAddr)

	ctx := context.Background()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		go s.handleDoQConn(ctx, conn)
	}
}

func (s *Server) handleDoQConn(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleDoQStream(stream, conn.RemoteAddr().String())
	}
}

func (s *Server) handleDoQStream(stream quic.Stream, clientAddr string) {
	defer stream.Close()

	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return
	}
	if length == 0 || length > 65535 {
		return
	}

	msgBytes := make([]byte, length)
	if _, err := io.ReadFull(stream, msgBytes); err != nil {
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		return
	}

	resp := s.processDNSMsg(msg, clientAddr, "doq")
	if resp == nil {
		return
	}

	respBytes, err := resp.Pack()
	if err != nil {
		return
	}

	binary.Write(stream, binary.BigEndian, uint16(len(respBytes)))
	stream.Write(respBytes)
}

// --- Core processing ---

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Handle AXFR requests
	if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAXFR {
		s.handleAXFR(w, r)
		return
	}

	resp := s.processDNSMsg(r, remoteAddrStr(w), "udp/tcp")
	if resp != nil {
		w.WriteMsg(resp)
	} else {
		dns.HandleFailed(w, r)
	}
}

func (s *Server) processDNSMsg(r *dns.Msg, clientAddr string, protocol string) *dns.Msg {
	start := time.Now()

	if len(r.Question) == 0 {
		return nil
	}

	if !s.checkRateLimit(clientAddr) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeRefused)
		return msg
	}

	q := r.Question[0]
	domain := q.Name
	qtype := q.Qtype

	result := &QueryResult{
		ClientIP:       clientAddr,
		ClientHostname: s.resolveHostname(clientAddr),
		Domain:         domain,
		QueryType:      dns.TypeToString[qtype],
		Timestamp:      start,
		Protocol:       protocol,
	}

	// Block page domain resolves to block page IP
	s.mu.RLock()
	bpDomain := s.blockPageDomain
	bpIPForDomain := s.blockPageIP
	s.mu.RUnlock()
	if bpDomain != "" && bpIPForDomain != nil {
		queryDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
		if queryDomain == bpDomain && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
			msg := new(dns.Msg)
			msg.SetReply(r)
			if qtype == dns.TypeA && bpIPForDomain.To4() != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   bpIPForDomain.To4(),
				})
			}
			result.Upstream = "blockpage"
			result.ResponseIP = bpIPForDomain.String()
			result.Latency = time.Since(start)
			if s.logFn != nil {
				s.logFn(result)
			}
			return msg
		}
	}

	// ACME DNS-01 challenge — serve TXT records for _acme-challenge domains
	if qtype == dns.TypeTXT && strings.HasPrefix(strings.ToLower(domain), "_acme-challenge.") {
		s.mu.RLock()
		acmeLookup := s.acmeTxtLookup
		s.mu.RUnlock()
		if acmeLookup != nil {
			fqdn := strings.TrimSuffix(strings.ToLower(domain), ".")
			if txtValue := acmeLookup(fqdn); txtValue != "" {
				msg := new(dns.Msg)
				msg.SetReply(r)
				msg.Authoritative = true
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{txtValue},
				})
				result.Upstream = "acme"
				result.Latency = time.Since(start)
				slog.Info("served ACME challenge TXT", "component", "dns", "fqdn", fqdn, "value", txtValue[:8]+"...")
				if s.logFn != nil {
					s.logFn(result)
				}
				return msg
			}
		}
	}

	// Filter check
	if s.filterFn != nil {
		blocked, rule := s.filterFn(domain, qtype)
		if blocked {
			result.Blocked = true
			result.BlockRule = rule
			result.Latency = time.Since(start)

			msg := new(dns.Msg)
			msg.SetReply(r)

			s.mu.RLock()
			bpIP := s.blockPageIP
			onBlock := s.onBlock
			s.mu.RUnlock()

			if bpIP != nil && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
				// Return block page IP instead of NXDOMAIN
				if qtype == dns.TypeA && bpIP.To4() != nil {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   bpIP.To4(),
					})
				}
				result.ResponseIP = bpIP.String()
				if onBlock != nil {
					onBlock(domain, rule)
				}
			} else {
				msg.Rcode = dns.RcodeNameError
			}

			if s.logFn != nil {
				s.logFn(result)
			}
			return msg
		}
	}

	// Zone lookup (authoritative)
	if zoneResp := s.resolveFromZones(domain, qtype); zoneResp != nil {
		zoneResp.SetReply(r)
		zoneResp.Authoritative = true
		result.Latency = time.Since(start)
		result.Upstream = "zone"
		if s.logFn != nil {
			s.logFn(result)
		}
		if len(zoneResp.Answer) > 0 {
			result.ResponseIP = extractIP(zoneResp.Answer[0])
		}
		return zoneResp
	}

	// Cache check
	cacheKey := fmt.Sprintf("%s-%d", domain, qtype)
	if cached, ok := s.cache.Get(cacheKey); ok {
		msg := cached.Copy()
		msg.Id = r.Id
		result.Latency = time.Since(start)
		result.Upstream = "cache"
		if s.logFn != nil {
			s.logFn(result)
		}
		return msg
	}

	// Forward
	resp, upstream, err := s.forward(r)
	if err != nil {
		slog.Error("forward error", "component", "dns", "domain", domain, "error", err)
		return nil
	}

	result.Upstream = upstream
	result.Latency = time.Since(start)
	if len(resp.Answer) > 0 {
		result.ResponseIP = extractIP(resp.Answer[0])
	}

	// Network protection: check destination IPs in the response
	s.mu.RLock()
	respFilter := s.responseFilterFn
	bpIP := s.blockPageIP
	onBlock := s.onBlock
	s.mu.RUnlock()

	if respFilter != nil && len(resp.Answer) > 0 {
		for _, rr := range resp.Answer {
			ansIP := extractIP(rr)
			if ansIP == "" {
				continue
			}
			if blocked, rule, _ := respFilter(ansIP); blocked {
				result.Blocked = true
				result.BlockRule = rule
				result.Latency = time.Since(start)

				msg := new(dns.Msg)
				msg.SetReply(r)

				if bpIP != nil && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
					if qtype == dns.TypeA && bpIP.To4() != nil {
						msg.Answer = append(msg.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   bpIP.To4(),
						})
					}
					result.ResponseIP = bpIP.String()
					if onBlock != nil {
						onBlock(domain, rule)
					}
				} else {
					msg.Rcode = dns.RcodeNameError
				}

				if s.logFn != nil {
					s.logFn(result)
				}
				return msg
			}
		}
	}

	if resp.Rcode == dns.RcodeSuccess {
		if ttl := s.extractMinTTL(resp); ttl > 0 {
			s.cache.Set(cacheKey, resp, ttl)
		}
	}

	if s.logFn != nil {
		s.logFn(result)
	}
	return resp
}

func remoteAddrStr(w dns.ResponseWriter) string {
	if addr := w.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (s *Server) GetForwarders() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, len(s.forwarders))
	copy(result, s.forwarders)
	return result
}

func (s *Server) SetForwarders(fwds []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forwarders = fwds
}

func (s *Server) forward(r *dns.Msg) (*dns.Msg, string, error) {
	s.mu.RLock()
	forwarders := s.forwarders
	s.mu.RUnlock()

	if len(forwarders) == 0 {
		return nil, "", fmt.Errorf("no forwarders configured")
	}

	// Single forwarder — no need for goroutines
	if len(forwarders) == 1 {
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		resp, _, err := c.Exchange(r, forwarders[0])
		if err == nil && resp != nil {
			return resp, forwarders[0], nil
		}
		return nil, "", fmt.Errorf("forwarder %s failed: %w", forwarders[0], err)
	}

	type result struct {
		resp *dns.Msg
		fw   string
		err  error
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := make(chan result, len(forwarders))

	for _, fw := range forwarders {
		go func(fw string) {
			c := new(dns.Client)
			c.Timeout = 5 * time.Second
			resp, _, err := c.ExchangeContext(ctx, r.Copy(), fw)
			ch <- result{resp, fw, err}
		}(fw)
	}

	for range forwarders {
		res := <-ch
		if res.err == nil && res.resp != nil {
			cancel() // cancel remaining
			return res.resp, res.fw, nil
		}
	}

	return nil, "", fmt.Errorf("all forwarders failed")
}

func extractIP(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	default:
		return ""
	}
}

func (s *Server) extractMinTTL(msg *dns.Msg) time.Duration {
	minTTL := uint32(300)
	for _, rr := range msg.Answer {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}
	floor := uint32(s.cfg.CacheMinTTL)
	if floor == 0 {
		floor = 10
	}
	if minTTL < floor {
		minTTL = floor
	}
	ceiling := uint32(s.cfg.CacheMaxTTL)
	if ceiling > 0 && minTTL > ceiling {
		minTTL = ceiling
	}
	return time.Duration(minTTL) * time.Second
}
