package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"dns-supreme-mini/internal/config"

	mdns "github.com/miekg/dns"
)

type QueryResult struct {
	ClientIP       string
	ClientHostname string
	Domain         string
	QueryType      string
	Blocked        bool
	BlockRule      string
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
	cfg             config.DNSConfig
	udpServer       *mdns.Server
	tcpServer       *mdns.Server
	cache           *Cache
	filterFn        FilterFunc
	logFn           LogFunc
	forwarders      []string
	blockPageIP     net.IP
	blockPageDomain string
	onBlock         func(domain, reason string)
	responseFilterFn ResponseFilterFunc
	hostnameCache   map[string]string
	hostnameMu      sync.RWMutex
	rateLimiter     map[string]*rateBucket
	rateLimiterMu   sync.Mutex
	mu              sync.RWMutex
}

type rateBucket struct {
	tokens    int
	lastReset time.Time
}

const (
	rateLimit  = 100
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
	return bucket.tokens <= rateLimit
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

func NewServer(cfg config.DNSConfig, filterFn FilterFunc, logFn LogFunc) *Server {
	s := &Server{
		cfg:           cfg,
		cache:         NewCache(cfg.CacheSize),
		filterFn:      filterFn,
		logFn:         logFn,
		forwarders:    cfg.Forwarders,
		hostnameCache: make(map[string]string),
		rateLimiter:   make(map[string]*rateBucket),
	}
	s.startRateLimitCleanup()
	return s
}

func (s *Server) CacheSize() int {
	return s.cache.Size()
}

func (s *Server) FlushCache() {
	s.cache.Flush()
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

func (s *Server) SetResponseFilter(fn ResponseFilterFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responseFilterFn = fn
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

func (s *Server) resolveHostname(ip string) string {
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

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, host)
	hostname := ""
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	s.hostnameMu.Lock()
	s.hostnameCache[host] = hostname
	if len(s.hostnameCache) > 5000 {
		count := 0
		for k := range s.hostnameCache {
			delete(s.hostnameCache, k)
			count++
			if count >= 1000 {
				break
			}
		}
	}
	s.hostnameMu.Unlock()

	return hostname
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	handler := mdns.HandlerFunc(s.handleDNS)

	s.udpServer = &mdns.Server{Addr: addr, Net: "udp", Handler: handler}
	s.tcpServer = &mdns.Server{Addr: addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 2)

	go func() {
		slog.Info("UDP listener starting", "component", "dns", "addr", addr)
		errCh <- s.udpServer.ListenAndServe()
	}()
	go func() {
		slog.Info("TCP listener starting", "component", "dns", "addr", addr)
		errCh <- s.tcpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed: %w", err)
	case <-time.After(500 * time.Millisecond):
		slog.Info("server running", "component", "dns", "addr", addr, "protocols", "UDP+TCP")
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
}

func (s *Server) handleDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	resp := s.processDNSMsg(r, remoteAddrStr(w), "udp/tcp")
	if resp != nil {
		w.WriteMsg(resp)
	} else {
		mdns.HandleFailed(w, r)
	}
}

func (s *Server) processDNSMsg(r *mdns.Msg, clientAddr string, protocol string) *mdns.Msg {
	start := time.Now()

	if len(r.Question) == 0 {
		return nil
	}

	if !s.checkRateLimit(clientAddr) {
		msg := new(mdns.Msg)
		msg.SetRcode(r, mdns.RcodeRefused)
		return msg
	}

	q := r.Question[0]
	domain := q.Name
	qtype := q.Qtype

	result := &QueryResult{
		ClientIP:       clientAddr,
		ClientHostname: s.resolveHostname(clientAddr),
		Domain:         domain,
		QueryType:      mdns.TypeToString[qtype],
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
		if queryDomain == bpDomain && (qtype == mdns.TypeA || qtype == mdns.TypeAAAA) {
			msg := new(mdns.Msg)
			msg.SetReply(r)
			if qtype == mdns.TypeA && bpIPForDomain.To4() != nil {
				msg.Answer = append(msg.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
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

	// Filter check
	if s.filterFn != nil {
		blocked, rule := s.filterFn(domain, qtype)
		if blocked {
			result.Blocked = true
			result.BlockRule = rule
			result.Latency = time.Since(start)

			msg := new(mdns.Msg)
			msg.SetReply(r)

			s.mu.RLock()
			bpIP := s.blockPageIP
			onBlock := s.onBlock
			s.mu.RUnlock()

			if bpIP != nil && (qtype == mdns.TypeA || qtype == mdns.TypeAAAA) {
				if qtype == mdns.TypeA && bpIP.To4() != nil {
					msg.Answer = append(msg.Answer, &mdns.A{
						Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
						A:   bpIP.To4(),
					})
				}
				result.ResponseIP = bpIP.String()
				if onBlock != nil {
					onBlock(domain, rule)
				}
			} else {
				msg.Rcode = mdns.RcodeNameError
			}

			if s.logFn != nil {
				s.logFn(result)
			}
			return msg
		}
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

				msg := new(mdns.Msg)
				msg.SetReply(r)

				if bpIP != nil && (qtype == mdns.TypeA || qtype == mdns.TypeAAAA) {
					if qtype == mdns.TypeA && bpIP.To4() != nil {
						msg.Answer = append(msg.Answer, &mdns.A{
							Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
							A:   bpIP.To4(),
						})
					}
					result.ResponseIP = bpIP.String()
					if onBlock != nil {
						onBlock(domain, rule)
					}
				} else {
					msg.Rcode = mdns.RcodeNameError
				}

				if s.logFn != nil {
					s.logFn(result)
				}
				return msg
			}
		}
	}

	if resp.Rcode == mdns.RcodeSuccess {
		if ttl := s.extractMinTTL(resp); ttl > 0 {
			s.cache.Set(cacheKey, resp, ttl)
		}
	}

	if s.logFn != nil {
		s.logFn(result)
	}
	return resp
}

func remoteAddrStr(w mdns.ResponseWriter) string {
	if addr := w.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (s *Server) forward(r *mdns.Msg) (*mdns.Msg, string, error) {
	s.mu.RLock()
	forwarders := s.forwarders
	s.mu.RUnlock()

	if len(forwarders) == 0 {
		return nil, "", fmt.Errorf("no forwarders configured")
	}

	if len(forwarders) == 1 {
		c := new(mdns.Client)
		c.Timeout = 5 * time.Second
		resp, _, err := c.Exchange(r, forwarders[0])
		if err == nil && resp != nil {
			return resp, forwarders[0], nil
		}
		return nil, "", fmt.Errorf("forwarder %s failed: %w", forwarders[0], err)
	}

	type result struct {
		resp *mdns.Msg
		fw   string
		err  error
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch := make(chan result, len(forwarders))

	for _, fw := range forwarders {
		go func(fw string) {
			c := new(mdns.Client)
			c.Timeout = 5 * time.Second
			resp, _, err := c.ExchangeContext(ctx, r.Copy(), fw)
			ch <- result{resp, fw, err}
		}(fw)
	}

	for range forwarders {
		res := <-ch
		if res.err == nil && res.resp != nil {
			cancel()
			return res.resp, res.fw, nil
		}
	}

	return nil, "", fmt.Errorf("all forwarders failed")
}

func extractIP(rr mdns.RR) string {
	switch v := rr.(type) {
	case *mdns.A:
		return v.A.String()
	case *mdns.AAAA:
		return v.AAAA.String()
	default:
		return ""
	}
}

func (s *Server) extractMinTTL(msg *mdns.Msg) time.Duration {
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
