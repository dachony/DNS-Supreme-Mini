package blockpage

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

var defaultTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Blocked — DNS-supreme</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #0f172a; color: #e2e8f0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}
.card {
  background: #1e293b; border: 1px solid #334155; border-radius: 16px;
  padding: 48px; max-width: 520px; text-align: center;
}
.icon { font-size: 3rem; margin-bottom: 16px; }
h1 { color: #ef4444; font-size: 1.5rem; margin-bottom: 8px; }
.domain { color: #f59e0b; font-family: monospace; font-size: 1.1rem; margin: 16px 0;
  background: #0f172a; padding: 8px 16px; border-radius: 8px; word-break: break-all; }
.reason { color: #94a3b8; font-size: 0.9rem; margin-bottom: 24px; }
.info { color: #475569; font-size: 0.8rem; line-height: 1.6; }
.brand { color: #38bdf8; font-weight: 700; margin-top: 24px; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#x1F6AB;</div>
  <h1>Access Blocked</h1>
  <div class="domain">{{.Domain}}</div>
  <div class="reason">{{.Reason}}</div>
  <div class="info">
    This domain has been blocked by your DNS filtering policy.<br>
    If you believe this is a mistake, contact your administrator.
  </div>
  <div class="brand">DNS-supreme</div>
</div>
</body>
</html>`

type BlockInfo struct {
	Domain string
	Reason string
}

type Server struct {
	listenAddr   string
	httpPort     int
	httpsPort    int
	tlsConfig    *tls.Config
	blockPageCert *tls.Certificate // dedicated cert for block page domain
	tmpl         *template.Template
	customHTML   string
	blockMap     map[string]string
	redirectURL  string // base URL to redirect blocked requests to (e.g. "http://192.168.1.1" or "http://block.example.com")
	dohHandler   http.Handler
	mu           sync.RWMutex
}

func NewServer(listenAddr string, httpPort, httpsPort int, tlsCfg *tls.Config) *Server {
	tmpl, _ := template.New("block").Parse(defaultTemplate)
	return &Server{
		listenAddr: listenAddr,
		httpPort:   httpPort,
		httpsPort:  httpsPort,
		tlsConfig:  tlsCfg,
		tmpl:       tmpl,
		blockMap:   make(map[string]string),
	}
}

// SetRedirectURL sets the block page redirect URL (IP or domain).
// When set, blocked requests are redirected to this URL instead of serving inline.
func (s *Server) SetRedirectURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirectURL = strings.TrimRight(url, "/")
	slog.Info("block page redirect URL set", "component", "blockpage", "url", url)
}

// GetRedirectURL returns the current redirect URL
func (s *Server) GetRedirectURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.redirectURL
}

func (s *Server) SetCustomTemplate(html string) error {
	tmpl, err := template.New("block").Parse(html)
	if err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}
	s.mu.Lock()
	s.tmpl = tmpl
	s.customHTML = html
	s.mu.Unlock()
	return nil
}

func (s *Server) GetCustomTemplate() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.customHTML
}

func (s *Server) RecordBlock(domain, reason string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	s.mu.Lock()
	s.blockMap[domain] = reason
	s.mu.Unlock()
}

func (s *Server) ReloadTLS(tlsCfg *tls.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsConfig = tlsCfg
}

// SetBlockPageCert loads a dedicated TLS certificate for the block page domain
func (s *Server) SetBlockPageCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load block page cert: %w", err)
	}
	s.mu.Lock()
	s.blockPageCert = &cert
	s.mu.Unlock()
	slog.Info("block page certificate loaded", "component", "blockpage", "cert", certFile)
	return nil
}

func (s *Server) SetDoHHandler(handler http.Handler) {
	s.dohHandler = handler
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	if s.dohHandler != nil {
		mux.Handle("/dns-query", s.dohHandler)
	}
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("/app/data/uploads"))))
	mux.HandleFunc("/", s.handleBlock)

	// HTTP on port 80
	httpAddr := fmt.Sprintf("%s:%d", s.listenAddr, s.httpPort)
	go func() {
		slog.Info("HTTP server starting", "component", "blockpage", "addr", httpAddr)
		if err := http.ListenAndServe(httpAddr, mux); err != nil {
			slog.Error("HTTP server error", "component", "blockpage", "error", err)
		}
	}()

	// HTTPS on port 443 (if TLS configured)
	if s.tlsConfig != nil && s.httpsPort > 0 {
		httpsAddr := fmt.Sprintf("%s:%d", s.listenAddr, s.httpsPort)
		// Use GetCertificate callback so cert reloads take effect without restart
		dynamicTLS := &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				s.mu.RLock()
				bpCert := s.blockPageCert
				cfg := s.tlsConfig
				s.mu.RUnlock()
				// Prefer dedicated block page cert if available
				if bpCert != nil {
					return bpCert, nil
				}
				if cfg == nil || len(cfg.Certificates) == 0 {
					return nil, fmt.Errorf("no certificate configured")
				}
				return &cfg.Certificates[0], nil
			},
		}
		httpsServer := &http.Server{
			Addr:      httpsAddr,
			Handler:   mux,
			TLSConfig: dynamicTLS,
		}
		go func() {
			slog.Info("HTTPS server starting", "component", "blockpage", "addr", httpsAddr)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
				slog.Error("HTTPS server error", "component", "blockpage", "error", err)
			}
		}()
	}

	return nil
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	// If path is /blocked, render block page from query params
	if r.URL.Path == "/blocked" {
		domain := r.URL.Query().Get("domain")
		reason := r.URL.Query().Get("reason")
		if domain == "" {
			domain = "unknown"
		}
		if reason == "" {
			reason = "Domain blocked by DNS filtering policy"
		}
		s.mu.RLock()
		tmpl := s.tmpl
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		tmpl.Execute(w, BlockInfo{Domain: domain, Reason: reason})
		return
	}

	domain := r.Host
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	domain = strings.ToLower(domain)

	s.mu.RLock()
	reason, ok := s.blockMap[domain]
	redirectURL := s.redirectURL
	tmpl := s.tmpl
	s.mu.RUnlock()

	if !ok {
		reason = "Domain blocked by DNS filtering policy"
	}

	// If redirect URL is set and the request host is NOT the block page itself, redirect
	if redirectURL != "" {
		blockHost := strings.TrimPrefix(redirectURL, "https://")
		blockHost = strings.TrimPrefix(blockHost, "http://")
		blockHost = strings.Split(blockHost, "/")[0]
		blockHost = strings.Split(blockHost, ":")[0]

		if domain != blockHost {
			target := fmt.Sprintf("%s/blocked?domain=%s&reason=%s",
				redirectURL,
				template.URLQueryEscaper(domain),
				template.URLQueryEscaper(reason),
			)
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}

	// Fallback: render block page inline (when no redirect URL or request is to block page itself)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	tmpl.Execute(w, BlockInfo{Domain: domain, Reason: reason})
}
