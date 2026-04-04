package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"dns-supreme-mini/internal/certs"
	"github.com/gin-gonic/gin"
)

type certInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	IsCA      bool      `json:"is_ca"`
	CertFile  string    `json:"cert_file"`
	KeyFile   string    `json:"key_file"`
}

func (s *Server) getCerts(c *gin.Context) {
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "/app/certs/server.crt"
	}

	info, err := readCertInfo(certFile)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "self-signed (auto-generated)",
			"message": "Using auto-generated self-signed certificate",
		})
		return
	}

	c.JSON(http.StatusOK, info)
}

type generateCertReq struct {
	Domain             string   `json:"domain"`
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Country            string   `json:"country"`
	State              string   `json:"state"`
	Locality           string   `json:"locality"`
	DNSNames           []string `json:"dns_names"`
	ValidityDays       int      `json:"validity_days"`
}

func (s *Server) generateSelfSigned(c *gin.Context) {
	os.MkdirAll("/app/certs", 0755)

	var req generateCertReq
	c.ShouldBindJSON(&req)

	// Zone-specific cert
	if req.Domain != "" {
		certFile := "/app/certs/" + req.Domain + ".crt"
		keyFile := "/app/certs/" + req.Domain + ".key"
		cr := &certs.CertRequest{
			CommonName: req.Domain,
			DNSNames:   []string{req.Domain, "*." + req.Domain},
			ValidityDays: 365,
		}
		if err := certs.GenerateAndSave(certFile, keyFile, cr); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "Certificate generated for " + req.Domain + ". Apply to reload TLS.",
		})
		return
	}

	// Server cert
	certFile := "/app/certs/server.crt"
	keyFile := "/app/certs/server.key"

	cr := &certs.CertRequest{
		CommonName:         req.CommonName,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Country:            req.Country,
		State:              req.State,
		Locality:           req.Locality,
		DNSNames:           req.DNSNames,
		ValidityDays:       req.ValidityDays,
	}
	if cr.CommonName == "" {
		cr.CommonName = "dns-supreme"
	}

	if err := certs.GenerateAndSave(certFile, keyFile, cr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if data, err := json.Marshal(cr); err == nil {
		s.db.SetSetting("cert_params", string(data))
	}

	info, _ := readCertInfo(certFile)
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"message":   "Certificate generated. Apply to reload TLS.",
		"cert_info": info,
	})
}

func (s *Server) getCertZones(c *gin.Context) {
	entries, _ := os.ReadDir("/app/certs")
	zones := make([]string, 0)
	for _, e := range entries {
		name := e.Name()
		if name != "server.crt" && name != "server.key" && len(name) > 4 && name[len(name)-4:] == ".crt" {
			zones = append(zones, name[:len(name)-4])
		}
	}
	c.JSON(http.StatusOK, zones)
}

func (s *Server) deleteCert(c *gin.Context) {
	certFile := "/app/certs/server.crt"
	keyFile := "/app/certs/server.key"
	os.Remove(certFile)
	os.Remove(keyFile)
	slog.Info("server certificate deleted", "component", "certs")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Certificate deleted"})
}

func (s *Server) uploadCert(c *gin.Context) {
	certData, err := readFormFile(c, "cert")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cert file required"})
		return
	}
	keyData, err := readFormFile(c, "key")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key file required"})
		return
	}

	os.MkdirAll("/app/certs", 0755)
	if err := os.WriteFile("/app/certs/server.crt", certData, 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := os.WriteFile("/app/certs/server.key", keyData, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "Certificate uploaded. Restart to apply.",
	})
}

func (s *Server) exportCert(c *gin.Context) {
	format := c.Query("format")
	domain := c.Query("domain")

	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "/app/certs/server.crt"
	}
	// Domain-specific cert file
	if domain != "" {
		domainCert := "/app/certs/" + domain + ".crt"
		if _, err := os.Stat(domainCert); err == nil {
			certFile = domainCert
		}
	}

	// Return cert info as JSON
	if format == "info" {
		info, err := readCertInfo(certFile)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "No certificate found"})
			return
		}
		c.JSON(http.StatusOK, info)
		return
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No certificate found to export"})
		return
	}

	filename := "dns-supreme-ca"
	if domain != "" {
		filename = domain
	}

	if format == "der" {
		block, _ := pem.Decode(data)
		if block == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse certificate"})
			return
		}
		c.Header("Content-Disposition", "attachment; filename="+filename+".crt")
		c.Data(http.StatusOK, "application/x-x509-ca-cert", block.Bytes)
	} else {
		c.Header("Content-Disposition", "attachment; filename="+filename+".pem")
		c.Data(http.StatusOK, "application/x-pem-file", data)
	}
}

func readFormFile(c *gin.Context, name string) ([]byte, error) {
	fh, err := c.FormFile(name)
	if err != nil {
		return nil, err
	}
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func readCertInfo(certFile string) (*certInfo, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &certInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		DNSNames:  cert.DNSNames,
		IsCA:      cert.IsCA,
		CertFile:  certFile,
	}, nil
}

// --- ACME ---

func (s *Server) getACMEConfig(c *gin.Context) {
	cfg := s.acmeClient.GetConfig()
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) setACMEConfig(c *gin.Context) {
	var cfg certs.ACMEConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.acmeClient.SetConfig(cfg)
	// Persist
	if data, err := json.Marshal(cfg); err == nil {
		s.db.SetSetting("acme_config", string(data))
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type acmeRequestReq struct {
	Domain string `json:"domain"`
}

func (s *Server) loadACMEConfig() {
	if data := s.db.GetSetting("acme_config"); data != "" {
		var cfg certs.ACMEConfig
		if json.Unmarshal([]byte(data), &cfg) == nil {
			s.acmeClient.SetConfig(cfg)
		}
	}
}

func (s *Server) getACMEStatus(c *gin.Context) {
	domain := c.Param("domain")
	data := s.db.GetSetting("acme_status_" + domain)
	if data == "" {
		c.JSON(http.StatusOK, gin.H{"status": "none"})
		return
	}
	var status map[string]interface{}
	json.Unmarshal([]byte(data), &status)
	c.JSON(http.StatusOK, status)
}

// wireACMESolver sets up the DNS solver based on ACME config (local or Cloudflare)
func (s *Server) wireACMESolver() {
	cfg := s.acmeClient.GetConfig()
	if cfg.DNSProvider == "cloudflare" && cfg.CloudflareToken != "" {
		slog.Info("using Cloudflare DNS-01 solver", "component", "acme")
		s.acmeClient.SetDNSSolver(
			func(fqdn, value string) error {
				slog.Info("setting Cloudflare TXT record", "component", "acme", "fqdn", fqdn)
				return s.acmeClient.CloudflareDNSSet(fqdn, value)
			},
			func(fqdn string) error {
				slog.Info("clearing Cloudflare TXT record", "component", "acme", "fqdn", fqdn)
				return s.acmeClient.CloudflareDNSClear(fqdn)
			},
		)
	} else {
		slog.Info("using local DNS-01 solver", "component", "acme")
		s.acmeClient.SetDNSSolver(
			func(fqdn, value string) error {
				slog.Info("setting local DNS TXT record", "component", "acme", "fqdn", fqdn)
				return s.db.CreateACMERecord(fqdn, value)
			},
			func(fqdn string) error {
				slog.Info("clearing local DNS TXT record", "component", "acme", "fqdn", fqdn)
				return s.db.DeleteACMERecord(fqdn)
			},
		)
	}
}

func (s *Server) requestACMECert(c *gin.Context) {
	var req acmeRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain required"})
		return
	}

	// Wire DNS solver based on config (local or Cloudflare)
	s.wireACMESolver()

	// Store status and run in background
	s.db.SetSetting("acme_status_"+req.Domain, `{"status":"pending","domain":"`+req.Domain+`"}`)

	go func() {
		if err := s.acmeClient.RequestCertificate(req.Domain); err != nil {
			slog.Error("certificate request failed", "component", "acme", "domain", req.Domain, "error", err)
			errMsg := err.Error()
			if len(errMsg) > 200 {
				errMsg = errMsg[:200]
			}
			s.db.SetSetting("acme_status_"+req.Domain, `{"status":"failed","domain":"`+req.Domain+`","error":"`+errMsg+`"}`)
		} else {
			s.db.SetSetting("acme_status_"+req.Domain, `{"status":"issued","domain":"`+req.Domain+`"}`)
			// If this cert is for the block page domain, load it into block page server
			s.loadBlockPageCertIfMatch(req.Domain)
		}
	}()

	c.JSON(http.StatusOK, gin.H{"status": "requesting", "domain": req.Domain})
}

// loadBlockPageCertIfMatch checks if a cert exists for the block page domain and loads it
func (s *Server) loadBlockPageCertIfMatch(domain string) {
	bpDomain := s.dns.GetBlockPageDomain()
	if bpDomain == "" || domain != bpDomain {
		return
	}
	certPath := "/app/certs/" + domain + ".crt"
	keyPath := "/app/certs/" + domain + ".key"
	if s.blockPage != nil {
		if err := s.blockPage.SetBlockPageCert(certPath, keyPath); err != nil {
			slog.Error("failed to load block page cert", "component", "acme", "domain", domain, "error", err)
		} else {
			// Set redirect URL to HTTPS if not already set
			redirectURL := s.blockPage.GetRedirectURL()
			if redirectURL == "" || !strings.HasPrefix(redirectURL, "https://") {
				httpsURL := "https://" + domain
				s.blockPage.SetRedirectURL(httpsURL)
				s.db.SetSetting("block_page_redirect_url", httpsURL)
				slog.Info("auto-set block page redirect to HTTPS", "component", "acme", "url", httpsURL)
			}
		}
	}
}
