package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dns-supreme-mini/internal/db"
	"github.com/gin-gonic/gin"
)

// Block page visual settings stored as JSON
type blockPageSettings struct {
	Logo        string `json:"logo"`
	Heading     string `json:"heading"`
	Message     string `json:"message"`
	Description string `json:"description"`
	Footer      string `json:"footer"`
	Color       string `json:"color"`
}

type blockPageReq struct {
	HTML     string             `json:"html"`
	Settings *blockPageSettings `json:"settings,omitempty"`
}

func (s *Server) getBlockPageTemplate(c *gin.Context) {
	html := ""
	if s.blockPage != nil {
		html = s.blockPage.GetCustomTemplate()
	}
	// Try DB if in-memory is empty
	if html == "" {
		html = s.db.GetSetting("block_page_html")
	}

	// Load visual settings
	var settings blockPageSettings
	if data := s.db.GetSetting("block_page_visual"); data != "" {
		json.Unmarshal([]byte(data), &settings)
	}

	c.JSON(http.StatusOK, gin.H{
		"html":     html,
		"settings": settings,
	})
}

func (s *Server) setBlockPageTemplate(c *gin.Context) {
	var req blockPageReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if s.blockPage == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "block page server not available"})
		return
	}

	html := req.HTML
	if html == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "html is required"})
		return
	}

	if err := s.blockPage.SetCustomTemplate(html); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.db.SetSetting("block_page_html", html)

	// Save visual settings if provided
	if req.Settings != nil {
		if data, err := json.Marshal(req.Settings); err == nil {
			s.db.SetSetting("block_page_visual", string(data))
		}
	}

	// Audit
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page template updated", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) uploadBlockPageLogo(c *gin.Context) {
	file, header, err := c.Request.FormFile("logo")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	// Sanitize extension to prevent path traversal
	ext := filepath.Ext(filepath.Base(header.Filename))
	ext = strings.ToLower(ext)
	allowed := map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".svg": true, ".gif": true, ".webp": true, ".ico": true}
	if !allowed[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file type, allowed: png, jpg, svg, gif, webp, ico"})
		return
	}

	// Limit to 2MB
	if header.Size > 2*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file too large, max 2MB"})
		return
	}

	// Ensure upload dir exists
	uploadDir := "/app/data/uploads"
	os.MkdirAll(uploadDir, 0755)

	// Save with timestamp to avoid caching issues
	filename := "logo_" + strings.ReplaceAll(time.Now().Format("20060102_150405"), " ", "") + ext
	destPath := filepath.Join(uploadDir, filename)

	dest, err := os.Create(destPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
		return
	}
	defer dest.Close()
	io.Copy(dest, file)

	// Clean up old logos
	entries, _ := os.ReadDir(uploadDir)
	for _, e := range entries {
		if e.Name() != filename && strings.HasPrefix(e.Name(), "logo_") {
			os.Remove(filepath.Join(uploadDir, e.Name()))
		}
	}

	logoURL := "/uploads/" + filename
	s.db.SetSetting("block_page_logo", logoURL)

	slog.Info("block page logo uploaded", "component", "api", "file", filename, "size", header.Size)

	c.JSON(http.StatusOK, gin.H{"url": logoURL})
}

func (s *Server) LoadBlockPageTemplate() {
	if html := s.db.GetSetting("block_page_html"); html != "" && s.blockPage != nil {
		s.blockPage.SetCustomTemplate(html)
	}
	// Load block page domain
	if domain := s.db.GetSetting("block_page_domain"); domain != "" {
		s.dns.SetBlockPageDomain(domain)
	}
	// Load block page redirect URL
	if url := s.db.GetSetting("block_page_redirect_url"); url != "" && s.blockPage != nil {
		s.blockPage.SetRedirectURL(url)
	}
	// Try to load dedicated block page cert
	if domain := s.db.GetSetting("block_page_domain"); domain != "" && s.blockPage != nil {
		certPath := "/app/certs/" + domain + ".crt"
		keyPath := "/app/certs/" + domain + ".key"
		if _, err := os.Stat(certPath); err == nil {
			s.blockPage.SetBlockPageCert(certPath, keyPath)
		}
	}
}

func (s *Server) getBlockPageDomain(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"domain": s.dns.GetBlockPageDomain()})
}

type blockPageDomainReq struct {
	Domain string `json:"domain"`
}

func (s *Server) setBlockPageDomain(c *gin.Context) {
	var req blockPageDomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.dns.SetBlockPageDomain(req.Domain)
	s.db.SetSetting("block_page_domain", req.Domain)

	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page domain set to: "+req.Domain, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok", "domain": req.Domain})
}

func (s *Server) setupBlockPageDomain(c *gin.Context) {
	var req struct {
		Prefix string `json:"prefix"`
		Zone   string `json:"zone"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Prefix == "" || req.Zone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prefix and zone are required"})
		return
	}

	// Sanitize prefix
	req.Prefix = strings.ToLower(strings.TrimSpace(req.Prefix))
	req.Zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Zone), "."))
	domain := req.Prefix + "." + req.Zone

	// 1. Set block page domain (DNS auto-resolve)
	s.dns.SetBlockPageDomain(domain)
	s.db.SetSetting("block_page_domain", domain)

	// 1b. Create A record in the zone so it's visible in zone management
	s.ensureBlockPageRecord(req.Prefix, req.Zone)

	// 2. Set HTTP redirect immediately (works without cert)
	httpURL := "http://" + domain
	if s.blockPage != nil {
		s.blockPage.SetRedirectURL(httpURL)
	}
	s.db.SetSetting("block_page_redirect_url", httpURL)

	// 3. Check if cert already exists
	certPath := "/app/certs/" + domain + ".crt"
	keyPath := "/app/certs/" + domain + ".key"
	if _, err := os.Stat(certPath); err == nil {
		// Cert exists — load it and switch to HTTPS
		if s.blockPage != nil {
			if err := s.blockPage.SetBlockPageCert(certPath, keyPath); err == nil {
				httpsURL := "https://" + domain
				s.blockPage.SetRedirectURL(httpsURL)
				s.db.SetSetting("block_page_redirect_url", httpsURL)
			}
		}
		userID, _ := c.Get("userID")
		username, _ := c.Get("username")
		s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page domain setup: "+domain+" (cert found)", c.ClientIP())
		c.JSON(http.StatusOK, gin.H{"status": "ok", "domain": domain, "cert": "loaded", "redirect_url": "https://" + domain})
		return
	}

	// 4. Request ACME cert in background
	acmeCfg := s.acmeClient.GetConfig()
	certStatus := "skipped"
	if acmeCfg.Email != "" {
		// Wire DNS solver based on config (local or Cloudflare)
		s.wireACMESolver()
		s.db.SetSetting("acme_status_"+domain, `{"status":"pending","domain":"`+domain+`"}`)
		certStatus = "requesting"

		go func() {
			if err := s.acmeClient.RequestCertificate(domain); err != nil {
				slog.Error("block page cert request failed", "component", "acme", "domain", domain, "error", err)
				errMsg := err.Error()
				if len(errMsg) > 200 {
					errMsg = errMsg[:200]
				}
				s.db.SetSetting("acme_status_"+domain, `{"status":"failed","domain":"`+domain+`","error":"`+errMsg+`"}`)
			} else {
				s.db.SetSetting("acme_status_"+domain, `{"status":"issued","domain":"`+domain+`"}`)
				s.loadBlockPageCertIfMatch(domain)
			}
		}()
	}

	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page domain setup: "+domain, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok", "domain": domain, "cert": certStatus, "redirect_url": httpURL})
}

// ensureBlockPageRecord creates an A record in the zone for the block page subdomain
func (s *Server) ensureBlockPageRecord(prefix, zoneName string) {
	ip := s.dns.GetBlockPageIP()
	if ip == "" || ip == "0.0.0.0" {
		slog.Warn("no block page IP available, skipping zone record", "component", "blockpage")
		return
	}

	zone, err := s.db.GetZoneByName(zoneName)
	if err != nil {
		slog.Warn("zone not found for block page record", "component", "blockpage", "zone", zoneName, "error", err)
		return
	}

	// Check if record already exists
	records, _ := s.db.ListRecords(zone.ID)
	for _, r := range records {
		if r.Name == prefix && r.Type == "A" {
			// Update if IP changed
			if r.Value != ip {
				r.Value = ip
				s.db.UpdateRecord(&r)
				slog.Info("updated block page A record", "component", "blockpage", "name", prefix, "zone", zoneName, "ip", ip)
			}
			return
		}
	}

	// Create new A record
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID,
		Name:   prefix,
		Type:   "A",
		Value:  ip,
		TTL:    300,
	})
	slog.Info("created block page A record", "component", "blockpage", "name", prefix, "zone", zoneName, "ip", ip)
}

func (s *Server) getBlockPageRedirect(c *gin.Context) {
	url := ""
	if s.blockPage != nil {
		url = s.blockPage.GetRedirectURL()
	}
	c.JSON(http.StatusOK, gin.H{"redirect_url": url})
}

func (s *Server) setBlockPageRedirect(c *gin.Context) {
	var req struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if s.blockPage != nil {
		s.blockPage.SetRedirectURL(req.RedirectURL)
	}
	s.db.SetSetting("block_page_redirect_url", req.RedirectURL)

	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page redirect URL set to: "+req.RedirectURL, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok", "redirect_url": req.RedirectURL})
}
