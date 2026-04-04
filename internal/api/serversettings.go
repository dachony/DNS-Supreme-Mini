package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type serverSettingsResp struct {
	Protocols    map[string]bool `json:"protocols"`
	ListenAddresses struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	} `json:"listen_addresses"`
	IPv6Enabled  bool   `json:"ipv6_enabled"`
	CacheSize    int    `json:"cache_size"`
	DefaultTTL   int    `json:"default_ttl"`
	MinTTL       int    `json:"min_ttl"`
	MaxTTL       int    `json:"max_ttl"`
	ManagementHTTPS bool `json:"management_https"`
}

func defaultServerSettings() serverSettingsResp {
	resp := serverSettingsResp{
		Protocols: map[string]bool{
			"udp": true, "tcp": true, "dot": true, "doh": true, "doq": true,
		},
		IPv6Enabled:     true,
		CacheSize:       10000,
		DefaultTTL:      3600,
		MinTTL:          10,
		MaxTTL:          86400,
		ManagementHTTPS: false,
	}
	resp.ListenAddresses.IPv4 = "0.0.0.0"
	resp.ListenAddresses.IPv6 = "::"
	return resp
}

func (s *Server) getServerSettings(c *gin.Context) {
	resp := defaultServerSettings()
	// Load from DB if available
	if data := s.db.GetSetting("server_settings"); data != "" {
		json.Unmarshal([]byte(data), &resp)
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) updateServerSettings(c *gin.Context) {
	var req serverSettingsResp
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Persist to DB
	if data, err := json.Marshal(req); err == nil {
		s.db.SetSetting("server_settings", string(data))
	}
	// Audit
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Server settings updated", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "Settings saved. Some changes require a restart to take effect.",
	})
}

// --- Forwarders persistence ---

func (s *Server) getForwarders(c *gin.Context) {
	fwds := s.dns.GetForwarders()
	type fwInfo struct {
		Address string `json:"address"`
		Name    string `json:"name"`
	}
	result := make([]fwInfo, 0, len(fwds))
	for _, addr := range fwds {
		result = append(result, fwInfo{Address: addr, Name: describeForwarder(addr)})
	}
	c.JSON(http.StatusOK, result)
}

type setForwardersReq struct {
	Forwarders []string `json:"forwarders"`
}

func (s *Server) setForwarders(c *gin.Context) {
	var req setForwardersReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.dns.SetForwarders(req.Forwarders)
	// Persist
	if data, err := json.Marshal(req.Forwarders); err == nil {
		s.db.SetSetting("forwarders", string(data))
	}
	// Audit
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", fmt.Sprintf("Forwarders updated: %v", req.Forwarders), c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func describeForwarder(addr string) string {
	names := map[string]string{
		"8.8.8.8:53":             "Google DNS",
		"8.8.4.4:53":             "Google DNS",
		"1.1.1.1:53":             "Cloudflare",
		"1.0.0.1:53":             "Cloudflare",
		"9.9.9.9:53":             "Quad9",
		"149.112.112.112:53":     "Quad9",
		"94.140.14.14:53":        "AdGuard DNS",
		"94.140.15.15:53":        "AdGuard DNS",
		"208.67.222.222:53":      "OpenDNS",
		"208.67.220.220:53":      "OpenDNS",
	}
	if name, ok := names[addr]; ok {
		return name
	}
	if len(addr) > 4 && addr[:4] == "tls:" {
		return "DNS-over-TLS"
	}
	if len(addr) > 5 && addr[:5] == "https" {
		return "DNS-over-HTTPS"
	}
	if len(addr) > 5 && addr[:5] == "quic:" {
		return "DNS-over-QUIC"
	}
	return ""
}

// --- Filtering Mode ---

type filteringModeResp struct {
	Mode string `json:"mode"`
	Description string `json:"description"`
}

func (s *Server) getFilteringMode(c *gin.Context) {
	mode := s.filter.GetMode()
	desc := "Allow all traffic except domains on blocklists"
	if mode == "allowlist" {
		desc = "Block all traffic except domains on the allowlist"
	}
	c.JSON(http.StatusOK, filteringModeResp{Mode: mode, Description: desc})
}

type setFilteringModeReq struct {
	Mode string `json:"mode" binding:"required"`
}

func (s *Server) setFilteringMode(c *gin.Context) {
	var req setFilteringModeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Mode != "blocklist" && req.Mode != "allowlist" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'blocklist' or 'allowlist'"})
		return
	}
	s.filter.SetMode(req.Mode)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mode": req.Mode})
}
