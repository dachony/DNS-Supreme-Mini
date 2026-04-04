package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Fail2Ban tracks failed login attempts and bans IPs
type Fail2Ban struct {
	enabled    bool
	maxRetries int
	banSeconds int
	attempts   map[string]*banEntry // IP -> entry
	allowedIPs map[string]bool      // management panel IP allowlist
	mu         sync.RWMutex
}

type banEntry struct {
	Count    int       `json:"count"`
	LastFail time.Time `json:"last_fail"`
	BannedAt time.Time `json:"banned_at,omitempty"`
	Banned   bool      `json:"banned"`
}

type BannedIP struct {
	IP        string    `json:"ip"`
	Attempts  int       `json:"attempts"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewFail2Ban() *Fail2Ban {
	f := &Fail2Ban{
		enabled:    true,
		maxRetries: 5,
		banSeconds: 900, // 15 minutes
		attempts:   make(map[string]*banEntry),
		allowedIPs: make(map[string]bool),
	}
	go f.cleanupLoop()
	return f
}

// RecordFail records a failed login attempt. Returns true if IP is now banned.
func (f *Fail2Ban) RecordFail(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.enabled {
		return false
	}

	ip = extractHost(ip)
	entry, ok := f.attempts[ip]
	if !ok {
		entry = &banEntry{}
		f.attempts[ip] = entry
	}

	entry.Count++
	entry.LastFail = time.Now()

	if entry.Count >= f.maxRetries && !entry.Banned {
		entry.Banned = true
		entry.BannedAt = time.Now()
		return true
	}

	return entry.Banned
}

// RecordSuccess clears failed attempts for an IP
func (f *Fail2Ban) RecordSuccess(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attempts, extractHost(ip))
}

// IsBanned checks if an IP is currently banned
func (f *Fail2Ban) IsBanned(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled {
		return false
	}

	ip = extractHost(ip)
	entry, ok := f.attempts[ip]
	if !ok || !entry.Banned {
		return false
	}

	// Check if ban expired
	if time.Since(entry.BannedAt) > time.Duration(f.banSeconds)*time.Second {
		return false
	}

	return true
}

// UnbanIP removes an IP from the ban list
func (f *Fail2Ban) UnbanIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attempts, extractHost(ip))
}

// GetBannedIPs returns all currently banned IPs
func (f *Fail2Ban) GetBannedIPs() []BannedIP {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var result []BannedIP
	banDuration := time.Duration(f.banSeconds) * time.Second

	for ip, entry := range f.attempts {
		if entry.Banned && time.Since(entry.BannedAt) < banDuration {
			result = append(result, BannedIP{
				IP:        ip,
				Attempts:  entry.Count,
				BannedAt:  entry.BannedAt,
				ExpiresAt: entry.BannedAt.Add(banDuration),
			})
		}
	}
	return result
}

// GetSettings returns current fail2ban settings
func (f *Fail2Ban) GetSettings() map[string]any {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return map[string]any{
		"enabled":     f.enabled,
		"max_retries": f.maxRetries,
		"ban_seconds": f.banSeconds,
	}
}

// SetSettings updates fail2ban settings
func (f *Fail2Ban) SetSettings(enabled bool, maxRetries, banSeconds int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = enabled
	if maxRetries >= 1 {
		f.maxRetries = maxRetries
	}
	if banSeconds >= 60 {
		f.banSeconds = banSeconds
	}
}

// --- IP Allowlist for management panel ---

func (f *Fail2Ban) SetAllowedIPs(ips []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowedIPs = make(map[string]bool)
	for _, ip := range ips {
		if ip = extractHost(ip); ip != "" {
			f.allowedIPs[ip] = true
		}
	}
}

func (f *Fail2Ban) GetAllowedIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]string, 0, len(f.allowedIPs))
	for ip := range f.allowedIPs {
		result = append(result, ip)
	}
	return result
}

// IsAllowed checks if an IP is allowed to access management panel
// Empty allowlist = all IPs allowed
func (f *Fail2Ban) IsAllowed(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.allowedIPs) == 0 {
		return true // no restriction
	}
	return f.allowedIPs[extractHost(ip)]
}

func (f *Fail2Ban) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		f.mu.Lock()
		banDuration := time.Duration(f.banSeconds) * time.Second
		for ip, entry := range f.attempts {
			if entry.Banned && time.Since(entry.BannedAt) > banDuration {
				delete(f.attempts, ip)
			} else if !entry.Banned && time.Since(entry.LastFail) > 30*time.Minute {
				delete(f.attempts, ip)
			}
		}
		f.mu.Unlock()
	}
}

func extractHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// --- API Handlers ---

func (s *Server) getFail2BanStatus(c *gin.Context) {
	settings := s.fail2ban.GetSettings()
	banned := s.fail2ban.GetBannedIPs()
	allowedIPs := s.fail2ban.GetAllowedIPs()
	c.JSON(http.StatusOK, gin.H{
		"settings":    settings,
		"banned":      banned,
		"banned_count": len(banned),
		"allowed_ips": allowedIPs,
	})
}

type fail2banSettingsReq struct {
	Enabled    bool `json:"enabled"`
	MaxRetries int  `json:"max_retries"`
	BanSeconds int  `json:"ban_seconds"`
}

func (s *Server) setFail2BanSettings(c *gin.Context) {
	var req fail2banSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.fail2ban.SetSettings(req.Enabled, req.MaxRetries, req.BanSeconds)
	if data, err := json.Marshal(s.fail2ban.GetSettings()); err == nil {
		s.db.SetSetting("fail2ban_settings", string(data))
	}
	if uid, ok := c.Get("userID"); ok {
		uname, _ := c.Get("username")
		detail := fmt.Sprintf("Fail2ban settings: enabled=%v, max_retries=%d, ban_seconds=%d", req.Enabled, req.MaxRetries, req.BanSeconds)
		s.db.LogAudit(uid.(int), uname.(string), "settings_fail2ban", detail, c.ClientIP())
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) unbanIP(c *gin.Context) {
	ip := c.Param("ip")
	s.fail2ban.UnbanIP(ip)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "unbanned": ip})
}

type allowedIPsReq struct {
	IPs []string `json:"ips"`
}

func (s *Server) setAllowedIPs(c *gin.Context) {
	var req allowedIPsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.fail2ban.SetAllowedIPs(req.IPs)
	if data, err := json.Marshal(req.IPs); err == nil {
		s.db.SetSetting("allowed_ips", string(data))
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "count": len(req.IPs)})
}

// LoadFail2BanConfig restores fail2ban settings from database
func (s *Server) LoadFail2BanConfig() {
	if data := s.db.GetSetting("fail2ban_settings"); data != "" {
		var settings map[string]any
		if json.Unmarshal([]byte(data), &settings) == nil {
			enabled, _ := settings["enabled"].(bool)
			maxRetries := int(settings["max_retries"].(float64))
			banSeconds := int(settings["ban_seconds"].(float64))
			s.fail2ban.SetSettings(enabled, maxRetries, banSeconds)
		}
	}
	if data := s.db.GetSetting("allowed_ips"); data != "" {
		var ips []string
		if json.Unmarshal([]byte(data), &ips) == nil {
			s.fail2ban.SetAllowedIPs(ips)
		}
	}
}
