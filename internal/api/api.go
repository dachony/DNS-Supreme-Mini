package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dns-supreme-mini/internal/auth"
	"dns-supreme-mini/internal/blockpage"
	"dns-supreme-mini/internal/config"
	"dns-supreme-mini/internal/db"
	dnsserver "dns-supreme-mini/internal/dns"
	"dns-supreme-mini/internal/filter"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

//go:embed static
var staticFS embed.FS

var startTime = time.Now()

type Server struct {
	cfg            config.APIConfig
	db             *db.Database
	filter         *filter.Engine
	blockPage      *blockpage.Server
	dns            *dnsserver.Server
	fail2ban       *Fail2Ban
	blocklistTimer *time.Timer
	router         *gin.Engine
}

func NewServer(cfg config.APIConfig, database *db.Database, filterEngine *filter.Engine, bp *blockpage.Server, dnsServer *dnsserver.Server) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: false,
	}))

	s := &Server{
		cfg:       cfg,
		db:        database,
		filter:    filterEngine,
		blockPage: bp,
		dns:       dnsServer,
		fail2ban:  NewFail2Ban(),
		router:    router,
	}

	auth.InitSecret(database.GetSetting, database.SetSetting)
	s.ensureDefaultAdmin()
	s.loadFail2BanConfig()
	s.setupRoutes()
	return s
}

func (s *Server) ensureDefaultAdmin() {
	if s.db.UserCount() == 0 {
		hash, _ := auth.HashPassword("admin")
		user := &db.User{
			Username:     "admin",
			PasswordHash: hash,
			FirstName:    "Administrator",
			Role:         "admin",
		}
		if err := s.db.CreateUser(user); err != nil {
			slog.Error("failed to create default admin", "component", "api", "error", err)
		} else {
			s.db.SetSetting("force_password_change", "true")
			slog.Info("default admin user created (admin/admin)", "component", "api")
		}
	}
}

func (s *Server) loadFail2BanConfig() {
	if data := s.db.GetSetting("fail2ban_config"); data != "" {
		var cfg struct {
			MaxRetries int `json:"max_retries"`
			BanSeconds int `json:"ban_seconds"`
		}
		if json.Unmarshal([]byte(data), &cfg) == nil {
			s.fail2ban.SetConfig(cfg.MaxRetries, cfg.BanSeconds)
		}
	}
	if data := s.db.GetSetting("fail2ban_allowed_ips"); data != "" {
		var ips []string
		if json.Unmarshal([]byte(data), &ips) == nil {
			s.fail2ban.SetAllowedIPs(ips)
		}
	}
}

func (s *Server) setupRoutes() {
	// Serve embedded frontend
	staticSub, _ := fs.Sub(staticFS, "static")
	s.router.StaticFS("/ui", http.FS(staticSub))
	s.router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/ui/")
	})

	api := s.router.Group("/api")

	// Health check
	api.GET("/health", func(c *gin.Context) {
		dbOK := s.db.Ping() == nil
		status := "healthy"
		code := http.StatusOK
		if !dbOK {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}
		c.JSON(code, gin.H{
			"status":         status,
			"version":        "1.0.0-mini",
			"uptime_seconds": int64(time.Since(startTime).Seconds()),
			"db_ok":          dbOK,
			"dns_ok":         true,
		})
	})

	// Public auth
	api.POST("/auth/login", s.login)
	api.POST("/auth/mfa-verify", s.mfaVerify)

	// Protected routes
	protected := api.Group("")
	protected.Use(auth.AuthMiddleware())
	{
		// Read-only
		protected.GET("/stats", s.getStats)
		protected.GET("/logs", s.getLogs)
		protected.GET("/status", s.getStatus)
		protected.GET("/blocklists", s.getBlocklists)
		protected.GET("/blocklists/:name/domains", s.getBlocklistDomains)
		protected.GET("/custom-blocks", s.getCustomBlocks)
		protected.GET("/allowlist", s.getAllowlist)
		protected.GET("/categories", s.getCategories)
		protected.GET("/block-services", s.getBlockServices)
		protected.GET("/fail2ban", s.getFail2BanStatus)
		protected.GET("/settings/forwarders", s.getForwarders)
		protected.GET("/settings/blockpage", s.getBlockPageTemplate)
		protected.GET("/settings/blockpage/redirect", s.getBlockPageRedirect)
		protected.GET("/settings/filtering-mode", s.getFilteringMode)
		protected.GET("/auth/me", s.getMe)
		protected.PUT("/auth/password", s.changePassword)
		protected.POST("/auth/mfa/setup", s.setupMFA)
		protected.POST("/auth/mfa/enable", s.enableMFA)
		protected.DELETE("/auth/mfa", s.disableMFA)

		// Admin-only
		admin := protected.Group("")
		admin.Use(auth.AdminOnly())
		{
			admin.POST("/blocklists", s.addBlocklist)
			admin.POST("/blocklists/update", s.updateBlocklists)
			admin.GET("/blocklists/schedule", s.getBlocklistSchedule)
			admin.PUT("/blocklists/schedule", s.setBlocklistSchedule)
			admin.DELETE("/blocklists/:name", s.removeBlocklist)
			admin.POST("/custom-blocks", s.addCustomBlock)
			admin.DELETE("/custom-blocks/:domain", s.removeCustomBlock)
			admin.POST("/allowlist", s.addAllowlist)
			admin.DELETE("/allowlist/:domain", s.removeAllowlist)
			admin.PUT("/categories/:name", s.toggleCategory)
			admin.PUT("/block-services/service/:id", s.toggleBlockService)
			admin.PUT("/block-services/category/:id", s.toggleBlockServiceCategory)
			admin.PUT("/fail2ban/settings", s.setFail2BanSettings)
			admin.DELETE("/fail2ban/unban/:ip", s.unbanIP)
			admin.PUT("/fail2ban/allowed-ips", s.setAllowedIPs)
			admin.PUT("/settings/forwarders", s.setForwarders)
			admin.PUT("/settings/blockpage", s.setBlockPageTemplate)
			admin.PUT("/settings/blockpage/redirect", s.setBlockPageRedirect)
			admin.PUT("/settings/filtering-mode", s.setFilteringMode)
			admin.POST("/restart", s.restartServer)
			admin.POST("/cache/flush", s.flushCache)
			admin.GET("/audit-logs", s.getAuditLogs)
			admin.GET("/users", s.listUsers)
			admin.POST("/users", s.createUser)
			admin.PUT("/users/:id", s.updateUser)
			admin.DELETE("/users/:id", s.deleteUser)
			admin.PUT("/users/:id/password", s.resetUserPassword)
		}
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	slog.Info("web UI and API available", "component", "api", "addr", addr)

	// Restore blocklist auto-update schedule
	if v := s.db.GetSetting("blocklist_update_hours"); v != "" {
		var hours int
		if json.Unmarshal([]byte(v), &hours) == nil && hours > 0 {
			s.startBlocklistTimer(hours)
		}
	}

	go func() {
		if err := s.router.Run(addr); err != nil {
			slog.Error("API server failed", "component", "api", "error", err)
			os.Exit(1)
		}
	}()

	return nil
}

// --- Auth Handlers ---

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (s *Server) login(c *gin.Context) {
	clientIP := c.ClientIP()

	if s.fail2ban.IsBanned(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts. Your IP is temporarily blocked."})
		return
	}
	if !s.fail2ban.IsAllowed(clientIP) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied from this IP address"})
		return
	}

	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.db.GetUserByUsername(req.Username)
	if err != nil || user == nil {
		s.fail2ban.RecordFail(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !auth.CheckPassword(user.PasswordHash, req.Password) {
		s.fail2ban.RecordFail(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	s.fail2ban.RecordSuccess(clientIP)

	mfaDone := !user.MFAEnabled
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, mfaDone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	if !mfaDone {
		c.JSON(http.StatusOK, gin.H{
			"token":        token,
			"mfa_required": true,
			"mfa_type":     user.MFAType,
		})
		return
	}

	s.db.UpdateLastLogin(user.ID)
	s.db.LogAudit(user.ID, user.Username, "login", "Successful login", clientIP)
	forceChange := s.db.GetSetting("force_password_change") == "true" && user.Username == "admin"
	c.JSON(http.StatusOK, gin.H{
		"token":                 token,
		"mfa_required":          false,
		"force_password_change": forceChange,
		"user": gin.H{
			"id": user.ID, "username": user.Username,
			"first_name": user.FirstName, "last_name": user.LastName,
			"email": user.Email, "role": user.Role,
		},
	})
}

func (s *Server) mfaVerify(c *gin.Context) {
	clientIP := c.ClientIP()
	if s.fail2ban.IsBanned(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts."})
		return
	}

	header := c.GetHeader("Authorization")
	if header == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token required"})
		return
	}
	token := strings.TrimPrefix(header, "Bearer ")
	claims, err := auth.ValidateTokenPartial(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.db.GetUserByID(claims.UserID)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	verified := auth.VerifyTOTP(user.MFASecret, req.Code)
	if !verified {
		codesStr := s.db.GetRecoveryCodes(user.ID)
		if codesStr != "" {
			codes := strings.Split(codesStr, ",")
			for i, code := range codes {
				if code == req.Code {
					verified = true
					codes = append(codes[:i], codes[i+1:]...)
					s.db.SetRecoveryCodes(user.ID, strings.Join(codes, ","))
					break
				}
			}
		}
	}

	if !verified {
		s.fail2ban.RecordFail(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid MFA code"})
		return
	}

	fullToken, _ := auth.GenerateToken(user.ID, user.Username, user.Role, true)
	s.db.UpdateLastLogin(user.ID)
	c.JSON(http.StatusOK, gin.H{
		"token": fullToken,
		"user": gin.H{
			"id": user.ID, "username": user.Username,
			"first_name": user.FirstName, "last_name": user.LastName,
			"email": user.Email, "role": user.Role,
		},
	})
}

func (s *Server) getMe(c *gin.Context) {
	userID, _ := c.Get("userID")
	user, _ := s.db.GetUserByID(userID.(int))
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (s *Server) changePassword(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.db.GetUserByID(userID.(int))
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if !auth.CheckPassword(user.PasswordHash, req.CurrentPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current password is incorrect"})
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.UpdateUserPassword(user.ID, hash)
	if s.db.GetSetting("force_password_change") == "true" {
		s.db.DeleteSetting("force_password_change")
	}
	s.db.LogAudit(user.ID, user.Username, "password_change", "Password changed", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) setupMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	secret, _ := auth.GenerateTOTPSecret()
	uri := auth.TOTPProvisioningURI(secret, username.(string), "DNS-Supreme-Mini")
	s.db.UpdateUserMFA(userID.(int), false, "totp", secret)
	c.JSON(http.StatusOK, gin.H{"secret": secret, "uri": uri})
}

func (s *Server) enableMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, _ := s.db.GetUserByID(userID.(int))
	if user == nil || user.MFASecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run MFA setup first"})
		return
	}
	if !auth.VerifyTOTP(user.MFASecret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
		return
	}
	s.db.UpdateUserMFA(user.ID, true, "totp", user.MFASecret)
	recoveryCodes := auth.GenerateRecoveryCodes()
	s.db.SetRecoveryCodes(user.ID, strings.Join(recoveryCodes, ","))
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mfa_enabled": true, "recovery_codes": recoveryCodes})
}

func (s *Server) disableMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	s.db.UpdateUserMFA(userID.(int), false, "", "")
	s.db.SetRecoveryCodes(userID.(int), "")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mfa_enabled": false})
}

// --- Stats/Logs ---

func (s *Server) getStats(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours <= 0 {
		hours = 24
	}
	stats, err := s.db.GetStats(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (s *Server) getLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	domain := c.Query("domain")
	clientIP := c.Query("client_ip")
	var blocked *bool
	if b := c.Query("blocked"); b != "" {
		val := b == "true"
		blocked = &val
	}
	logs, total, err := s.db.GetQueryLogs(limit, offset, domain, clientIP, blocked)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) getStatus(c *gin.Context) {
	totalDomains, totalLists := s.filter.Stats()
	bannedIPs := len(s.fail2ban.GetBannedIPs())
	c.JSON(http.StatusOK, gin.H{
		"status":        "running",
		"version":       "1.0.0-mini",
		"total_domains": totalDomains,
		"total_lists":   totalLists,
		"cache_size":    s.dns.CacheSize(),
		"banned_ips":    bannedIPs,
		"users":         s.db.UserCount(),
	})
}

// --- Blocklists ---

func (s *Server) getBlocklists(c *gin.Context) {
	lists := s.filter.GetLists()
	totalDomains, totalLists := s.filter.Stats()
	c.JSON(http.StatusOK, gin.H{"lists": lists, "total_domains": totalDomains, "total_lists": totalLists})
}

func (s *Server) addBlocklist(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		URL      string `json:"url" binding:"required"`
		Category string `json:"category"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cat := filter.Category(req.Category)
	if cat == "" {
		cat = filter.CategoryUncategorized
	}
	if err := s.filter.AddList(req.Name, req.URL, cat); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	lists := s.filter.GetLists()
	for _, l := range lists {
		if l.Name == req.Name {
			s.db.SaveBlocklist(l.Name, req.URL, string(l.Category), l.Count)
			break
		}
	}
	if uid, ok := c.Get("userID"); ok {
		uname, _ := c.Get("username")
		s.db.LogAudit(uid.(int), uname.(string), "blocklist_add", "Added blocklist: "+req.Name, c.ClientIP())
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) updateBlocklists(c *gin.Context) {
	lists := s.filter.GetLists()
	go func() {
		for _, l := range lists {
			if err := s.filter.UpdateList(l.Name); err != nil {
				slog.Error("blocklist update failed", "name", l.Name, "error", err)
				continue
			}
			updated := s.filter.GetLists()
			for _, u := range updated {
				if u.Name == l.Name {
					s.db.SaveBlocklist(u.Name, l.URL, string(u.Category), u.Count)
					break
				}
			}
		}
	}()
	c.JSON(http.StatusOK, gin.H{"status": "updating", "count": len(lists)})
}

func (s *Server) getBlocklistSchedule(c *gin.Context) {
	hours := 0
	if v := s.db.GetSetting("blocklist_update_hours"); v != "" {
		json.Unmarshal([]byte(v), &hours)
	}
	c.JSON(http.StatusOK, gin.H{"interval_hours": hours})
}

func (s *Server) setBlocklistSchedule(c *gin.Context) {
	var req struct {
		IntervalHours int `json:"interval_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	data, _ := json.Marshal(req.IntervalHours)
	s.db.SetSetting("blocklist_update_hours", string(data))
	s.startBlocklistTimer(req.IntervalHours)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "interval_hours": req.IntervalHours})
}

func (s *Server) startBlocklistTimer(hours int) {
	if s.blocklistTimer != nil {
		s.blocklistTimer.Stop()
		s.blocklistTimer = nil
	}
	if hours <= 0 {
		return
	}
	d := time.Duration(hours) * time.Hour
	s.blocklistTimer = time.AfterFunc(d, func() {
		slog.Info("blocklist auto-update triggered", "component", "filter")
		lists := s.filter.GetLists()
		for _, l := range lists {
			s.filter.UpdateList(l.Name)
		}
		s.startBlocklistTimer(hours)
	})
	slog.Info("blocklist auto-update scheduled", "interval_hours", hours)
}

func (s *Server) removeBlocklist(c *gin.Context) {
	name := c.Param("name")
	s.filter.RemoveList(name)
	s.db.RemoveBlocklist(name)
	if uid, ok := c.Get("userID"); ok {
		uname, _ := c.Get("username")
		s.db.LogAudit(uid.(int), uname.(string), "blocklist_remove", "Removed: "+name, c.ClientIP())
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getBlocklistDomains(c *gin.Context) {
	name := c.Param("name")
	domains := s.filter.GetListDomains(name, 200)
	c.JSON(http.StatusOK, gin.H{"name": name, "domains": domains, "sample_size": len(domains)})
}

// --- Custom blocks & allowlist ---

func (s *Server) getCustomBlocks(c *gin.Context)  { c.JSON(http.StatusOK, s.filter.GetCustomBlocks()) }
func (s *Server) getAllowlist(c *gin.Context)      { c.JSON(http.StatusOK, s.filter.GetAllowlist()) }

func (s *Server) addCustomBlock(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.AddCustomBlock(req.Domain, req.Reason)
	s.persistCustomBlocks()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) removeCustomBlock(c *gin.Context) {
	s.filter.RemoveCustomBlock(c.Param("domain"))
	s.persistCustomBlocks()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistCustomBlocks() {
	data, _ := json.Marshal(s.filter.GetCustomBlocks())
	s.db.SetSetting("custom_blocks", string(data))
}

func (s *Server) addAllowlist(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.AddAllowlistDomain(req.Domain)
	s.persistAllowlist()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) removeAllowlist(c *gin.Context) {
	s.filter.RemoveAllowlistDomain(c.Param("domain"))
	s.persistAllowlist()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistAllowlist() {
	data, _ := json.Marshal(s.filter.GetAllowlist())
	s.db.SetSetting("allowlist", string(data))
}

// --- Categories & Services ---

func (s *Server) getCategories(c *gin.Context) {
	categories := s.filter.GetCategories()
	catStats := s.filter.CategoryStats()
	result := make([]gin.H, 0)
	for cat, enabled := range categories {
		result = append(result, gin.H{"name": string(cat), "enabled": enabled, "domains": catStats[cat]})
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) toggleCategory(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cat := filter.Category(c.Param("name"))
	if req.Enabled {
		s.filter.EnableCategory(cat)
	} else {
		s.filter.DisableCategory(cat)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getBlockServices(c *gin.Context) {
	c.JSON(http.StatusOK, s.filter.ServiceBlocker().GetCategories())
}

func (s *Server) toggleBlockService(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.ServiceBlocker().SetServiceEnabled(c.Param("id"), req.Enabled)
	s.filter.ClearFilterCache()
	s.persistBlockServices()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) toggleBlockServiceCategory(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.ServiceBlocker().SetCategoryEnabled(c.Param("id"), req.Enabled)
	s.filter.ClearFilterCache()
	s.persistBlockServices()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistBlockServices() {
	ids := s.filter.ServiceBlocker().GetEnabledServiceIDs()
	data, _ := json.Marshal(ids)
	s.db.SetSetting("blocked_services", string(data))
}

// --- Fail2Ban ---

func (s *Server) getFail2BanStatus(c *gin.Context) {
	maxRetries, banSeconds := s.fail2ban.GetConfig()
	c.JSON(http.StatusOK, gin.H{
		"banned_ips":  s.fail2ban.GetBannedIPs(),
		"max_retries": maxRetries,
		"ban_seconds": banSeconds,
		"allowed_ips": s.fail2ban.GetAllowedIPs(),
	})
}

func (s *Server) setFail2BanSettings(c *gin.Context) {
	var req struct {
		MaxRetries int `json:"max_retries"`
		BanSeconds int `json:"ban_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.fail2ban.SetConfig(req.MaxRetries, req.BanSeconds)
	data, _ := json.Marshal(req)
	s.db.SetSetting("fail2ban_config", string(data))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) unbanIP(c *gin.Context) {
	s.fail2ban.UnbanIP(c.Param("ip"))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) setAllowedIPs(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.fail2ban.SetAllowedIPs(req.IPs)
	data, _ := json.Marshal(req.IPs)
	s.db.SetSetting("fail2ban_allowed_ips", string(data))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- Settings ---

func (s *Server) getForwarders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"forwarders": s.dns.GetForwarders()})
}

func (s *Server) setForwarders(c *gin.Context) {
	var req struct {
		Forwarders []string `json:"forwarders" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.dns.SetForwarders(req.Forwarders)
	data, _ := json.Marshal(req.Forwarders)
	s.db.SetSetting("forwarders", string(data))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getBlockPageTemplate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"template": s.blockPage.GetCustomTemplate()})
}

func (s *Server) setBlockPageTemplate(c *gin.Context) {
	var req struct {
		Template string `json:"template"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.blockPage.SetCustomTemplate(req.Template); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.db.SetSetting("blockpage_template", req.Template)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getBlockPageRedirect(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"url": s.blockPage.GetRedirectURL()})
}

func (s *Server) setBlockPageRedirect(c *gin.Context) {
	var req struct {
		URL string `json:"url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.blockPage.SetRedirectURL(req.URL)
	s.db.SetSetting("blockpage_redirect", req.URL)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getFilteringMode(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"mode": s.filter.GetMode()})
}

func (s *Server) setFilteringMode(c *gin.Context) {
	var req struct {
		Mode string `json:"mode" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.SetMode(req.Mode)
	s.db.SetSetting("filtering_mode", req.Mode)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mode": req.Mode})
}

func (s *Server) flushCache(c *gin.Context) {
	s.dns.FlushCache()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) restartServer(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "restarting"})
	go func() {
		time.Sleep(500 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGTERM)
	}()
}

// --- Audit logs ---

func (s *Server) getAuditLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	entries, total, _ := s.db.GetAuditLogs(limit, offset)
	c.JSON(http.StatusOK, gin.H{"entries": entries, "total": total})
}

// --- User management ---

func (s *Server) listUsers(c *gin.Context) {
	users, err := s.db.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (s *Server) createUser(c *gin.Context) {
	var req struct {
		Username  string `json:"username" binding:"required"`
		Password  string `json:"password" binding:"required"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Role      string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, _ := auth.HashPassword(req.Password)
	user := &db.User{Username: req.Username, PasswordHash: hash, FirstName: req.FirstName, LastName: req.LastName, Email: req.Email, Role: req.Role}
	if err := s.db.CreateUser(user); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}
	if uid, ok := c.Get("userID"); ok {
		uname, _ := c.Get("username")
		s.db.LogAudit(uid.(int), uname.(string), "user_create", "Created user: "+req.Username, c.ClientIP())
	}
	c.JSON(http.StatusCreated, user)
}

func (s *Server) updateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Role      string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, _ := s.db.GetUserByID(id)
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	s.db.UpdateUser(user)
	c.JSON(http.StatusOK, user)
}

func (s *Server) deleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	currentUserID, _ := c.Get("userID")
	if id == currentUserID.(int) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete yourself"})
		return
	}
	if err := s.db.DeleteUser(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) resetUserPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.UpdateUserPassword(id, hash)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
