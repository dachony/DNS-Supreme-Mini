package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dns-supreme-mini/internal/auth"
	"dns-supreme-mini/internal/blockpage"
	"dns-supreme-mini/internal/certs"
	"dns-supreme-mini/internal/config"
	"dns-supreme-mini/internal/db"
	dnsserver "dns-supreme-mini/internal/dns"
	"dns-supreme-mini/internal/filter"
	"dns-supreme-mini/internal/mailer"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg        config.APIConfig
	db         *db.Database
	filter     *filter.Engine
	netProtect *filter.NetProtectEngine
	blockPage  *blockpage.Server
	policies   *filter.PolicyManager
	dns        *dnsserver.Server
	dnssec     *dnsserver.DNSSECManager
	fail2ban      *Fail2Ban
	mailer        *mailer.Mailer
	acmeClient    *certs.ACMEClient
	emailMFACodesMu sync.RWMutex
	emailMFACodes   map[int]emailMFAEntry // userID -> code+expiry
	blocklistTimer *time.Timer
	sseHub         *sseHub
	router         *gin.Engine
}

func NewServer(cfg config.APIConfig, database *db.Database, filterEngine *filter.Engine, netProtect *filter.NetProtectEngine, bp *blockpage.Server, dnsServer *dnsserver.Server) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:    []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: false,
	}))

	s := &Server{
		cfg:        cfg,
		db:         database,
		filter:     filterEngine,
		netProtect: netProtect,
		blockPage:  bp,
		policies:   filter.NewPolicyManager(),
		dns:        dnsServer,
		fail2ban:      NewFail2Ban(),
		mailer:        mailer.New(),
		acmeClient:    certs.NewACMEClient("/app/certs"),
		emailMFACodes: make(map[int]emailMFAEntry),
		sseHub:     newSSEHub(),
		dnssec:     dnsserver.NewDNSSECManager(),
		router:     router,
	}

	auth.InitSecret(database.GetSetting, database.SetSetting)
	s.ensureDefaultAdmin()
	s.LoadMailConfig()
	s.LoadFail2BanConfig()
	s.LoadPolicies()
	s.LoadBlockPageTemplate()
	s.loadACMEConfig()
	s.getClusterFromDB()
	dnsServer.SetDNSSEC(s.dnssec)
	s.setupRoutes()
	go s.broadcastStats()
	return s
}

func (s *Server) ensureDefaultAdmin() {
	if s.db.UserCount() == 0 {
		hash, _ := auth.HashPassword("admin")
		user := &db.User{
			Username:     "admin",
			PasswordHash: hash,
			FirstName:    "Administrator",
			LastName:     "",
			Email:        "",
			Role:         "admin",
		}
		if err := s.db.CreateUser(user); err != nil {
			slog.Error("failed to create default admin", "component", "api", "error", err)
		} else {
			s.db.SetSetting("force_password_change", "true")
			slog.Info("default admin user created", "component", "api", "username", "admin")
		}
	}
}

func (s *Server) setupRoutes() {
	// Serve frontend static files
	s.router.Static("/assets", "/app/web/dist/assets")
	s.router.Static("/uploads", "/app/data/uploads")
	s.router.NoRoute(func(c *gin.Context) {
		c.File("/app/web/dist/index.html")
	})

	api := s.router.Group("/api")

	// Health check and restart (no auth on health)
	api.GET("/health", func(c *gin.Context) {
		dbOK := true
		if err := s.db.Ping(); err != nil {
			dbOK = false
		}

		status := "healthy"
		code := http.StatusOK
		if !dbOK {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}

		c.JSON(code, gin.H{
			"status":         status,
			"version":        "2.0.0",
			"uptime_seconds": int64(time.Since(startTime).Seconds()),
			"db_ok":          dbOK,
			"dns_ok":         true,
		})
	})

	// Prometheus metrics (no auth, for monitoring scrapers)
	api.GET("/metrics", s.prometheusMetrics)

	// Public auth endpoints
	api.POST("/auth/login", s.login)
	api.POST("/auth/mfa-verify", s.mfaVerify)
	api.POST("/auth/forgot-password", s.forgotPassword)
	api.POST("/auth/reset-password", s.resetPassword)

	// SSE endpoint (manual auth — EventSource can't send headers)
	api.GET("/events", s.sseHandler)

	// Protected endpoints (authenticated users — viewers + admins)
	protected := api.Group("")
	protected.Use(auth.AuthMiddleware())
	{
		// === Viewer-safe routes (read-only) ===

		// Dashboard & monitoring
		protected.GET("/stats", s.getStats)
		protected.GET("/logs", s.getLogs)
		protected.GET("/status", s.getStatus)
		protected.GET("/system-metrics", s.getSystemMetrics)

		// Blocklists (read)
		protected.GET("/blocklists", s.getBlocklists)
		protected.GET("/blocklists/:name/domains", s.getBlocklistDomains)

		// Custom blocks & allowlist (read)
		protected.GET("/custom-blocks", s.getCustomBlocks)
		protected.GET("/allowlist", s.getAllowlist)

		// Categories & geo-blocking (read)
		protected.GET("/categories", s.getCategories)
		protected.GET("/geo-blocked", s.getGeoBlocked)

		// Block services (read)
		protected.GET("/block-services", s.getBlockServices)

		// Network protection (read)
		protected.GET("/network-protection", s.getNetProtectCategories)
		protected.GET("/network-protection/:id/entries", s.getNetProtectEntries)
		protected.GET("/network-protection/geo", s.getNetProtectGeo)
		protected.GET("/network-protection/settings", s.getNetProtectSettings)

		// Fail2ban (read)
		protected.GET("/fail2ban", s.getFail2BanStatus)

		// Mail (read)
		protected.GET("/mail/settings", s.getMailSettings)
		protected.GET("/mail/notifications", s.getMailNotifications)

		// Settings (read)
		protected.GET("/settings/blockpage", s.getBlockPageTemplate)
		protected.GET("/settings/blockpage/domain", s.getBlockPageDomain)
		protected.GET("/settings/blockpage/redirect", s.getBlockPageRedirect)
		protected.GET("/settings/forwarders", s.getForwarders)
		protected.GET("/settings/server", s.getServerSettings)
		protected.GET("/settings/hostname", s.getHostname)
		protected.GET("/settings/primary-domain", s.getPrimaryDomain)
		protected.GET("/settings/cluster", s.getCluster)
		protected.GET("/settings/filtering-mode", s.getFilteringMode)

		// Certificates (read)
		protected.GET("/certs", s.getCerts)

		// Current user (own account management)
		protected.GET("/auth/me", s.getMe)
		protected.PUT("/auth/password", s.changePassword)
		protected.POST("/auth/mfa/setup", s.setupMFA)
		protected.POST("/auth/mfa/enable", s.enableMFA)
		protected.DELETE("/auth/mfa", s.disableMFA)

		// Sub-route groups with viewer/admin split
		// (GET routes registered on protected, write routes on admin below)

		// === Admin-only routes (all write/config operations) ===
		admin := protected.Group("")
		admin.Use(auth.AdminOnly())
		{
			// Blocklists (write)
			admin.POST("/blocklists", s.addBlocklist)
			admin.POST("/blocklists/update", s.updateBlocklists)
			admin.GET("/blocklists/schedule", s.getBlocklistSchedule)
			admin.PUT("/blocklists/schedule", s.setBlocklistSchedule)
			admin.DELETE("/blocklists/:name", s.removeBlocklist)

			// Custom blocks (write)
			admin.POST("/custom-blocks", s.addCustomBlock)
			admin.DELETE("/custom-blocks/:domain", s.removeCustomBlock)

			// Allowlist (write)
			admin.POST("/allowlist", s.addAllowlist)
			admin.DELETE("/allowlist/:domain", s.removeAllowlist)

			// Categories (write)
			admin.PUT("/categories/:name", s.toggleCategory)

			// Geo-blocking (write)
			admin.PUT("/geo-blocked", s.setGeoBlocked)

			// Block services (write)
			admin.PUT("/block-services/service/:id", s.toggleBlockService)
			admin.PUT("/block-services/category/:id", s.toggleBlockServiceCategory)

			// Network protection (write)
			admin.PUT("/network-protection/:id", s.setNetProtectCategory)
			admin.PUT("/network-protection/geo", s.setNetProtectGeo)
			admin.POST("/network-protection/refresh", s.refreshNetProtect)
			admin.PUT("/network-protection/settings", s.setNetProtectSettings)

			// Fail2ban (write)
			admin.PUT("/fail2ban/settings", s.setFail2BanSettings)
			admin.DELETE("/fail2ban/unban/:ip", s.unbanIP)
			admin.PUT("/fail2ban/allowed-ips", s.setAllowedIPs)

			// Server restart
			admin.POST("/restart", s.restartServer)

			// Mail (write)
			admin.PUT("/mail/settings", s.setMailSettings)
			admin.POST("/mail/test", s.sendTestMail)
			admin.PUT("/mail/notifications", s.setMailNotifications)

			// Settings (write)
			admin.PUT("/settings/blockpage", s.setBlockPageTemplate)
			admin.POST("/settings/blockpage/upload-logo", s.uploadBlockPageLogo)
		admin.PUT("/settings/blockpage/domain", s.setBlockPageDomain)
			admin.POST("/settings/blockpage/setup-domain", s.setupBlockPageDomain)
			admin.PUT("/settings/blockpage/redirect", s.setBlockPageRedirect)
			admin.PUT("/settings/forwarders", s.setForwarders)
			admin.PUT("/settings/server", s.updateServerSettings)
			admin.PUT("/settings/hostname", s.setHostname)
			admin.PUT("/settings/primary-domain", s.setPrimaryDomain)
			admin.PUT("/settings/cluster", s.setCluster)
			admin.POST("/settings/cluster/test", s.testClusterPeer)
			admin.PUT("/settings/filtering-mode", s.setFilteringMode)

			// Certificate management (write + admin-only reads)
			admin.GET("/certs/zones", s.getCertZones)
			admin.POST("/certs/generate", s.generateSelfSigned)
			admin.DELETE("/certs", s.deleteCert)
			admin.POST("/certs/upload", s.uploadCert)
			admin.GET("/certs/export", s.exportCert)
			admin.GET("/acme/config", s.getACMEConfig)
			admin.GET("/acme/status/:domain", s.getACMEStatus)
			admin.PUT("/acme/config", s.setACMEConfig)
			admin.POST("/acme/request", s.requestACMECert)

			// User management
			admin.GET("/audit-logs", s.getAuditLogs)
			admin.GET("/users", s.listUsers)
			admin.POST("/users", s.createUser)
			admin.PUT("/users/:id", s.updateUser)
			admin.DELETE("/users/:id", s.deleteUser)
			admin.PUT("/users/:id/password", s.resetUserPassword)
		}

		// Sub-route groups: viewer GET routes on protected, write routes on admin
		s.setupLogRoutes(protected, admin)
		s.setupZoneRoutes(protected, admin)
		s.setupDNSSECRoutes(protected, admin)
		s.setupPolicyRoutes(protected, admin)
		s.setupBackupRoutes(admin)
	}
}

type emailMFAEntry struct {
	Code      string
	ExpiresAt time.Time
}

func (s *Server) storeEmailMFACode(userID int, code string) {
	s.emailMFACodesMu.Lock()
	defer s.emailMFACodesMu.Unlock()
	s.emailMFACodes[userID] = emailMFAEntry{
		Code:      code,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func (s *Server) verifyEmailMFACode(userID int, code string) bool {
	s.emailMFACodesMu.Lock()
	defer s.emailMFACodesMu.Unlock()
	entry, ok := s.emailMFACodes[userID]
	if !ok {
		return false
	}
	delete(s.emailMFACodes, userID)
	return entry.Code == code && time.Now().Before(entry.ExpiresAt)
}

func (s *Server) restartServer(c *gin.Context) {
	slog.Info("server restart requested via API", "component", "api")
	c.JSON(http.StatusOK, gin.H{"status": "restarting"})

	// Full restart: send SIGTERM so Docker restarts the container
	go func() {
		time.Sleep(500 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			slog.Info("sending SIGTERM for full restart", "component", "api")
			p.Signal(syscall.SIGTERM)
		}
	}()
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	slog.Info("web UI and API available", "component", "api", "addr", addr)

	// Restore DNSSEC keys from database
	s.restoreDNSSECKeys()

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

	// Start HTTPS management panel if enabled
	mgmtHTTPS := false
	if data := s.db.GetSetting("server_settings"); data != "" {
		var ss struct {
			ManagementHTTPS bool `json:"management_https"`
		}
		if json.Unmarshal([]byte(data), &ss) == nil {
			mgmtHTTPS = ss.ManagementHTTPS
		}
	}
	if mgmtHTTPS && s.cfg.HTTPSPort > 0 {
		httpsAddr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.HTTPSPort)
		certFile, keyFile := "/app/certs/server.crt", "/app/certs/server.key"
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			slog.Warn("management HTTPS enabled but no certificate found", "component", "api", "cert", certFile)
		} else {
			go func() {
				slog.Info("management HTTPS starting", "component", "api", "addr", httpsAddr)
				httpsServer := &http.Server{
					Addr:    httpsAddr,
					Handler: s.router,
				}
				if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil {
					slog.Error("management HTTPS failed", "component", "api", "error", err)
				}
			}()
		}
	}

	return nil
}

// --- Auth Handlers ---

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (s *Server) login(c *gin.Context) {
	clientIP := c.ClientIP()

	// Fail2ban: check if IP is banned
	if s.fail2ban.IsBanned(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts. Your IP is temporarily blocked."})
		return
	}

	// Access control: check if IP is allowed
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
		banned := s.fail2ban.RecordFail(clientIP)
		if banned {
			// Send security alert if admin has email
			admins, _ := s.db.GetAdminEmails()
			for _, email := range admins {
				go s.mailer.SendSecurityAlert(email,
					"IP Banned",
					fmt.Sprintf("IP %s was banned after too many failed login attempts for user '%s'", clientIP, req.Username))
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	s.fail2ban.RecordSuccess(clientIP)

	// If MFA is enabled, return partial token (mfaDone=false)
	mfaDone := !user.MFAEnabled
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, mfaDone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	if !mfaDone {
		// If email MFA, send the code now
		if user.MFAType == "email" && user.Email != "" && s.mailer.IsConfigured() {
			code := auth.GenerateEmailCode()
			s.storeEmailMFACode(user.ID, code)
			go s.mailer.SendMFACode(user.Email, code)
		}
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
			"id":         user.ID,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"email":      user.Email,
			"role":       user.Role,
		},
	})
}

type mfaVerifyReq struct {
	Code string `json:"code" binding:"required"`
}

func (s *Server) mfaVerify(c *gin.Context) {
	clientIP := c.ClientIP()
	if s.fail2ban.IsBanned(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts. Your IP is temporarily blocked."})
		return
	}

	header := c.GetHeader("Authorization")
	if header == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token required"})
		return
	}
	token := header
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	claims, err := auth.ValidateTokenPartial(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req mfaVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.db.GetUserByID(claims.UserID)
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Verify based on MFA type
	verified := false
	if user.MFAType == "email" {
		verified = s.verifyEmailMFACode(user.ID, req.Code)
	} else {
		verified = auth.VerifyTOTP(user.MFASecret, req.Code)
	}
	// Check recovery codes as fallback
	if !verified {
		codesStr := s.db.GetRecoveryCodes(user.ID)
		if codesStr != "" {
			codes := strings.Split(codesStr, ",")
			for i, code := range codes {
				if code == req.Code {
					verified = true
					// Remove used code
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

	// Issue full token
	fullToken, _ := auth.GenerateToken(user.ID, user.Username, user.Role, true)
	s.db.UpdateLastLogin(user.ID)

	c.JSON(http.StatusOK, gin.H{
		"token": fullToken,
		"user": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"email":      user.Email,
			"role":       user.Role,
		},
	})
}

func (s *Server) getMe(c *gin.Context) {
	userID, _ := c.Get("userID")
	user, err := s.db.GetUserByID(userID.(int))
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

type changePasswordReq struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (s *Server) changePassword(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req changePasswordReq
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
	// Clear force password change flag if it was set
	if s.db.GetSetting("force_password_change") == "true" {
		s.db.DeleteSetting("force_password_change")
	}
	s.db.LogAudit(user.ID, user.Username, "password_change", "Password changed", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) setupMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	uri := auth.TOTPProvisioningURI(secret, username.(string), "DNS-supreme")

	// Store secret temporarily (not enabled yet)
	s.db.UpdateUserMFA(userID.(int), false, "totp", secret)

	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"uri":    uri,
	})
}

type enableMFAReq struct {
	Code string `json:"code" binding:"required"`
}

func (s *Server) enableMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req enableMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.db.GetUserByID(userID.(int))
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if user.MFASecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run MFA setup first"})
		return
	}

	if !auth.VerifyTOTP(user.MFASecret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code, try again"})
		return
	}

	s.db.UpdateUserMFA(user.ID, true, "totp", user.MFASecret)

	// Generate recovery codes
	recoveryCodes := auth.GenerateRecoveryCodes()
	codesStr := strings.Join(recoveryCodes, ",")
	s.db.SetRecoveryCodes(user.ID, codesStr)

	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"mfa_enabled":    true,
		"recovery_codes": recoveryCodes,
	})
}

func (s *Server) disableMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	s.db.UpdateUserMFA(userID.(int), false, "", "")
	s.db.SetRecoveryCodes(userID.(int), "")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mfa_enabled": false})
}

// --- User Management (admin) ---

func (s *Server) listUsers(c *gin.Context) {
	users, err := s.db.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

type createUserReq struct {
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password" binding:"required"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

func (s *Server) createUser(c *gin.Context) {
	var req createUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.Role != "admin" && req.Role != "viewer" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'viewer'"})
		return
	}

	if err := auth.ValidatePassword(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, _ := auth.HashPassword(req.Password)
	user := &db.User{
		Username:     req.Username,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Email:        req.Email,
		Role:         req.Role,
	}

	if err := s.db.CreateUser(user); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}

	adminID, _ := c.Get("userID")
	adminName, _ := c.Get("username")
	s.db.LogAudit(adminID.(int), adminName.(string), "user_create", "Created user: "+req.Username, c.ClientIP())
	c.JSON(http.StatusCreated, user)
}

type updateUserReq struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

func (s *Server) updateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req updateUserReq
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
	deletedUser, _ := s.db.GetUserByID(id)
	if err := s.db.DeleteUser(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	adminName, _ := c.Get("username")
	deletedName := fmt.Sprintf("user_id=%d", id)
	if deletedUser != nil {
		deletedName = deletedUser.Username
	}
	s.db.LogAudit(currentUserID.(int), adminName.(string), "user_delete", "Deleted user: "+deletedName, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type resetPasswordReq struct {
	NewPassword string `json:"new_password" binding:"required"`
}

func (s *Server) resetUserPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req resetPasswordReq
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

type forgotPasswordReq struct {
	Email string `json:"email" binding:"required"`
}

func (s *Server) forgotPassword(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Always return success to prevent email enumeration
	defer func() {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "If an account with that email exists, a reset link has been sent."})
	}()

	user, err := s.db.GetUserByEmail(req.Email)
	if err != nil || user == nil {
		return // Don't reveal if email exists
	}

	token := auth.GenerateResetToken()
	s.db.CreatePasswordReset(user.ID, token, time.Now().Add(1*time.Hour))

	// Build reset URL
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	resetURL := fmt.Sprintf("%s://%s/reset-password?token=%s", scheme, host, token)

	// Send email
	body := fmt.Sprintf(`<h2>DNS Supreme — Password Reset</h2>
<p>A password reset was requested for account <strong>%s</strong>.</p>
<p>Click the link below to reset your password. This link expires in 1 hour.</p>
<p><a href="%s" style="display:inline-block;padding:12px 24px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">Reset Password</a></p>
<p style="margin-top:16px;font-size:0.85rem;color:#64748b">If the button doesn't work, copy this URL: %s</p>
<p style="color:#64748b;font-size:12px">If you didn't request this, ignore this email. Your password will not be changed.</p>`, user.Username, resetURL, resetURL)

	go s.mailer.Send(user.Email, "DNS Supreme — Password Reset", body)

	slog.Info("password reset requested", "component", "auth", "email", req.Email, "username", user.Username)
}

type resetPasswordReq2 struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func (s *Server) resetPassword(c *gin.Context) {
	var req resetPasswordReq2
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := s.db.ValidateResetToken(req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.UpdateUserPassword(userID, hash)
	s.db.MarkResetTokenUsed(req.Token)

	// Audit log
	user, _ := s.db.GetUserByID(userID)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	s.db.LogAudit(userID, username, "password_reset", "Password reset via email link", c.ClientIP())

	slog.Info("password reset completed", "component", "auth", "user_id", userID)

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Password has been reset. You can now log in."})
}

func (s *Server) getAuditLogs(c *gin.Context) {
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "50")); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	if o, err := strconv.Atoi(c.DefaultQuery("offset", "0")); err == nil && o >= 0 {
		offset = o
	}
	entries, total, err := s.db.GetAuditLogs(limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"entries": entries, "total": total})
}

// --- Existing Handlers ---

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

	c.JSON(http.StatusOK, gin.H{
		"data":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) getBlocklists(c *gin.Context) {
	lists := s.filter.GetLists()
	totalDomains, totalLists := s.filter.Stats()
	c.JSON(http.StatusOK, gin.H{
		"lists":         lists,
		"total_domains": totalDomains,
		"total_lists":   totalLists,
	})
}

type addBlocklistReq struct {
	Name     string `json:"name" binding:"required"`
	URL      string `json:"url" binding:"required"`
	Category string `json:"category"`
}

func (s *Server) addBlocklist(c *gin.Context) {
	var req addBlocklistReq
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
	// Persist to database
	lists := s.filter.GetLists()
	for _, l := range lists {
		if l.Name == req.Name {
			s.db.SaveBlocklistWithCategory(l.Name, req.URL, string(l.Category), l.Count)
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
				slog.Error("failed to update blocklist", "component", "filter", "name", l.Name, "error", err)
				continue
			}
			updated := s.filter.GetLists()
			for _, u := range updated {
				if u.Name == l.Name {
					s.db.SaveBlocklistWithCategory(u.Name, l.URL, string(u.Category), u.Count)
					break
				}
			}
		}
		slog.Info("updated blocklists", "component", "filter", "count", len(lists))
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
		slog.Info("blocklist auto-update disabled", "component", "filter")
		return
	}
	d := time.Duration(hours) * time.Hour
	s.blocklistTimer = time.AfterFunc(d, func() {
		slog.Info("blocklist auto-update triggered", "component", "filter", "interval_hours", hours)
		lists := s.filter.GetLists()
		for _, l := range lists {
			if err := s.filter.UpdateList(l.Name); err != nil {
				slog.Error("blocklist auto-update failed", "component", "filter", "name", l.Name, "error", err)
			}
		}
		s.startBlocklistTimer(hours) // re-schedule
	})
	slog.Info("blocklist auto-update scheduled", "component", "filter", "interval_hours", hours)
}

func (s *Server) removeBlocklist(c *gin.Context) {
	name := c.Param("name")
	s.filter.RemoveList(name)
	s.db.RemoveBlocklist(name)
	if uid, ok := c.Get("userID"); ok {
		uname, _ := c.Get("username")
		s.db.LogAudit(uid.(int), uname.(string), "blocklist_remove", "Removed blocklist: "+name, c.ClientIP())
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getBlocklistDomains(c *gin.Context) {
	name := c.Param("name")
	domains := s.filter.GetListDomains(name, 200)
	c.JSON(http.StatusOK, gin.H{"name": name, "domains": domains, "sample_size": len(domains)})
}

func (s *Server) getCustomBlocks(c *gin.Context) {
	blocks := s.filter.GetCustomBlocks()
	c.JSON(http.StatusOK, blocks)
}

type customBlockReq struct {
	Domain string `json:"domain" binding:"required"`
	Reason string `json:"reason"`
}

func (s *Server) addCustomBlock(c *gin.Context) {
	var req customBlockReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.AddCustomBlock(req.Domain, req.Reason)
	s.persistCustomBlocks()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) removeCustomBlock(c *gin.Context) {
	domain := c.Param("domain")
	s.filter.RemoveCustomBlock(domain)
	s.persistCustomBlocks()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistCustomBlocks() {
	blocks := s.filter.GetCustomBlocks()
	if data, err := json.Marshal(blocks); err == nil {
		s.db.SetSetting("custom_blocks", string(data))
	}
}

func (s *Server) getAllowlist(c *gin.Context) {
	list := s.filter.GetAllowlist()
	c.JSON(http.StatusOK, list)
}

type allowlistReq struct {
	Domain string `json:"domain" binding:"required"`
}

func (s *Server) addAllowlist(c *gin.Context) {
	var req allowlistReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.AddAllowlistDomain(req.Domain)
	s.persistAllowlist()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) removeAllowlist(c *gin.Context) {
	domain := c.Param("domain")
	s.filter.RemoveAllowlistDomain(domain)
	s.persistAllowlist()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistAllowlist() {
	list := s.filter.GetAllowlist()
	if data, err := json.Marshal(list); err == nil {
		s.db.SetSetting("allowlist", string(data))
	}
}

func (s *Server) getStatus(c *gin.Context) {
	totalDomains, totalLists := s.filter.Stats()
	npCats := 0
	if s.netProtect != nil {
		for _, cat := range s.netProtect.GetCategories() {
			if cat.Enabled {
				npCats++
			}
		}
	}
	geoCodes := 0
	if s.netProtect != nil {
		geoCodes = len(s.netProtect.GetGeoBlocked())
	}
	bannedIPs := 0
	if s.fail2ban != nil {
		bannedIPs = len(s.fail2ban.GetBannedIPs())
	}
	c.JSON(http.StatusOK, gin.H{
		"status":                "running",
		"version":               "1.0.0",
		"total_domains":         totalDomains,
		"total_lists":           totalLists,
		"np_active_feeds":       npCats,
		"geo_blocked_countries": geoCodes,
		"banned_ips":            bannedIPs,
		"users":                 s.db.UserCount(),
		"smtp_configured":       s.mailer.IsConfigured(),
	})
}

// --- Categories ---

func (s *Server) getCategories(c *gin.Context) {
	categories := s.filter.GetCategories()
	catStats := s.filter.CategoryStats()
	result := make([]gin.H, 0)
	for cat, enabled := range categories {
		result = append(result, gin.H{
			"name":    string(cat),
			"enabled": enabled,
			"domains": catStats[cat],
		})
	}
	c.JSON(http.StatusOK, result)
}

type toggleCategoryReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) toggleCategory(c *gin.Context) {
	name := c.Param("name")
	var req toggleCategoryReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cat := filter.Category(name)
	if req.Enabled {
		s.filter.EnableCategory(cat)
	} else {
		s.filter.DisableCategory(cat)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- Geo-blocking ---

func (s *Server) getGeoBlocked(c *gin.Context) {
	countries := s.filter.GetGeoBlocked()
	c.JSON(http.StatusOK, countries)
}

type setGeoBlockedReq struct {
	Countries []string `json:"countries"`
}

func (s *Server) setGeoBlocked(c *gin.Context) {
	var req setGeoBlockedReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.SetGeoBlocked(req.Countries)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "blocked_countries": len(req.Countries)})
}

// --- Block Services ---

func (s *Server) getBlockServices(c *gin.Context) {
	sb := s.filter.ServiceBlocker()
	c.JSON(http.StatusOK, sb.GetCategories())
}

func (s *Server) toggleBlockService(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sb := s.filter.ServiceBlocker()
	sb.SetServiceEnabled(id, req.Enabled)
	s.filter.ClearFilterCache()
	s.persistBlockServices()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) toggleBlockServiceCategory(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	sb := s.filter.ServiceBlocker()
	sb.SetCategoryEnabled(id, req.Enabled)
	s.filter.ClearFilterCache()
	s.persistBlockServices()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistBlockServices() {
	sb := s.filter.ServiceBlocker()
	ids := sb.GetEnabledServiceIDs()
	data, _ := json.Marshal(ids)
	s.db.SetSetting("blocked_services", string(data))
}
