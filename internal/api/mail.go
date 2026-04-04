package api

import (
	"encoding/json"
	"net/http"

	"dns-supreme-mini/internal/mailer"
	"github.com/gin-gonic/gin"
)

func (s *Server) getMailSettings(c *gin.Context) {
	cfg := s.mailer.GetConfig()
	// Don't expose password in GET
	cfg.Password = ""
	if s.mailer.IsConfigured() {
		cfg.Password = "********"
	}
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) setMailSettings(c *gin.Context) {
	var cfg mailer.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// If password is masked, keep the old one
	if cfg.Password == "********" {
		old := s.mailer.GetConfig()
		cfg.Password = old.Password
	}
	s.mailer.SetConfig(cfg)

	// Persist
	if data, err := json.Marshal(cfg); err == nil {
		s.db.SetSetting("mail_config", string(data))
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type testMailReq struct {
	To string `json:"to"`
}

func (s *Server) sendTestMail(c *gin.Context) {
	var req testMailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		// If no body, send to configured from address
		req.To = s.mailer.GetConfig().From
	}
	if req.To == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No recipient email address"})
		return
	}
	if err := s.mailer.SendTest(req.To); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "sent_to": req.To})
}

func (s *Server) getMailNotifications(c *gin.Context) {
	c.JSON(http.StatusOK, s.mailer.GetNotifConfig())
}

func (s *Server) setMailNotifications(c *gin.Context) {
	var cfg mailer.NotifConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.mailer.SetNotifConfig(cfg)

	if data, err := json.Marshal(cfg); err == nil {
		s.db.SetSetting("mail_notifications", string(data))
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// LoadMailConfig loads mail settings from database (called on startup)
func (s *Server) LoadMailConfig() {
	if data := s.db.GetSetting("mail_config"); data != "" {
		var cfg mailer.Config
		if json.Unmarshal([]byte(data), &cfg) == nil {
			s.mailer.SetConfig(cfg)
		}
	}
	if data := s.db.GetSetting("mail_notifications"); data != "" {
		var cfg mailer.NotifConfig
		if json.Unmarshal([]byte(data), &cfg) == nil {
			s.mailer.SetNotifConfig(cfg)
		}
	}
}
