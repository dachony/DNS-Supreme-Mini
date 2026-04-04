package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	dnsserver "dns-supreme-mini/internal/dns"
	"github.com/gin-gonic/gin"
)

func (s *Server) setupDNSSECRoutes(viewer, admin *gin.RouterGroup) {
	// Read-only DNSSEC routes (viewer-safe)
	viewDnssec := viewer.Group("/dnssec")
	{
		viewDnssec.GET("", s.listDNSSECKeys)
		viewDnssec.GET("/:zone", s.getDNSSECKey)
	}

	// Write DNSSEC routes (admin-only)
	adminDnssec := admin.Group("/dnssec")
	{
		adminDnssec.POST("/generate", s.generateDNSSECKey)
		adminDnssec.PUT("/:zone", s.toggleDNSSEC)
		adminDnssec.DELETE("/:zone", s.deleteDNSSECKey)
		adminDnssec.POST("/:zone/rotate", s.rotateDNSSECKey)
	}
}

func (s *Server) listDNSSECKeys(c *gin.Context) {
	keys := s.dnssec.ListKeys()
	c.JSON(http.StatusOK, keys)
}

type generateDNSSECReq struct {
	ZoneName string `json:"zone_name" binding:"required"`
}

func (s *Server) generateDNSSECKey(c *gin.Context) {
	var req generateDNSSECReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, err := s.dnssec.GenerateKey(req.ZoneName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.persistDNSSECKeys()
	c.JSON(http.StatusOK, key)
}

func (s *Server) getDNSSECKey(c *gin.Context) {
	zone := c.Param("zone")
	key := s.dnssec.GetKey(zone)
	if key == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no DNSSEC key for this zone"})
		return
	}
	c.JSON(http.StatusOK, key)
}

type toggleDNSSECReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) toggleDNSSEC(c *gin.Context) {
	zone := c.Param("zone")
	var req toggleDNSSECReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.dnssec.SetEnabled(zone, req.Enabled)
	s.persistDNSSECKeys()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) deleteDNSSECKey(c *gin.Context) {
	zone := c.Param("zone")
	s.dnssec.RemoveKey(zone)
	s.persistDNSSECKeys()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) rotateDNSSECKey(c *gin.Context) {
	zoneName := c.Param("zone")

	newKey, err := s.dnssec.RotateKey(zoneName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Persist to DB
	s.persistDNSSECKeys()

	// Audit log
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "dnssec_rotate", "Rotated DNSSEC key for zone: "+zoneName, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"key": newKey})
}

func (s *Server) persistDNSSECKeys() {
	keys := s.dnssec.ListKeys()
	data, _ := json.Marshal(keys)
	s.db.SetSetting("dnssec_keys", string(data))
}

func (s *Server) restoreDNSSECKeys() {
	data := s.db.GetSetting("dnssec_keys")
	if data == "" {
		return
	}
	var keys []dnsserver.DNSSECKey
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return
	}
	for _, k := range keys {
		if err := s.dnssec.RestoreKey(k); err != nil {
			slog.Error("failed to restore DNSSEC key", "component", "dnssec", "zone", k.ZoneName, "error", err)
		}
	}
}
