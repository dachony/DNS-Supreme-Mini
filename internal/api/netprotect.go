package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) getNetProtectCategories(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	c.JSON(http.StatusOK, s.netProtect.GetCategories())
}

type setNetProtectReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) setNetProtectCategory(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "network protection not available"})
		return
	}
	id := c.Param("id")
	var req setNetProtectReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.netProtect.SetCategoryEnabled(id, req.Enabled); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Persist enabled categories
	s.saveNpCategories()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": id, "enabled": req.Enabled})
}

func (s *Server) getNetProtectGeo(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusOK, []string{})
		return
	}
	c.JSON(http.StatusOK, s.netProtect.GetGeoBlocked())
}

type setNetProtectGeoReq struct {
	Countries []string `json:"countries"`
}

func (s *Server) setNetProtectGeo(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "network protection not available"})
		return
	}
	var req setNetProtectGeoReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.netProtect.SetGeoBlocked(req.Countries)
	if data, err := json.Marshal(req.Countries); err == nil {
		s.db.SetSetting("geo_blocked_countries", string(data))
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "blocked_countries": len(req.Countries)})
}

func (s *Server) saveNpCategories() {
	cats := s.netProtect.GetCategories()
	enabled := make([]string, 0)
	for _, c := range cats {
		if c.Enabled {
			enabled = append(enabled, c.ID)
		}
	}
	if data, err := json.Marshal(enabled); err == nil {
		s.db.SetSetting("np_enabled_categories", string(data))
	}
}

func (s *Server) getNetProtectEntries(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "network protection not available"})
		return
	}
	id := c.Param("id")
	entries, err := s.netProtect.GetCategoryEntries(id, 100)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "entries": entries, "sample_size": len(entries)})
}

func (s *Server) refreshNetProtect(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "network protection not available"})
		return
	}
	go s.netProtect.RefreshNow()
	c.JSON(http.StatusOK, gin.H{"status": "refreshing"})
}

func (s *Server) getNetProtectSettings(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusOK, gin.H{"refresh_minutes": 360})
		return
	}
	c.JSON(http.StatusOK, gin.H{"refresh_minutes": s.netProtect.GetRefreshInterval()})
}

type setNetProtectSettingsReq struct {
	RefreshMinutes int `json:"refresh_minutes"`
}

func (s *Server) setNetProtectSettings(c *gin.Context) {
	if s.netProtect == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "network protection not available"})
		return
	}
	var req setNetProtectSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.netProtect.SetRefreshInterval(req.RefreshMinutes)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "refresh_minutes": s.netProtect.GetRefreshInterval()})
}
