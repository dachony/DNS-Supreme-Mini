package api

import (
	"encoding/json"
	"net/http"

	"dns-supreme-mini/internal/filter"
	"github.com/gin-gonic/gin"
)

func (s *Server) setupPolicyRoutes(viewer, admin *gin.RouterGroup) {
	// Read-only policy routes (viewer-safe)
	viewPol := viewer.Group("/policies")
	{
		viewPol.GET("", s.listPolicies)
		viewPol.GET("/:ip", s.getPolicy)
	}

	// Write policy routes (admin-only)
	adminPol := admin.Group("/policies")
	{
		adminPol.POST("", s.createPolicy)
		adminPol.DELETE("/:ip", s.deletePolicy)
	}
}

func (s *Server) listPolicies(c *gin.Context) {
	if s.policies == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	c.JSON(http.StatusOK, s.policies.ListPolicies())
}

func (s *Server) createPolicy(c *gin.Context) {
	var p filter.DevicePolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if p.ClientIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_ip required"})
		return
	}
	s.policies.SetPolicy(&p)
	s.persistPolicies()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getPolicy(c *gin.Context) {
	ip := c.Param("ip")
	p := s.policies.GetPolicy(ip)
	if p == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no policy for this IP"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Server) deletePolicy(c *gin.Context) {
	ip := c.Param("ip")
	s.policies.RemovePolicy(ip)
	s.persistPolicies()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistPolicies() {
	policies := s.policies.ListPolicies()
	if data, err := json.Marshal(policies); err == nil {
		s.db.SetSetting("device_policies", string(data))
	}
}

func (s *Server) LoadPolicies() {
	if data := s.db.GetSetting("device_policies"); data != "" {
		var policies []*filter.DevicePolicy
		if json.Unmarshal([]byte(data), &policies) == nil {
			for _, p := range policies {
				s.policies.SetPolicy(p)
			}
		}
	}
}
