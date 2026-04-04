package api

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type logSettings struct {
	RetentionDays int  `json:"retention_days"`
	AutoCleanup   bool `json:"auto_cleanup"`
}

var currentLogSettings = logSettings{RetentionDays: 30, AutoCleanup: true}

func (s *Server) setupLogRoutes(viewer, admin *gin.RouterGroup) {
	// Read-only log management routes (viewer-safe)
	viewLogs := viewer.Group("/log-management")
	{
		viewLogs.GET("/settings", s.getLogSettings)
		viewLogs.GET("/stats", s.getLogStats)
		viewLogs.GET("/export", s.exportLogs)
	}

	// Write log management routes (admin-only)
	adminLogs := admin.Group("/log-management")
	{
		adminLogs.PUT("/settings", s.setLogSettings)
		adminLogs.DELETE("/older-than", s.deleteOlderThan)
		adminLogs.DELETE("/all", s.deleteAllLogs)
	}
}

func (s *Server) getLogSettings(c *gin.Context) {
	c.JSON(http.StatusOK, currentLogSettings)
}

func (s *Server) setLogSettings(c *gin.Context) {
	var req logSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RetentionDays < 1 {
		req.RetentionDays = 1
	}
	currentLogSettings = req
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type logStatsResp struct {
	TotalEntries int64  `json:"total_entries"`
	OldestEntry  string `json:"oldest_entry"`
	NewestEntry  string `json:"newest_entry"`
	SizeEstimate string `json:"size_estimate"`
}

func (s *Server) getLogStats(c *gin.Context) {
	var stats logStatsResp
	s.db.QueryRow("SELECT COUNT(*) FROM query_log").Scan(&stats.TotalEntries)

	var oldest, newest time.Time
	s.db.QueryRow("SELECT MIN(timestamp) FROM query_log").Scan(&oldest)
	s.db.QueryRow("SELECT MAX(timestamp) FROM query_log").Scan(&newest)
	if !oldest.IsZero() {
		stats.OldestEntry = oldest.Format(time.RFC3339)
	}
	if !newest.IsZero() {
		stats.NewestEntry = newest.Format(time.RFC3339)
	}

	// Rough estimate: ~200 bytes per row
	stats.SizeEstimate = humanBytes(stats.TotalEntries * 200)

	c.JSON(http.StatusOK, stats)
}

type deleteOlderReq struct {
	Days int `json:"days" binding:"required"`
}

func (s *Server) deleteOlderThan(c *gin.Context) {
	days, _ := strconv.Atoi(c.Query("days"))
	if days <= 0 {
		var req deleteOlderReq
		if err := c.ShouldBindJSON(&req); err != nil || req.Days <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "days parameter required (> 0)"})
			return
		}
		days = req.Days
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	result, err := s.db.Exec("DELETE FROM query_log WHERE timestamp < ?", cutoff)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	deleted, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "deleted": deleted})
}

func (s *Server) deleteAllLogs(c *gin.Context) {
	result, err := s.db.Exec("DELETE FROM query_log")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	deleted, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "deleted": deleted})
}

func (s *Server) exportLogs(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	since := time.Now().AddDate(0, 0, -days)

	rows, err := s.db.Query(`
		SELECT timestamp, client_ip, domain, query_type, blocked, COALESCE(block_rule,''),
			COALESCE(response_ip,''), COALESCE(latency_ms,0), COALESCE(upstream,''), COALESCE(protocol,'')
		FROM query_log WHERE timestamp > ? ORDER BY timestamp DESC
	`, since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	filename := fmt.Sprintf("dns-supreme-logs-%s.csv", time.Now().Format("2006-01-02"))
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename="+filename)

	w := csv.NewWriter(c.Writer)
	w.Write([]string{"Timestamp", "Client IP", "Domain", "Type", "Blocked", "Block Rule", "Response IP", "Latency (ms)", "Upstream", "Protocol"})

	for rows.Next() {
		var ts time.Time
		var clientIP, domain, qtype, blockRule, responseIP, upstream, protocol string
		var blocked bool
		var latency float64
		rows.Scan(&ts, &clientIP, &domain, &qtype, &blocked, &blockRule, &responseIP, &latency, &upstream, &protocol)

		blockedStr := "false"
		if blocked {
			blockedStr = "true"
		}
		w.Write([]string{
			ts.Format(time.RFC3339),
			clientIP, domain, qtype, blockedStr, blockRule,
			responseIP, fmt.Sprintf("%.2f", latency), upstream, protocol,
		})
	}
	w.Flush()
}
