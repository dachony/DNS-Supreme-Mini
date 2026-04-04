package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"dns-supreme-mini/internal/db"
	"github.com/gin-gonic/gin"
)

type backupData struct {
	Version   string                 `json:"version"`
	Timestamp string                 `json:"timestamp"`
	Settings  map[string]string      `json:"settings"`
	Zones     []zoneBackup           `json:"zones"`
	Users     []db.User              `json:"users"`
}

type zoneBackup struct {
	Zone    db.Zone        `json:"zone"`
	Records []db.DNSRecord `json:"records"`
}

func (s *Server) setupBackupRoutes(admin *gin.RouterGroup) {
	admin.GET("/backup/export", s.exportBackup)
	admin.POST("/backup/restore", s.restoreBackup)
}

func (s *Server) exportBackup(c *gin.Context) {
	backup := backupData{
		Version:   "1.0",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Settings
	backup.Settings = s.db.GetSettings()

	// Zones + records
	zones, _ := s.db.ListZones()
	for _, z := range zones {
		records, _ := s.db.ListRecords(z.ID)
		backup.Zones = append(backup.Zones, zoneBackup{Zone: z, Records: records})
	}

	// Users
	backup.Users, _ = s.db.ListUsers()
	// Clear password hashes for safety — restore will require new passwords
	for i := range backup.Users {
		backup.Users[i].PasswordHash = ""
	}

	data, _ := json.MarshalIndent(backup, "", "  ")

	filename := fmt.Sprintf("dns-supreme-backup-%s.json", time.Now().Format("2006-01-02"))
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Data(http.StatusOK, "application/json", data)
}

func (s *Server) restoreBackup(c *gin.Context) {
	file, _, err := c.Request.FormFile("backup")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "backup file required"})
		return
	}
	defer file.Close()

	var backup backupData
	if err := json.NewDecoder(file).Decode(&backup); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid backup file: " + err.Error()})
		return
	}

	restored := struct {
		Settings int `json:"settings"`
		Zones    int `json:"zones"`
		Records  int `json:"records"`
	}{}

	// Restore settings
	for k, v := range backup.Settings {
		s.db.SetSetting(k, v)
		restored.Settings++
	}

	// Restore zones + records
	for _, zb := range backup.Zones {
		zone := &db.Zone{Name: zb.Zone.Name, Type: zb.Zone.Type, TTL: zb.Zone.TTL}
		if err := s.db.CreateZone(zone); err != nil {
			continue // zone may already exist
		}
		restored.Zones++
		for _, r := range zb.Records {
			s.db.CreateRecord(&db.DNSRecord{
				ZoneID:   zone.ID,
				Name:     r.Name,
				Type:     r.Type,
				Value:    r.Value,
				TTL:      r.TTL,
				Priority: r.Priority,
			})
			restored.Records++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Restored %d settings, %d zones, %d records", restored.Settings, restored.Zones, restored.Records),
	})
}
