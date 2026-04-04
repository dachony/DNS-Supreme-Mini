package api

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"dns-supreme-mini/internal/db"
	"github.com/gin-gonic/gin"
)

func validateRecordValue(rtype, value string) error {
	switch rtype {
	case "A":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 address: %s", value)
		}
	case "AAAA":
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid IPv6 address: %s", value)
		}
	case "MX", "CNAME", "NS":
		if value == "" || strings.Contains(value, " ") {
			return fmt.Errorf("invalid hostname: %s", value)
		}
	case "TXT":
		if len(value) > 255 {
			return fmt.Errorf("TXT record too long (max 255 chars)")
		}
	}
	return nil
}

func (s *Server) setupZoneRoutes(viewer, admin *gin.RouterGroup) {
	// Read-only zone routes (viewer-safe)
	viewZones := viewer.Group("/zones")
	{
		viewZones.GET("", s.listZones)
		viewZones.GET("/:id", s.getZone)
		viewZones.GET("/:id/records", s.listRecords)
		viewZones.GET("/:id/export", s.exportZone)
	}

	// Write zone routes (admin-only)
	adminZones := admin.Group("/zones")
	{
		adminZones.POST("", s.createZone)
		adminZones.DELETE("/:id", s.deleteZone)
		adminZones.POST("/:id/records", s.createRecord)
		adminZones.PUT("/:id/records/:rid", s.updateRecord)
		adminZones.DELETE("/:id/records/:rid", s.deleteRecord)
		adminZones.POST("/ptr", s.createPTRRecord)
	}
}

func (s *Server) listZones(c *gin.Context) {
	zones, err := s.db.ListZones()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Enrich with record count
	type zoneInfo struct {
		db.Zone
		RecordCount int `json:"record_count"`
	}
	result := make([]zoneInfo, len(zones))
	for i, z := range zones {
		records, _ := s.db.ListRecords(z.ID)
		result[i] = zoneInfo{Zone: z, RecordCount: len(records)}
	}
	c.JSON(http.StatusOK, result)
}

type createZoneReq struct {
	Name         string `json:"name" binding:"required"`
	Type         string `json:"type"`
	TTL          int    `json:"ttl"`
	PrimaryNS    string `json:"primary_ns"`
	AdminEmail   string `json:"admin_email"`
	Nameservers  []string `json:"nameservers"`
}

func (s *Server) createZone(c *gin.Context) {
	var req createZoneReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type == "" {
		req.Type = "primary"
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}
	if req.PrimaryNS == "" {
		req.PrimaryNS = "ns1." + req.Name
	}
	if req.AdminEmail == "" {
		req.AdminEmail = "admin." + req.Name
	}

	zone := &db.Zone{Name: req.Name, Type: req.Type, TTL: req.TTL}
	if err := s.db.CreateZone(zone); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "zone already exists"})
		return
	}

	// --- SOA ---
	soaValue := fmt.Sprintf("%s %s %d 3600 900 604800 300",
		req.PrimaryNS, req.AdminEmail, zone.SOASerial)
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "SOA", Value: soaValue, TTL: req.TTL,
	})

	// --- NS record (primary nameserver) ---
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "NS", Value: req.PrimaryNS, TTL: req.TTL,
	})

	// Auto-add secondary NS if cluster is configured
	settingsMu.RLock()
	clusterRole := clusterStore.Role
	clusterPeer := clusterStore.PeerAddress
	settingsMu.RUnlock()
	if clusterRole != "standalone" && clusterPeer != "" {
		secondaryNS := "ns2." + req.Name
		s.db.CreateRecord(&db.DNSRecord{
			ZoneID: zone.ID, Name: "@", Type: "NS", Value: secondaryNS, TTL: req.TTL,
		})
	}

	// Additional nameservers if explicitly provided
	for _, ns := range req.Nameservers {
		if ns != req.PrimaryNS {
			s.db.CreateRecord(&db.DNSRecord{
				ZoneID: zone.ID, Name: "@", Type: "NS", Value: ns, TTL: req.TTL,
			})
		}
	}

	c.JSON(http.StatusCreated, zone)
}

func (s *Server) getZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	zone, err := s.db.GetZone(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "zone not found"})
		return
	}

	records, _ := s.db.ListRecords(id)

	c.JSON(http.StatusOK, gin.H{
		"zone":    zone,
		"records": records,
	})
}

func (s *Server) deleteZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := s.db.DeleteZone(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type createRecordReq struct {
	Name     string `json:"name" binding:"required"`
	Type     string `json:"type" binding:"required"`
	Value    string `json:"value" binding:"required"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
}

func (s *Server) listRecords(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	records, err := s.db.ListRecords(zoneID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, records)
}

func (s *Server) createRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var req createRecordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}

	if err := validateRecordValue(req.Type, req.Value); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record := &db.DNSRecord{
		ZoneID: zoneID, Name: req.Name, Type: req.Type,
		Value: req.Value, TTL: req.TTL, Priority: req.Priority,
	}
	if err := s.db.CreateRecord(record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, record)
}

func (s *Server) updateRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	rid, _ := strconv.Atoi(c.Param("rid"))
	var req createRecordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}

	if err := validateRecordValue(req.Type, req.Value); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record := &db.DNSRecord{
		ID: rid, ZoneID: zoneID, Name: req.Name, Type: req.Type,
		Value: req.Value, TTL: req.TTL, Priority: req.Priority,
	}
	if err := s.db.UpdateRecord(record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, record)
}

func (s *Server) deleteRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	rid, _ := strconv.Atoi(c.Param("rid"))
	if err := s.db.DeleteRecord(rid, zoneID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) exportZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	zone, err := s.db.GetZone(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "zone not found"})
		return
	}
	records, _ := s.db.ListRecords(id)

	// Generate BIND zone file format
	var b strings.Builder
	b.WriteString(fmt.Sprintf("; Zone file for %s\n", zone.Name))
	b.WriteString(fmt.Sprintf("; Exported from DNS Supreme\n"))
	b.WriteString(fmt.Sprintf("$ORIGIN %s.\n", zone.Name))
	b.WriteString(fmt.Sprintf("$TTL %d\n\n", zone.TTL))

	for _, r := range records {
		name := r.Name
		if name == "@" {
			name = zone.Name + "."
		}
		if r.Type == "MX" || r.Type == "SRV" {
			b.WriteString(fmt.Sprintf("%-24s %d IN %-6s %d %s\n", name, r.TTL, r.Type, r.Priority, r.Value))
		} else {
			b.WriteString(fmt.Sprintf("%-24s %d IN %-6s %s\n", name, r.TTL, r.Type, r.Value))
		}
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zone", zone.Name))
	c.Data(http.StatusOK, "text/plain", []byte(b.String()))
}

type createPTRReq struct {
	IP       string `json:"ip" binding:"required"`
	Hostname string `json:"hostname" binding:"required"`
}

func (s *Server) createPTRRecord(c *gin.Context) {
	var req createPTRReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	parts := strings.Split(req.IP, ".")
	if len(parts) != 4 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only IPv4 supported for auto-PTR"})
		return
	}

	reverseZone := parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa"
	ptrName := parts[3]

	zone, err := s.db.GetZoneByName(reverseZone)
	if err != nil {
		zone = &db.Zone{Name: reverseZone, Type: "primary", TTL: 3600}
		if err := s.db.CreateZone(zone); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create reverse zone"})
			return
		}
		settingsMu.RLock()
		hn := hostnameStore
		settingsMu.RUnlock()
		soaVal := fmt.Sprintf("%s admin.%s %d 3600 900 604800 300", hn, reverseZone, zone.SOASerial)
		s.db.CreateRecord(&db.DNSRecord{ZoneID: zone.ID, Name: "@", Type: "SOA", Value: soaVal, TTL: 3600})
		s.db.CreateRecord(&db.DNSRecord{ZoneID: zone.ID, Name: "@", Type: "NS", Value: hn, TTL: 3600})
	}

	s.db.CreateRecord(&db.DNSRecord{ZoneID: zone.ID, Name: ptrName, Type: "PTR", Value: req.Hostname, TTL: 3600})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "reverse_zone": reverseZone, "ptr_name": ptrName})
}
