package api

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

type certAlert struct {
	Subject   string `json:"subject"`
	ExpiresAt string `json:"expires_at"`
	DaysLeft  int    `json:"days_left"`
	Warning   bool   `json:"warning"`
}

type appMetrics struct {
	HeapAlloc    uint64 `json:"heap_alloc"`     // bytes allocated on heap
	HeapSys      uint64 `json:"heap_sys"`       // bytes obtained from OS for heap
	StackInuse   uint64 `json:"stack_inuse"`    // bytes in stack spans
	TotalAlloc   uint64 `json:"total_alloc"`    // cumulative bytes allocated
	NumGC        uint32 `json:"num_gc"`         // completed GC cycles
	LastGCPause  uint64 `json:"last_gc_pause"`  // nanoseconds of last GC pause
	Goroutines   int    `json:"goroutines"`
	FilterDomains int   `json:"filter_domains"` // domains loaded in filter engine
	FilterLists   int   `json:"filter_lists"`   // active blocklists
	CacheSize     int   `json:"cache_size"`     // filter cache entries (approx)
	BlockedSvcs   int   `json:"blocked_services"` // enabled service blocks
}

type systemMetrics struct {
	CPU        cpuMetrics  `json:"cpu"`
	Memory     memMetrics  `json:"memory"`
	Disk       diskMetrics `json:"disk"`
	Database   dbMetrics   `json:"database"`
	App        appMetrics  `json:"app"`
	Uptime     int64       `json:"uptime_seconds"`
	GoRoutines int         `json:"goroutines"`
	Certs      []certAlert `json:"certs"`
}

type cpuMetrics struct {
	UsagePercent float64 `json:"usage_percent"`
	NumCPU       int     `json:"num_cpu"`
}

type memMetrics struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	AppAllocBytes  uint64  `json:"app_alloc_bytes"`
	AppSysBytes    uint64  `json:"app_sys_bytes"`
}

type diskMetrics struct {
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	FreeBytes    uint64  `json:"free_bytes"`
	UsagePercent float64 `json:"usage_percent"`
	AppSizeBytes uint64  `json:"app_size_bytes"`
}

type dbMetrics struct {
	SizeBytes  int64  `json:"size_bytes"`
	SizeHuman  string `json:"size_human"`
	QueryCount int64  `json:"query_count"`
	OldestLog  string `json:"oldest_log"`
}

var startTime = time.Now()

func (s *Server) getSystemMetrics(c *gin.Context) {
	metrics := systemMetrics{
		Uptime:     int64(time.Since(startTime).Seconds()),
		GoRoutines: runtime.NumGoroutine(),
	}

	metrics.CPU.NumCPU = runtime.NumCPU()
	metrics.CPU.UsagePercent = getCPUUsage()

	metrics.Memory = getMemoryMetrics()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	metrics.Memory.AppAllocBytes = m.Alloc
	metrics.Memory.AppSysBytes = m.Sys

	metrics.Disk = getDiskMetrics("/")
	metrics.Disk.AppSizeBytes = getDirSize("/app")

	metrics.Database = s.getDBMetrics()
	metrics.Certs = s.getCertAlerts()

	// Application-specific metrics
	filterDomains, filterLists := s.filter.Stats()
	metrics.App = appMetrics{
		HeapAlloc:     m.Alloc,
		HeapSys:       m.Sys,
		StackInuse:    m.StackInuse,
		TotalAlloc:    m.TotalAlloc,
		NumGC:         m.NumGC,
		Goroutines:    runtime.NumGoroutine(),
		FilterDomains: filterDomains,
		FilterLists:   filterLists,
		BlockedSvcs:   len(s.filter.ServiceBlocker().GetEnabledServiceIDs()),
	}
	if m.NumGC > 0 {
		metrics.App.LastGCPause = m.PauseNs[(m.NumGC+255)%256]
	}

	c.JSON(http.StatusOK, metrics)
}

func getCPUUsage() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	fields := strings.Fields(strings.Split(string(data), "\n")[0])
	if len(fields) < 5 {
		return 0
	}
	var user, nice, system, idle uint64
	fmt.Sscanf(fields[1], "%d", &user)
	fmt.Sscanf(fields[2], "%d", &nice)
	fmt.Sscanf(fields[3], "%d", &system)
	fmt.Sscanf(fields[4], "%d", &idle)
	total := user + nice + system + idle
	if total == 0 {
		return 0
	}
	return float64(user+nice+system) / float64(total) * 100
}

func getMemoryMetrics() memMetrics {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return memMetrics{}
	}
	var total, available, free uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var val uint64
		fmt.Sscanf(fields[1], "%d", &val)
		val *= 1024
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			available = val
		case "MemFree:":
			free = val
		}
	}
	if available == 0 {
		available = free
	}
	used := total - available
	pct := float64(0)
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return memMetrics{TotalBytes: total, UsedBytes: used, AvailableBytes: available, UsagePercent: pct}
}

func getDiskMetrics(path string) diskMetrics {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskMetrics{}
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	pct := float64(0)
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return diskMetrics{TotalBytes: total, UsedBytes: used, FreeBytes: free, UsagePercent: pct}
}

func getDirSize(path string) uint64 {
	var size uint64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		size += uint64(info.Size())
		return nil
	})
	return size
}

func (s *Server) getDBMetrics() dbMetrics {
	var metrics dbMetrics
	s.db.QueryRow("SELECT pg_database_size(current_database())").Scan(&metrics.SizeBytes)
	metrics.SizeHuman = humanBytes(metrics.SizeBytes)
	s.db.QueryRow("SELECT COUNT(*) FROM query_log").Scan(&metrics.QueryCount)
	var oldest time.Time
	if err := s.db.QueryRow("SELECT MIN(timestamp) FROM query_log").Scan(&oldest); err == nil && !oldest.IsZero() {
		metrics.OldestLog = oldest.Format(time.RFC3339)
	}
	return metrics
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (s *Server) getCertAlerts() []certAlert {
	var alerts []certAlert
	certPath := "/app/certs/server.crt"
	data, err := os.ReadFile(certPath)
	if err != nil {
		return alerts
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return alerts
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return alerts
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	alerts = append(alerts, certAlert{
		Subject:   cert.Subject.CommonName,
		ExpiresAt: cert.NotAfter.Format(time.RFC3339),
		DaysLeft:  daysLeft,
		Warning:   daysLeft < 30,
	})
	return alerts
}
