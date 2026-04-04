package api

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (s *Server) prometheusMetrics(c *gin.Context) {
	var b strings.Builder

	// dns_queries_total
	var totalQueries int64
	s.db.QueryRow("SELECT COUNT(*) FROM query_log").Scan(&totalQueries)
	b.WriteString("# HELP dns_queries_total Total DNS queries processed\n")
	b.WriteString("# TYPE dns_queries_total counter\n")
	b.WriteString(fmt.Sprintf("dns_queries_total %d\n", totalQueries))

	// dns_queries_blocked_total
	var blockedQueries int64
	s.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE blocked = true").Scan(&blockedQueries)
	b.WriteString("# HELP dns_queries_blocked_total Total DNS queries blocked\n")
	b.WriteString("# TYPE dns_queries_blocked_total counter\n")
	b.WriteString(fmt.Sprintf("dns_queries_blocked_total %d\n", blockedQueries))

	// dns_cache_size
	cacheSize := 0
	if s.dns != nil {
		cacheSize = s.dns.CacheSize()
	}
	b.WriteString("# HELP dns_cache_size Current number of entries in the DNS cache\n")
	b.WriteString("# TYPE dns_cache_size gauge\n")
	b.WriteString(fmt.Sprintf("dns_cache_size %d\n", cacheSize))

	// dns_goroutines
	b.WriteString("# HELP dns_goroutines Current number of goroutines\n")
	b.WriteString("# TYPE dns_goroutines gauge\n")
	b.WriteString(fmt.Sprintf("dns_goroutines %d\n", runtime.NumGoroutine()))

	// dns_uptime_seconds
	uptime := time.Since(startTime).Seconds()
	b.WriteString("# HELP dns_uptime_seconds Time since server start in seconds\n")
	b.WriteString("# TYPE dns_uptime_seconds gauge\n")
	b.WriteString(fmt.Sprintf("dns_uptime_seconds %.0f\n", uptime))

	// dns_memory_alloc_bytes
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b.WriteString("# HELP dns_memory_alloc_bytes Bytes of allocated heap objects\n")
	b.WriteString("# TYPE dns_memory_alloc_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dns_memory_alloc_bytes %d\n", m.Alloc))

	// dns_memory_sys_bytes
	b.WriteString("# HELP dns_memory_sys_bytes Total bytes of memory obtained from the OS\n")
	b.WriteString("# TYPE dns_memory_sys_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dns_memory_sys_bytes %d\n", m.Sys))

	// dns_database_size_bytes
	var dbSize int64
	// SQLite: get page_count * page_size
	s.db.QueryRow("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&dbSize)
	b.WriteString("# HELP dns_database_size_bytes Size of the SQLite database in bytes\n")
	b.WriteString("# TYPE dns_database_size_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dns_database_size_bytes %d\n", dbSize))

	// process_cpu_count
	b.WriteString("# HELP process_cpu_count Number of available CPU cores\n")
	b.WriteString("# TYPE process_cpu_count gauge\n")
	b.WriteString(fmt.Sprintf("process_cpu_count %d\n", runtime.NumCPU()))

	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}
