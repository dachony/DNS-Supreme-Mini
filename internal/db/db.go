package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dns-supreme-mini/internal/config"
	_ "modernc.org/sqlite"
)

type QueryLog struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ClientIP       string    `json:"client_ip"`
	ClientHostname string    `json:"client_hostname,omitempty"`
	Domain         string    `json:"domain"`
	QueryType      string    `json:"query_type"`
	Blocked        bool      `json:"blocked"`
	BlockRule      string    `json:"block_rule,omitempty"`
	ResponseIP     string    `json:"response_ip,omitempty"`
	LatencyMs      float64   `json:"latency_ms"`
	Upstream       string    `json:"upstream,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
}

type Stats struct {
	TotalQueries   int64            `json:"total_queries"`
	BlockedQueries int64            `json:"blocked_queries"`
	AllowedQueries int64            `json:"allowed_queries"`
	BlockedPercent float64          `json:"blocked_percent"`
	TopDomains     []DomainCount    `json:"top_domains"`
	TopBlocked     []DomainCount    `json:"top_blocked"`
	TopClients     []ClientCount    `json:"top_clients"`
	QueryTypes     []QueryTypeCount `json:"query_types"`
	QueriesOverTime []TimeCount     `json:"queries_over_time"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type ClientCount struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

type QueryTypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

type TimeCount struct {
	Time    time.Time `json:"time"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

type Database struct {
	db        *sql.DB
	cfg       config.LoggingConfig
	buffer    []QueryLog
	mu        sync.Mutex
	flushChan chan struct{}
}

func New(dataDir string, logCfg config.LoggingConfig) (*Database, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "dns-supreme.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database not ready: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	d := &Database{
		db:        db,
		cfg:       logCfg,
		buffer:    make([]QueryLog, 0, logCfg.BatchSize),
		flushChan: make(chan struct{}, 1),
	}

	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	go d.flushLoop()
	d.startRetentionCleanup()
	d.startAggregation()

	slog.Info("connected to SQLite", "component", "db", "path", dbPath)
	return d, nil
}

func (d *Database) startRetentionCleanup() {
	// Run immediately on startup, then every hour
	d.cleanOldLogs()
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			d.cleanOldLogs()
		}
	}()
}

func (d *Database) cleanOldLogs() {
	if d.cfg.RetentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -d.cfg.RetentionDays).Format(time.RFC3339)
	result, err := d.db.Exec("DELETE FROM query_log WHERE timestamp < ?", cutoff)
	if err != nil {
		slog.Error("retention cleanup error", "component", "db", "error", err)
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		slog.Info("retention cleanup completed", "component", "db", "deleted_rows", rows, "retention_days", d.cfg.RetentionDays)
	}
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		query_type TEXT NOT NULL,
		blocked INTEGER NOT NULL DEFAULT 0,
		block_rule TEXT,
		response_ip TEXT,
		latency_ms REAL,
		upstream TEXT,
		protocol TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log (timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log (domain);
	CREATE INDEX IF NOT EXISTS idx_query_log_client_ip ON query_log (client_ip);
	CREATE INDEX IF NOT EXISTS idx_query_log_blocked ON query_log (blocked);

	CREATE TABLE IF NOT EXISTS blocklists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		url TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		domain_count INTEGER NOT NULL DEFAULT 0,
		last_updated DATETIME,
		created_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		first_name TEXT NOT NULL DEFAULT '',
		last_name TEXT NOT NULL DEFAULT '',
		email TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL DEFAULT 'viewer',
		mfa_enabled INTEGER NOT NULL DEFAULT 0,
		mfa_type TEXT NOT NULL DEFAULT '',
		mfa_secret TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
		last_login DATETIME
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
		user_id INTEGER,
		username TEXT,
		action TEXT NOT NULL,
		detail TEXT,
		client_ip TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);

	CREATE TABLE IF NOT EXISTS query_log_hourly (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hour DATETIME NOT NULL,
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		query_type TEXT NOT NULL,
		blocked INTEGER NOT NULL DEFAULT 0,
		count INTEGER NOT NULL DEFAULT 1,
		UNIQUE(hour, client_ip, domain, query_type, blocked)
	);
	CREATE INDEX IF NOT EXISTS idx_query_log_hourly_hour ON query_log_hourly (hour DESC);
	`
	_, err := d.db.Exec(schema)
	if err != nil {
		return err
	}
	// Add columns if missing (for upgrades) - SQLite doesn't support IF NOT EXISTS for columns
	d.db.Exec("ALTER TABLE query_log ADD COLUMN protocol TEXT DEFAULT ''")
	d.db.Exec("ALTER TABLE query_log ADD COLUMN client_hostname TEXT DEFAULT ''")
	d.db.Exec("ALTER TABLE users ADD COLUMN recovery_codes TEXT DEFAULT ''")
	d.db.Exec(`CREATE TABLE IF NOT EXISTS password_resets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token TEXT NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		used INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT (datetime('now'))
	)`)
	return d.migrateZones()
}

func (d *Database) startAggregation() {
	// Run every hour
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		// Initial delay to not conflict with startup
		time.Sleep(5 * time.Minute)
		d.aggregateOldLogs()
		for range ticker.C {
			d.aggregateOldLogs()
		}
	}()
}

func (d *Database) aggregateOldLogs() {
	// Aggregate logs older than 24 hours into hourly summaries
	cutoff := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	_, err := d.db.Exec(`
		INSERT INTO query_log_hourly (hour, client_ip, domain, query_type, blocked, count)
		SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
		       client_ip, domain, query_type, blocked,
		       COUNT(*) as count
		FROM query_log
		WHERE timestamp < ?
		GROUP BY hour, client_ip, domain, query_type, blocked
		ON CONFLICT (hour, client_ip, domain, query_type, blocked)
		DO UPDATE SET count = query_log_hourly.count + excluded.count
	`, cutoff)
	if err != nil {
		slog.Error("aggregation insert error", "component", "db", "error", err)
		return
	}

	// Delete aggregated detailed rows
	result, err := d.db.Exec("DELETE FROM query_log WHERE timestamp < ?", cutoff)
	if err != nil {
		slog.Error("aggregation cleanup error", "component", "db", "error", err)
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		slog.Info("aggregated and removed old log entries", "component", "db", "deleted_rows", rows, "older_than", "24h")
	}
}

func (d *Database) LogQuery(entry QueryLog) {
	d.mu.Lock()
	d.buffer = append(d.buffer, entry)
	shouldFlush := len(d.buffer) >= d.cfg.BatchSize
	d.mu.Unlock()

	if shouldFlush {
		select {
		case d.flushChan <- struct{}{}:
		default:
		}
	}
}

func (d *Database) flushLoop() {
	ticker := time.NewTicker(time.Duration(d.cfg.FlushIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.flush()
		case <-d.flushChan:
			d.flush()
		}
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (d *Database) flush() {
	d.mu.Lock()
	if len(d.buffer) == 0 {
		d.mu.Unlock()
		return
	}
	entries := d.buffer
	d.buffer = make([]QueryLog, 0, d.cfg.BatchSize)
	d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		slog.Error("failed to begin transaction", "component", "db", "error", err)
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO query_log (timestamp, client_ip, client_hostname, domain, query_type, blocked, block_rule, response_ip, latency_ms, upstream, protocol)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		slog.Error("failed to prepare statement", "component", "db", "error", err)
		return
	}
	defer stmt.Close()

	for _, e := range entries {
		_, err := stmt.Exec(e.Timestamp.Format(time.RFC3339), e.ClientIP, e.ClientHostname, e.Domain, e.QueryType, boolToInt(e.Blocked), e.BlockRule, e.ResponseIP, e.LatencyMs, e.Upstream, e.Protocol)
		if err != nil {
			slog.Error("failed to insert query log", "component", "db", "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit transaction", "component", "db", "error", err)
	}
}

func (d *Database) GetQueryLogs(limit, offset int, domain, clientIP string, blocked *bool) ([]QueryLog, int64, error) {
	where := "WHERE 1=1"
	args := make([]interface{}, 0)

	if domain != "" {
		where += " AND domain LIKE ?"
		args = append(args, "%"+domain+"%")
	}
	if clientIP != "" {
		where += " AND client_ip LIKE ?"
		args = append(args, clientIP+"%")
	}
	if blocked != nil {
		where += " AND blocked = ?"
		args = append(args, boolToInt(*blocked))
	}

	// Count
	var total int64
	countQuery := "SELECT COUNT(*) FROM query_log " + where
	d.db.QueryRow(countQuery, args...).Scan(&total)

	// Fetch
	query := fmt.Sprintf("SELECT id, timestamp, client_ip, COALESCE(client_hostname,''), domain, query_type, blocked, COALESCE(block_rule,''), COALESCE(response_ip,''), COALESCE(latency_ms,0), COALESCE(upstream,''), COALESCE(protocol,'') FROM query_log %s ORDER BY timestamp DESC LIMIT ? OFFSET ?", where)
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]QueryLog, 0)
	for rows.Next() {
		var l QueryLog
		var tsStr string
		var blockedInt int
		err := rows.Scan(&l.ID, &tsStr, &l.ClientIP, &l.ClientHostname, &l.Domain, &l.QueryType, &blockedInt, &l.BlockRule, &l.ResponseIP, &l.LatencyMs, &l.Upstream, &l.Protocol)
		if err != nil {
			continue
		}
		l.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		l.Blocked = blockedInt != 0
		logs = append(logs, l)
	}

	return logs, total, nil
}

func (d *Database) GetStats(hours int) (*Stats, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
	stats := &Stats{}

	// Total and blocked counts
	d.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE timestamp > ?", since).Scan(&stats.TotalQueries)
	d.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE timestamp > ? AND blocked = 1", since).Scan(&stats.BlockedQueries)
	stats.AllowedQueries = stats.TotalQueries - stats.BlockedQueries
	if stats.TotalQueries > 0 {
		stats.BlockedPercent = float64(stats.BlockedQueries) / float64(stats.TotalQueries) * 100
	}

	// Top domains
	stats.TopDomains = d.topDomains(since, false, 10)
	stats.TopBlocked = d.topDomains(since, true, 10)

	// Top clients
	rows, err := d.db.Query("SELECT client_ip, COUNT(*) as cnt FROM query_log WHERE timestamp > ? GROUP BY client_ip ORDER BY cnt DESC LIMIT 10", since)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c ClientCount
			rows.Scan(&c.ClientIP, &c.Count)
			stats.TopClients = append(stats.TopClients, c)
		}
	}

	// Query types
	rows2, err := d.db.Query("SELECT query_type, COUNT(*) as cnt FROM query_log WHERE timestamp > ? GROUP BY query_type ORDER BY cnt DESC", since)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var qt QueryTypeCount
			rows2.Scan(&qt.Type, &qt.Count)
			stats.QueryTypes = append(stats.QueryTypes, qt)
		}
	}

	// Queries over time (hourly buckets)
	rows3, err := d.db.Query(`
		SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) as hour,
			COUNT(*) as total,
			SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
		FROM query_log
		WHERE timestamp > ?
		GROUP BY hour
		ORDER BY hour
	`, since)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var tc TimeCount
			var hourStr string
			rows3.Scan(&hourStr, &tc.Total, &tc.Blocked)
			tc.Time, _ = time.Parse(time.RFC3339, hourStr)
			stats.QueriesOverTime = append(stats.QueriesOverTime, tc)
		}
	}

	return stats, nil
}

func (d *Database) topDomains(since string, blocked bool, limit int) []DomainCount {
	query := "SELECT domain, COUNT(*) as cnt FROM query_log WHERE timestamp > ? AND blocked = ? GROUP BY domain ORDER BY cnt DESC LIMIT ?"
	rows, err := d.db.Query(query, since, boolToInt(blocked), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make([]DomainCount, 0)
	for rows.Next() {
		var dc DomainCount
		rows.Scan(&dc.Domain, &dc.Count)
		result = append(result, dc)
	}
	return result
}

func (d *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.db.QueryRow(query, args...)
}

func (d *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

func (d *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

func (d *Database) Ping() error {
	return d.db.Ping()
}

func (d *Database) Close() {
	d.flush()
	d.db.Close()
}
