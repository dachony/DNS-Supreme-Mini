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
	TotalQueries    int64            `json:"total_queries"`
	BlockedQueries  int64            `json:"blocked_queries"`
	AllowedQueries  int64            `json:"allowed_queries"`
	BlockedPercent  float64          `json:"blocked_percent"`
	TopDomains      []DomainCount    `json:"top_domains"`
	TopBlocked      []DomainCount    `json:"top_blocked"`
	TopClients      []ClientCount    `json:"top_clients"`
	QueryTypes      []QueryTypeCount `json:"query_types"`
	QueriesOverTime []TimeCount      `json:"queries_over_time"`
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
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "dns-supreme.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite supports one writer at a time
	db.SetMaxIdleConns(2)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database not ready: %w", err)
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

	slog.Info("SQLite database ready", "component", "db", "path", dbPath)
	return d, nil
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
		client_ip TEXT NOT NULL,
		client_hostname TEXT DEFAULT '',
		domain TEXT NOT NULL,
		query_type TEXT NOT NULL,
		blocked INTEGER NOT NULL DEFAULT 0,
		block_rule TEXT DEFAULT '',
		response_ip TEXT DEFAULT '',
		latency_ms REAL DEFAULT 0,
		upstream TEXT DEFAULT '',
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
		category TEXT DEFAULT 'uncategorized',
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
		recovery_codes TEXT DEFAULT '',
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
	`
	_, err := d.db.Exec(schema)
	return err
}

func (d *Database) startRetentionCleanup() {
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
		blocked := 0
		if e.Blocked {
			blocked = 1
		}
		_, err := stmt.Exec(e.Timestamp.Format(time.RFC3339), e.ClientIP, e.ClientHostname, e.Domain, e.QueryType, blocked, e.BlockRule, e.ResponseIP, e.LatencyMs, e.Upstream, e.Protocol)
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
		blockedInt := 0
		if *blocked {
			blockedInt = 1
		}
		where += " AND blocked = ?"
		args = append(args, blockedInt)
	}

	var total int64
	countQuery := "SELECT COUNT(*) FROM query_log " + where
	d.db.QueryRow(countQuery, args...).Scan(&total)

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
		var ts string
		var blockedInt int
		err := rows.Scan(&l.ID, &ts, &l.ClientIP, &l.ClientHostname, &l.Domain, &l.QueryType, &blockedInt, &l.BlockRule, &l.ResponseIP, &l.LatencyMs, &l.Upstream, &l.Protocol)
		if err != nil {
			continue
		}
		l.Timestamp, _ = time.Parse(time.RFC3339, ts)
		l.Blocked = blockedInt != 0
		logs = append(logs, l)
	}

	return logs, total, nil
}

func (d *Database) GetStats(hours int) (*Stats, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)
	stats := &Stats{}

	d.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE timestamp > ?", since).Scan(&stats.TotalQueries)
	d.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE timestamp > ? AND blocked = 1", since).Scan(&stats.BlockedQueries)
	stats.AllowedQueries = stats.TotalQueries - stats.BlockedQueries
	if stats.TotalQueries > 0 {
		stats.BlockedPercent = float64(stats.BlockedQueries) / float64(stats.TotalQueries) * 100
	}

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
			SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
		FROM query_log
		WHERE timestamp > ?
		GROUP BY hour
		ORDER BY hour
	`, since)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var tc TimeCount
			var ts string
			rows3.Scan(&ts, &tc.Total, &tc.Blocked)
			tc.Time, _ = time.Parse(time.RFC3339, ts)
			stats.QueriesOverTime = append(stats.QueriesOverTime, tc)
		}
	}

	return stats, nil
}

func (d *Database) topDomains(since string, blocked bool, limit int) []DomainCount {
	blockedInt := 0
	if blocked {
		blockedInt = 1
	}
	rows, err := d.db.Query("SELECT domain, COUNT(*) as cnt FROM query_log WHERE timestamp > ? AND blocked = ? GROUP BY domain ORDER BY cnt DESC LIMIT ?", since, blockedInt, limit)
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

func (d *Database) Ping() error {
	return d.db.Ping()
}

func (d *Database) Close() {
	d.flush()
	d.db.Close()
}

// LogAudit records an audit log entry
func (d *Database) LogAudit(userID int, username, action, detail, clientIP string) {
	d.db.Exec("INSERT INTO audit_log (user_id, username, action, detail, client_ip) VALUES (?, ?, ?, ?, ?)",
		userID, username, action, detail, clientIP)
}

func (d *Database) GetAuditLogs(limit, offset int) ([]map[string]interface{}, int64, error) {
	var total int64
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total)

	rows, err := d.db.Query("SELECT id, timestamp, COALESCE(user_id,0), COALESCE(username,''), action, COALESCE(detail,''), COALESCE(client_ip,'') FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int64
		var ts, username, action, detail, clientIP string
		var userID int
		rows.Scan(&id, &ts, &userID, &username, &action, &detail, &clientIP)
		entries = append(entries, map[string]interface{}{
			"id":        id,
			"timestamp": ts,
			"user_id":   userID,
			"username":  username,
			"action":    action,
			"detail":    detail,
			"client_ip": clientIP,
		})
	}
	return entries, total, nil
}
