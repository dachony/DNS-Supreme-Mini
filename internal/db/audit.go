package db

import "time"

type AuditEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
}

func (d *Database) LogAudit(userID int, username, action, detail, clientIP string) {
	d.db.Exec(
		"INSERT INTO audit_log (user_id, username, action, detail, client_ip) VALUES (?, ?, ?, ?, ?)",
		userID, username, action, detail, clientIP,
	)
}

func (d *Database) GetAuditLogs(limit, offset int) ([]AuditEntry, int64, error) {
	var total int64
	d.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total)

	rows, err := d.db.Query(
		"SELECT id, timestamp, COALESCE(user_id,0), COALESCE(username,''), action, COALESCE(detail,''), COALESCE(client_ip,'') FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var tsStr string
		if rows.Scan(&e.ID, &tsStr, &e.UserID, &e.Username, &e.Action, &e.Detail, &e.ClientIP) == nil {
			e.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
			entries = append(entries, e)
		}
	}
	return entries, total, nil
}
