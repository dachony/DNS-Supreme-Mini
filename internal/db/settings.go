package db

import "database/sql"

// GetSetting retrieves a setting value by key. Returns empty string if not found.
func (d *Database) GetSetting(key string) string {
	var value string
	err := d.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err != nil {
		return ""
	}
	return value
}

// SetSetting saves or updates a setting value.
func (d *Database) SetSetting(key, value string) error {
	_, err := d.db.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
	`, key, value)
	return err
}

// GetSettings retrieves all settings as a map.
func (d *Database) GetSettings() map[string]string {
	rows, err := d.db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			result[k] = v
		}
	}
	return result
}

// DeleteSetting removes a setting.
func (d *Database) DeleteSetting(key string) error {
	_, err := d.db.Exec("DELETE FROM settings WHERE key = ?", key)
	return err
}

// --- Blocklist persistence ---

type BlocklistRecord struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Category    string `json:"category"`
	Enabled     bool   `json:"enabled"`
	DomainCount int    `json:"domain_count"`
}

func (d *Database) SaveBlocklist(name, url, category string, count int) error {
	_, err := d.db.Exec(`
		INSERT INTO blocklists (name, url, enabled, domain_count, last_updated)
		VALUES (?, ?, 1, ?, datetime('now'))
		ON CONFLICT(name) DO UPDATE SET url = excluded.url, domain_count = excluded.domain_count, last_updated = datetime('now')
	`, name, url, count)
	return err
}

func (d *Database) RemoveBlocklist(name string) error {
	_, err := d.db.Exec("DELETE FROM blocklists WHERE name = ?", name)
	return err
}

func (d *Database) GetBlocklists() ([]BlocklistRecord, error) {
	rows, err := d.db.Query("SELECT id, name, url, COALESCE(domain_count, 0) FROM blocklists WHERE enabled = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []BlocklistRecord
	for rows.Next() {
		var r BlocklistRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.URL, &r.DomainCount); err == nil {
			r.Enabled = true
			result = append(result, r)
		}
	}
	return result, nil
}

// MigrateBlocklists adds the category column if it doesn't exist
func (d *Database) MigrateBlocklists() {
	// SQLite doesn't support IF NOT EXISTS for columns - just try and ignore errors
	d.db.Exec("ALTER TABLE blocklists ADD COLUMN category TEXT DEFAULT 'uncategorized'")
	_, _ = d.db.Exec("SELECT 1") // no-op, just ensure connection
}

func (d *Database) SaveBlocklistWithCategory(name, url, category string, count int) error {
	_, err := d.db.Exec(`
		INSERT INTO blocklists (name, url, domain_count, last_updated, category)
		VALUES (?, ?, ?, datetime('now'), ?)
		ON CONFLICT(name) DO UPDATE SET url = excluded.url, domain_count = excluded.domain_count, last_updated = datetime('now'), category = excluded.category
	`, name, url, count, category)
	_ = err // ignore if category column doesn't exist, fallback to SaveBlocklist
	if err != nil {
		return d.SaveBlocklist(name, url, category, count)
	}
	return nil
}

func (d *Database) GetBlocklistsFull() ([]BlocklistRecord, error) {
	d.MigrateBlocklists()
	rows, err := d.db.Query("SELECT id, name, url, COALESCE(domain_count, 0), COALESCE(category, 'uncategorized') FROM blocklists WHERE enabled = 1 ORDER BY name")
	if err != nil {
		// Fallback without category
		return d.GetBlocklists()
	}
	defer rows.Close()

	var result []BlocklistRecord
	for rows.Next() {
		var r BlocklistRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.URL, &r.DomainCount, &r.Category); err == nil {
			r.Enabled = true
			result = append(result, r)
		}
	}
	return result, rows.Err()
}

// --- Helper for checking if row exists ---
func (d *Database) SettingExists(key string) bool {
	var count int
	d.db.QueryRow("SELECT COUNT(1) FROM settings WHERE key = ?", key).Scan(&count)
	return count > 0
}

// --- Batch save settings ---
func (d *Database) SaveSettings(settings map[string]string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for k, v := range settings {
		if _, err := stmt.Exec(k, v); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// GetAdminEmails returns email addresses of all admin users
func (d *Database) GetAdminEmails() ([]string, error) {
	rows, err := d.db.Query("SELECT email FROM users WHERE role = 'admin' AND email != '' AND email IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var emails []string
	for rows.Next() {
		var email string
		if rows.Scan(&email) == nil && email != "" {
			emails = append(emails, email)
		}
	}
	return emails, nil
}

// ACME DNS challenge records (temporary TXT records)
func (d *Database) CreateACMERecord(fqdn, value string) error {
	// Store as a setting with acme_ prefix
	return d.SetSetting("acme_txt_"+fqdn, value)
}

func (d *Database) DeleteACMERecord(fqdn string) error {
	return d.DeleteSetting("acme_txt_" + fqdn)
}

// UserCount returns total user count
func (d *Database) UserCountCheck() int {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count
}

// Needed for settings.go but may already exist
func (d *Database) ExecRaw(query string, args ...any) (sql.Result, error) {
	return d.db.Exec(query, args...)
}
