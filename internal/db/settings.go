package db

type BlocklistRecord struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Category    string `json:"category"`
	Enabled     bool   `json:"enabled"`
	DomainCount int    `json:"domain_count"`
}

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
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
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

// SaveSettings batch saves settings.
func (d *Database) SaveSettings(settings map[string]string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
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

// --- Blocklist persistence ---

func (d *Database) SaveBlocklist(name, url, category string, count int) error {
	_, err := d.db.Exec(`
		INSERT INTO blocklists (name, url, category, domain_count, last_updated)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(name) DO UPDATE SET url = excluded.url, category = excluded.category, domain_count = excluded.domain_count, last_updated = datetime('now')
	`, name, url, category, count)
	return err
}

func (d *Database) RemoveBlocklist(name string) error {
	_, err := d.db.Exec("DELETE FROM blocklists WHERE name = ?", name)
	return err
}

func (d *Database) GetBlocklists() ([]BlocklistRecord, error) {
	rows, err := d.db.Query("SELECT id, name, url, COALESCE(category, 'uncategorized'), COALESCE(domain_count, 0) FROM blocklists WHERE enabled = 1 ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []BlocklistRecord
	for rows.Next() {
		var r BlocklistRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.URL, &r.Category, &r.DomainCount); err == nil {
			r.Enabled = true
			result = append(result, r)
		}
	}
	return result, rows.Err()
}

// UserCountCheck returns total user count
func (d *Database) UserCountCheck() int {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count
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
