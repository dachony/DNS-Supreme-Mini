package db

import (
	"fmt"
	"strings"
	"time"
)

type Zone struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // primary, secondary
	SOASerial uint32    `json:"soa_serial"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DNSRecord struct {
	ID       int       `json:"id"`
	ZoneID   int       `json:"zone_id"`
	Name     string    `json:"name"`
	Type     string    `json:"type"` // A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, CAA
	Value    string    `json:"value"`
	TTL      int       `json:"ttl"`
	Priority int       `json:"priority,omitempty"` // for MX, SRV
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (d *Database) migrateZones() error {
	schema := `
	CREATE TABLE IF NOT EXISTS zones (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL DEFAULT 'primary',
		soa_serial INTEGER NOT NULL DEFAULT 1,
		ttl INTEGER NOT NULL DEFAULT 3600,
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS dns_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 3600,
		priority INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_dns_records_zone ON dns_records (zone_id);
	CREATE INDEX IF NOT EXISTS idx_dns_records_name_type ON dns_records (name, type);
	`
	_, err := d.db.Exec(schema)
	return err
}

// --- Zones CRUD ---

func (d *Database) CreateZone(z *Zone) error {
	now := time.Now().Format(time.RFC3339)
	result, err := d.db.Exec(`
		INSERT INTO zones (name, type, ttl, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
	`, z.Name, z.Type, z.TTL, now, now)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	z.ID = int(id)
	z.SOASerial = 1
	z.CreatedAt, _ = time.Parse(time.RFC3339, now)
	z.UpdatedAt = z.CreatedAt
	return nil
}

func (d *Database) ListZones() ([]Zone, error) {
	rows, err := d.db.Query(`SELECT id, name, type, soa_serial, ttl, created_at, updated_at FROM zones ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	zones := make([]Zone, 0)
	for rows.Next() {
		var z Zone
		var createdStr, updatedStr string
		rows.Scan(&z.ID, &z.Name, &z.Type, &z.SOASerial, &z.TTL, &createdStr, &updatedStr)
		z.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		z.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
		zones = append(zones, z)
	}
	return zones, nil
}

func (d *Database) GetZone(id int) (*Zone, error) {
	z := &Zone{}
	var createdStr, updatedStr string
	err := d.db.QueryRow(`SELECT id, name, type, soa_serial, ttl, created_at, updated_at FROM zones WHERE id=?`, id).
		Scan(&z.ID, &z.Name, &z.Type, &z.SOASerial, &z.TTL, &createdStr, &updatedStr)
	if err != nil {
		return nil, err
	}
	z.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	z.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	return z, nil
}

func (d *Database) GetZoneByName(name string) (*Zone, error) {
	z := &Zone{}
	var createdStr, updatedStr string
	err := d.db.QueryRow(`SELECT id, name, type, soa_serial, ttl, created_at, updated_at FROM zones WHERE name=?`, name).
		Scan(&z.ID, &z.Name, &z.Type, &z.SOASerial, &z.TTL, &createdStr, &updatedStr)
	if err != nil {
		return nil, err
	}
	z.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	z.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	return z, nil
}

func (d *Database) DeleteZone(id int) error {
	result, err := d.db.Exec(`DELETE FROM zones WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("zone not found")
	}
	return nil
}

func (d *Database) IncrementSOA(zoneID int) error {
	_, err := d.db.Exec(`UPDATE zones SET soa_serial = soa_serial + 1, updated_at = datetime('now') WHERE id=?`, zoneID)
	return err
}

// --- Records CRUD ---

func (d *Database) CreateRecord(r *DNSRecord) error {
	now := time.Now().Format(time.RFC3339)
	result, err := d.db.Exec(`
		INSERT INTO dns_records (zone_id, name, type, value, ttl, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, r.ZoneID, r.Name, r.Type, r.Value, r.TTL, r.Priority, now, now)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	r.ID = int(id)
	r.CreatedAt, _ = time.Parse(time.RFC3339, now)
	r.UpdatedAt = r.CreatedAt
	d.IncrementSOA(r.ZoneID)
	return nil
}

func (d *Database) ListRecords(zoneID int) ([]DNSRecord, error) {
	rows, err := d.db.Query(`
		SELECT id, zone_id, name, type, value, ttl, priority, created_at, updated_at
		FROM dns_records WHERE zone_id=? ORDER BY name, type
	`, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]DNSRecord, 0)
	for rows.Next() {
		var r DNSRecord
		var createdStr, updatedStr string
		rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority, &createdStr, &updatedStr)
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
		records = append(records, r)
	}
	return records, nil
}

func (d *Database) UpdateRecord(r *DNSRecord) error {
	_, err := d.db.Exec(`
		UPDATE dns_records SET name=?, type=?, value=?, ttl=?, priority=?, updated_at=datetime('now')
		WHERE id=?
	`, r.Name, r.Type, r.Value, r.TTL, r.Priority, r.ID)
	if err == nil {
		d.IncrementSOA(r.ZoneID)
	}
	return err
}

func (d *Database) DeleteRecord(id, zoneID int) error {
	result, err := d.db.Exec(`DELETE FROM dns_records WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("record not found")
	}
	d.IncrementSOA(zoneID)
	return nil
}

// FindRecords looks up records matching a fully-qualified name and type.
// It splits "www.example.com" into record name "www" and zone "example.com",
// trying all possible splits.
func (d *Database) FindRecords(name, rtype string) ([]DNSRecord, error) {
	parts := strings.Split(name, ".")

	// Try each possible split: www.example.com -> record="www", zone="example.com"
	// Also try: record="@", zone="example.com" for apex queries
	for i := 1; i < len(parts); i++ {
		recName := strings.Join(parts[:i], ".")
		zoneName := strings.Join(parts[i:], ".")

		records, err := d.findRecordsInZone(zoneName, recName, rtype)
		if err == nil && len(records) > 0 {
			return records, nil
		}
	}

	// Try apex match: name = "@", zone = full name
	records, err := d.findRecordsInZone(name, "@", rtype)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	return nil, nil
}

func (d *Database) findRecordsInZone(zoneName, recName, rtype string) ([]DNSRecord, error) {
	rows, err := d.db.Query(`
		SELECT r.id, r.zone_id, r.name, r.type, r.value, r.ttl, r.priority, r.created_at, r.updated_at
		FROM dns_records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ? AND r.name = ? AND r.type = ?
	`, zoneName, recName, rtype)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]DNSRecord, 0)
	for rows.Next() {
		var r DNSRecord
		var createdStr, updatedStr string
		rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority, &createdStr, &updatedStr)
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
		records = append(records, r)
	}
	return records, nil
}
