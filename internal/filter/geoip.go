package filter

import (
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIPReader wraps a MaxMind DB reader for country lookups
type GeoIPReader struct {
	db   *maxminddb.Reader
	path string
}

type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// NewGeoIPReader loads or downloads a GeoIP database
// Tries in order:
// 1. Provided path (env GEOIP_DB_PATH)
// 2. Default path /app/data/geoip.mmdb
// 3. Auto-download from DB-IP (free, no registration)
func NewGeoIPReader(dataDir string) (*GeoIPReader, error) {
	if dataDir == "" {
		dataDir = "/app/data"
	}
	dbPath := filepath.Join(dataDir, "geoip.mmdb")

	// Check env override
	if envPath := os.Getenv("GEOIP_DB_PATH"); envPath != "" {
		dbPath = envPath
	}

	// Try to load existing file
	if _, err := os.Stat(dbPath); err == nil {
		return openDB(dbPath)
	}

	// Auto-download from DB-IP (free, MMDB format, no key needed)
	slog.Info("database not found, downloading from DB-IP", "component", "geoip")
	if err := downloadDBIP(dbPath); err != nil {
		return nil, fmt.Errorf("failed to download GeoIP database: %w", err)
	}

	return openDB(dbPath)
}

func openDB(path string) (*GeoIPReader, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoIP database %s: %w", path, err)
	}
	slog.Info("loaded GeoIP database", "component", "geoip", "path", path, "type", db.Metadata.DatabaseType)
	return &GeoIPReader{db: db, path: path}, nil
}

// Lookup returns the ISO country code for an IP address
func (g *GeoIPReader) Lookup(ip net.IP) string {
	if g == nil || g.db == nil {
		return ""
	}
	var record geoRecord
	if err := g.db.Lookup(ip, &record); err != nil {
		return ""
	}
	return record.Country.ISOCode
}

// Close closes the database
func (g *GeoIPReader) Close() {
	if g != nil && g.db != nil {
		g.db.Close()
	}
}

// downloadDBIP downloads the free DB-IP country database
func downloadDBIP(destPath string) error {
	// DB-IP provides free monthly MMDB databases
	// URL format: https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
	now := time.Now()
	url := fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb.gz",
		now.Year(), now.Month())

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try previous month if current not available yet
		prev := now.AddDate(0, -1, 0)
		url = fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb.gz",
			prev.Year(), prev.Month())
		resp.Body.Close()
		resp, err = client.Get(url)
		if err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
		}
	}

	// Decompress gzip
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip decompress failed: %w", err)
	}
	defer gz.Close()

	// Write to file
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, gz)
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("write failed: %w", err)
	}

	slog.Info("downloaded DB-IP database", "component", "geoip", "path", destPath, "size_mb", fmt.Sprintf("%.1f", float64(written)/1024/1024))
	return nil
}
