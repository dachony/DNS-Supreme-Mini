package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DNS       DNSConfig       `json:"dns"`
	Database  DatabaseConfig  `json:"database"`
	API       APIConfig       `json:"api"`
	BlockPage BlockPageConfig `json:"block_page"`
	Logging   LoggingConfig   `json:"logging"`
	DataDir   string          `json:"data_dir"`
}

type DNSConfig struct {
	ListenAddr  string   `json:"listen_addr"`
	Port        int      `json:"port"`
	Forwarders  []string `json:"forwarders"`
	CacheSize   int      `json:"cache_size"`
	CacheMinTTL int      `json:"cache_min_ttl"`
	CacheMaxTTL int      `json:"cache_max_ttl"`
}

type DatabaseConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	Password     string `json:"password"`
	DBName       string `json:"dbname"`
	SSLMode      string `json:"sslmode"`
	MaxOpenConns int    `json:"max_open_conns"`
	MaxIdleConns int    `json:"max_idle_conns"`
}

type APIConfig struct {
	ListenAddr string `json:"listen_addr"`
	Port       int    `json:"port"`
	HTTPSPort  int    `json:"https_port"`
}

type BlockPageConfig struct {
	ListenAddr string `json:"listen_addr"`
	HTTPPort   int    `json:"http_port"`
	HTTPSPort  int    `json:"https_port"`
}

type LoggingConfig struct {
	QueryLog       bool `json:"query_log"`
	RetentionDays  int  `json:"retention_days"`
	BatchSize      int  `json:"batch_size"`
	FlushIntervalS int  `json:"flush_interval_seconds"`
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

func DefaultConfig() *Config {
	return &Config{
		DNS: DNSConfig{
			ListenAddr:  "0.0.0.0",
			Port:        53,
			Forwarders:  []string{"8.8.8.8:53", "1.1.1.1:53"},
			CacheSize:   10000,
			CacheMinTTL: 10,
			CacheMaxTTL: 86400,
		},
		Database: DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			User:         "dnsupreme",
			Password:     "dnsupreme",
			DBName:       "dnsupreme",
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 5,
		},
		API: APIConfig{
			ListenAddr: "0.0.0.0",
			Port:       5380,
			HTTPSPort:  53443,
		},
		BlockPage: BlockPageConfig{
			ListenAddr: "0.0.0.0",
			HTTPPort:   80,
			HTTPSPort:  443,
		},
		Logging: LoggingConfig{
			QueryLog:       true,
			RetentionDays:  30,
			BatchSize:      100,
			FlushIntervalS: 5,
		},
		DataDir: "/data",
	}
}

func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadFromEnv() *Config {
	cfg := DefaultConfig()
	if v := os.Getenv("DNS_LISTEN_ADDR"); v != "" {
		cfg.DNS.ListenAddr = v
	}
	if v := os.Getenv("DNS_PORT"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.DNS.Port = p
		}
	}
	if v := os.Getenv("DNS_FORWARDERS"); v != "" {
		cfg.DNS.Forwarders = splitAndTrim(v, ",")
	}
	if v := os.Getenv("DB_HOST"); v != "" {
		cfg.Database.Host = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.Database.Port = p
		}
	}
	if v := os.Getenv("DB_USER"); v != "" {
		cfg.Database.User = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" {
		cfg.Database.Password = v
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		cfg.Database.DBName = v
	}
	if v := os.Getenv("DNS_CACHE_MIN_TTL"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.DNS.CacheMinTTL = p
		}
	}
	if v := os.Getenv("DNS_CACHE_MAX_TTL"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.DNS.CacheMaxTTL = p
		}
	}
	if v := os.Getenv("DB_MAX_OPEN_CONNS"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.Database.MaxOpenConns = p
		}
	}
	if v := os.Getenv("DB_MAX_IDLE_CONNS"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.Database.MaxIdleConns = p
		}
	}
	if v := os.Getenv("API_PORT"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.API.Port = p
		}
	}
	if v := os.Getenv("API_HTTPS_PORT"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.API.HTTPSPort = p
		}
	}
	if v := os.Getenv("BLOCKPAGE_HTTP_PORT"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.BlockPage.HTTPPort = p
		}
	}
	if v := os.Getenv("BLOCKPAGE_HTTPS_PORT"); v != "" {
		if p, err := parsePort(v); err == nil {
			cfg.BlockPage.HTTPSPort = p
		}
	}
	if v := os.Getenv("DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	return cfg
}

func parsePort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	return p, err
}

func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}
