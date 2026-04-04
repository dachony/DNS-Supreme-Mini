package main

import (
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"encoding/json"

	"dns-supreme-mini/internal/api"
	"dns-supreme-mini/internal/blockpage"
	"dns-supreme-mini/internal/certs"
	"dns-supreme-mini/internal/config"
	"dns-supreme-mini/internal/db"
	dnsserver "dns-supreme-mini/internal/dns"
	"dns-supreme-mini/internal/filter"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info("DNS-Supreme Mini starting", "version", "2.0.0-mini")

	cfg := config.LoadFromEnv()

	// Try loading config file
	if cfgFile := os.Getenv("CONFIG_FILE"); cfgFile != "" {
		if fileCfg, err := config.LoadFromFile(cfgFile); err == nil {
			cfg = fileCfg
		}
	} else if _, err := os.Stat("/app/configs/default.json"); err == nil {
		if fileCfg, err := config.LoadFromFile("/app/configs/default.json"); err == nil {
			cfg = fileCfg
		}
	}

	// Initialize SQLite database
	database, err := db.New(cfg.DataDir, cfg.Logging)
	if err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	// Initialize filter engine
	filterEngine := filter.NewEngine()

	// Load persisted blocklists from database, fallback to defaults
	loadPersistedBlocklists(database, filterEngine)
	loadPersistedFilterSettings(database, filterEngine)

	// Initialize network protection engine
	netProtect := filter.NewNetProtectEngine()

	// Initialize GeoIP for country blocking
	geoReader, err := filter.NewGeoIPReader("/app/data")
	if err != nil {
		slog.Warn("GeoIP not available", "component", "geoip", "error", err)
		slog.Info("country blocking disabled, set GEOIP_DB_PATH or ensure network access for auto-download", "component", "geoip")
	} else {
		netProtect.SetGeoLookup(geoReader.Lookup)
		defer geoReader.Close()
		slog.Info("country blocking available", "component", "geoip")
	}

	// Load persisted network protection settings
	loadPersistedNpSettings(database, netProtect)

	netProtect.Start()

	// Initialize TLS
	certsDir := cfg.DataDir + "/certs"
	os.MkdirAll(certsDir, 0755)
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile == "" {
		certFile = certsDir + "/server.crt"
		keyFile = certsDir + "/server.key"
	}
	// Auto-generate self-signed cert on disk if none exists
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		slog.Info("generating self-signed certificate to disk", "component", "tls", "path", certFile)
		certs.GenerateAndSave(certFile, keyFile, nil)
	}
	tlsConfig, err := certs.LoadOrGenerateTLS(certFile, keyFile)
	if err != nil {
		slog.Warn("TLS not available", "component", "tls", "error", err)
		tlsConfig = nil
	}

	// Create log function
	logFn := func(result *dnsserver.QueryResult) {
		if !cfg.Logging.QueryLog {
			return
		}
		database.LogQuery(db.QueryLog{
			Timestamp:      result.Timestamp,
			ClientIP:       result.ClientIP,
			ClientHostname: result.ClientHostname,
			Domain:         result.Domain,
			QueryType:  result.QueryType,
			Blocked:    result.Blocked,
			BlockRule:  result.BlockRule,
			ResponseIP: result.ResponseIP,
			LatencyMs:  float64(result.Latency.Microseconds()) / 1000.0,
			Upstream:   result.Upstream,
			Protocol:   result.Protocol,
		})
	}

	// Start DNS server
	dnsServer := dnsserver.NewServer(cfg.DNS, filterEngine.Check, logFn, tlsConfig)

	// Restore persisted forwarders
	if data := database.GetSetting("forwarders"); data != "" {
		var fwds []string
		if json.Unmarshal([]byte(data), &fwds) == nil && len(fwds) > 0 {
			dnsServer.SetForwarders(fwds)
			slog.Info("restored forwarders", "component", "persistence", "count", len(fwds))
		}
	}

	// Connect ACME DNS-01 challenge TXT lookup
	dnsServer.SetACMETxtLookup(func(fqdn string) string {
		return database.GetSetting("acme_txt_" + fqdn)
	})

	// Connect zone lookup to database
	dnsServer.SetZoneLookup(func(name, rtype string) ([]db.DNSRecord, error) {
		return database.FindRecords(name, rtype)
	})

	// Connect zone transfer data function
	dnsServer.SetZoneDataFunc(func(zoneName string) (*db.Zone, []db.DNSRecord, error) {
		zone, err := database.GetZoneByName(zoneName)
		if err != nil {
			return nil, nil, err
		}
		records, err := database.ListRecords(zone.ID)
		if err != nil {
			return nil, nil, err
		}
		return zone, records, nil
	})

	// Start block page server (HTTP on port 80, HTTPS+DoH on port 443)
	blockPageServer := blockpage.NewServer(
		cfg.BlockPage.ListenAddr,
		cfg.BlockPage.HTTPPort,
		cfg.BlockPage.HTTPSPort,
		tlsConfig,
	)
	blockPageServer.SetDoHHandler(dnsServer.DoHHandler())
	blockPageServer.Start()

	// Connect block page to DNS server
	blockPageIP := os.Getenv("BLOCK_PAGE_IP")
	if blockPageIP == "" || blockPageIP == "0.0.0.0" {
		// Auto-detect host IP from default route
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err == nil {
			blockPageIP = conn.LocalAddr().(*net.UDPAddr).IP.String()
			conn.Close()
			slog.Info("auto-detected block page IP", "ip", blockPageIP)
		} else {
			blockPageIP = "0.0.0.0"
			slog.Warn("could not detect block page IP, set BLOCK_PAGE_IP env var")
		}
	}
	dnsServer.SetBlockPage(blockPageIP, func(domain, reason string) {
		blockPageServer.RecordBlock(domain, reason)
	})

	// Connect network protection response filter to DNS server
	dnsServer.SetResponseFilter(func(ip string) (bool, string, string) {
		return netProtect.CheckIP(ip)
	})

	if err := dnsServer.Start(); err != nil {
		slog.Error("failed to start DNS server", "error", err)
		os.Exit(1)
	}
	defer dnsServer.Shutdown()

	// Start API server
	apiServer := api.NewServer(cfg.API, database, filterEngine, netProtect, blockPageServer, dnsServer, certsDir)
	if err := apiServer.Start(); err != nil {
		slog.Error("failed to start API server", "error", err)
		os.Exit(1)
	}

	// Auto-create default primary zone if no zones exist
	zones, _ := database.ListZones()
	if len(zones) == 0 {
		slog.Info("no zones found, creating default primary zone", "component", "setup", "zone", "dnssupreme.local")
		defaultZone := &db.Zone{Name: "dnssupreme.local", Type: "primary", TTL: 3600}
		if err := database.CreateZone(defaultZone); err == nil {
			database.CreateRecord(&db.DNSRecord{
				ZoneID: defaultZone.ID, Name: "@", Type: "SOA",
				Value: "ns1.dnssupreme.local admin.dnssupreme.local 1 3600 900 604800 300", TTL: 3600,
			})
			database.CreateRecord(&db.DNSRecord{
				ZoneID: defaultZone.ID, Name: "@", Type: "NS",
				Value: "ns1.dnssupreme.local", TTL: 3600,
			})
			slog.Info("default zone created with SOA and NS records", "component", "setup", "zone", "dnssupreme.local")
		}
	}

	slog.Info("DNS-Supreme Mini is ready")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for s := range sig {
		if s == syscall.SIGHUP {
			slog.Info("SIGHUP received, reloading TLS and restarting DNS", "component", "restart")
			// Reload TLS certificates from data dir
			reloadCert, reloadKey := certFile, keyFile
			newTLS, err := certs.LoadOrGenerateTLS(reloadCert, reloadKey)
			if err == nil && newTLS != nil {
				dnsServer.ReloadTLS(newTLS)
				blockPageServer.ReloadTLS(newTLS)
				slog.Info("TLS certificates reloaded", "component", "restart", "cert", reloadCert)
			}
			slog.Info("restart complete", "component", "restart")
			continue
		}
		slog.Info("shutting down gracefully", "timeout", "10s")
		break
	}

	// Give in-flight requests time to complete
	done := make(chan struct{})
	go func() {
		dnsServer.Shutdown()
		netProtect.Stop()
		database.Close()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("shutdown complete")
	case <-time.After(10 * time.Second):
		slog.Warn("shutdown timed out, forcing exit")
	}
}

func loadDefaultBlocklists(engine *filter.Engine) {
	type listDef struct {
		url      string
		category filter.Category
	}
	lists := map[string]listDef{
		"stevenblack-hosts": {"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", filter.CategoryAds},
	}

	if url := os.Getenv("BLOCKLIST_ADS"); url != "" {
		lists["ads-extra"] = listDef{url, filter.CategoryAds}
	}
	if url := os.Getenv("BLOCKLIST_MALWARE"); url != "" {
		lists["malware"] = listDef{url, filter.CategoryMalware}
	}

	for name, def := range lists {
		go func(n string, d listDef) {
			for i := 0; i < 3; i++ {
				if err := engine.AddList(n, d.url, d.category); err != nil {
					slog.Warn("failed to load blocklist", "component", "filter", "name", n, "attempt", i+1, "error", err)
					time.Sleep(5 * time.Second)
					continue
				}
				return
			}
			slog.Error("giving up on blocklist", "component", "filter", "name", n)
		}(name, def)
	}
}

func loadPersistedBlocklists(database *db.Database, engine *filter.Engine) {
	saved, err := database.GetBlocklistsFull()
	if err != nil || len(saved) == 0 {
		slog.Info("no saved blocklists, loading defaults", "component", "persistence")
		loadDefaultBlocklists(engine)
		return
	}

	slog.Info("loading saved blocklists from database", "component", "persistence", "count", len(saved))
	for _, bl := range saved {
		go func(name, url string, cat string) {
			for i := 0; i < 3; i++ {
				if err := engine.AddList(name, url, filter.Category(cat)); err != nil {
					slog.Warn("failed to load blocklist", "component", "filter", "name", name, "attempt", i+1, "error", err)
					time.Sleep(5 * time.Second)
					continue
				}
				return
			}
			slog.Error("giving up on blocklist", "component", "filter", "name", name)
		}(bl.Name, bl.URL, bl.Category)
	}
}

func loadPersistedNpSettings(database *db.Database, np *filter.NetProtectEngine) {
	// Load enabled NP categories
	if data := database.GetSetting("np_enabled_categories"); data != "" {
		var enabled []string
		if json.Unmarshal([]byte(data), &enabled) == nil {
			for _, id := range enabled {
				np.SetCategoryEnabled(id, true)
			}
			slog.Info("restored network protection categories", "component", "persistence", "count", len(enabled))
		}
	}

	// Load geo-blocked countries
	if data := database.GetSetting("geo_blocked_countries"); data != "" {
		var countries []string
		if json.Unmarshal([]byte(data), &countries) == nil {
			np.SetGeoBlocked(countries)
			slog.Info("restored geo-blocked countries", "component", "persistence", "count", len(countries))
		}
	}
}

func loadPersistedFilterSettings(database *db.Database, engine *filter.Engine) {
	// Custom blocks
	if data := database.GetSetting("custom_blocks"); data != "" {
		var blocks map[string]string
		if json.Unmarshal([]byte(data), &blocks) == nil {
			for domain, reason := range blocks {
				engine.AddCustomBlock(domain, reason)
			}
			slog.Info("restored custom block rules", "component", "persistence", "count", len(blocks))
		}
	}

	// Allowlist
	if data := database.GetSetting("allowlist"); data != "" {
		var list []string
		if json.Unmarshal([]byte(data), &list) == nil {
			for _, domain := range list {
				engine.AddAllowlistDomain(domain)
			}
			slog.Info("restored allowlist entries", "component", "persistence", "count", len(list))
		}
	}

	// Blocked services
	if data := database.GetSetting("blocked_services"); data != "" {
		var ids []string
		if json.Unmarshal([]byte(data), &ids) == nil && len(ids) > 0 {
			engine.ServiceBlocker().RestoreEnabled(ids)
		}
	}
}
