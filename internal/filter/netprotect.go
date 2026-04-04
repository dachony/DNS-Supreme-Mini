package filter

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NetProtectCategory represents a network protection threat category
type NetProtectCategory struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Enabled        bool     `json:"enabled"`
	Sources        []string `json:"sources"`
	EntryCount     int      `json:"entry_count"`
	LastUpdated    string   `json:"last_updated,omitempty"`
	LastFetchError string   `json:"last_fetch_error,omitempty"`
	Stale          bool     `json:"stale"`
}

// NetProtectEngine checks destination IPs against threat intelligence feeds and GeoIP
type NetProtectEngine struct {
	categories      map[string]*npCategory
	geoCountries    map[string]bool        // blocked country codes
	geoLookupFn     func(ip net.IP) string // IP -> country code
	refreshInterval time.Duration
	mu              sync.RWMutex
	stopCh          chan struct{}
}

type npCategory struct {
	meta          NetProtectCategory
	ips           map[string]bool
	cidrs         []*net.IPNet
	matcher       *IPMatcher // fast lookup via sorted prefixes + hash map
	lastFetchErr  string
	lastFetchTime time.Time
}

func (c *npCategory) contains(ip net.IP) bool {
	if c.matcher != nil {
		return c.matcher.Contains(ip)
	}
	// Fallback to linear scan if matcher not yet built
	ipStr := ip.String()
	if c.ips[ipStr] {
		return true
	}
	for _, cidr := range c.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Default threat feed sources
var defaultCategories = []NetProtectCategory{
	{
		ID:          "tor_exits",
		Name:        "Tor Exit Nodes",
		Description: "Block connections to IPs that are known Tor exit nodes",
		Enabled:     false,
		Sources:     []string{"https://check.torproject.org/torbulkexitlist"},
	},
	{
		ID:          "spamhaus_drop",
		Name:        "Spamhaus DROP",
		Description: "Don't Route Or Peer — hijacked IP blocks and known bad networks",
		Enabled:     false,
		Sources: []string{
			"https://www.spamhaus.org/drop/drop.txt",
			"https://www.spamhaus.org/drop/edrop.txt",
		},
	},
	{
		ID:          "botnet_c2",
		Name:        "Botnet C2 Servers",
		Description: "Known botnet command & control server IPs (Feodo Tracker)",
		Enabled:     false,
		Sources:     []string{"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
	},
	{
		ID:          "malicious_ips",
		Name:        "Malicious IPs",
		Description: "Compromised hosts and known attacker IPs (Emerging Threats)",
		Enabled:     false,
		Sources:     []string{"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
	},
	{
		ID:          "abuse_ch",
		Name:        "URLhaus Malware",
		Description: "Active malware distribution sites (abuse.ch URLhaus)",
		Enabled:     false,
		Sources:     []string{"https://urlhaus.abuse.ch/downloads/hostfile/"},
	},
}

func NewNetProtectEngine() *NetProtectEngine {
	e := &NetProtectEngine{
		categories:      make(map[string]*npCategory),
		geoCountries:    make(map[string]bool),
		refreshInterval: 6 * time.Hour,
		stopCh:          make(chan struct{}),
	}

	for _, def := range defaultCategories {
		e.categories[def.ID] = &npCategory{
			meta: def,
			ips:  make(map[string]bool),
		}
	}

	return e
}

// SetGeoLookup sets the function used to resolve IP -> country code
func (e *NetProtectEngine) SetGeoLookup(fn func(ip net.IP) string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoLookupFn = fn
}

// CheckIP checks if a destination IP should be blocked
// Returns (blocked, reason, category)
func (e *NetProtectEngine) CheckIP(ipStr string) (bool, string, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "", ""
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check threat categories
	for _, cat := range e.categories {
		if !cat.meta.Enabled {
			continue
		}
		if cat.contains(ip) {
			return true, fmt.Sprintf("[netprotect:%s] %s", cat.meta.ID, cat.meta.Name), cat.meta.ID
		}
	}

	// Check geo blocking
	if len(e.geoCountries) > 0 && e.geoLookupFn != nil {
		cc := e.geoLookupFn(ip)
		if cc != "" && e.geoCountries[cc] {
			return true, fmt.Sprintf("[netprotect:geo] Blocked country: %s", cc), "geo_countries"
		}
	}

	return false, "", ""
}

// categoryOrder defines the display order of categories
var categoryOrder = []string{"tor_exits", "spamhaus_drop", "botnet_c2", "malicious_ips", "abuse_ch"}

// GetCategories returns all categories with current status in stable order
func (e *NetProtectEngine) GetCategories() []NetProtectCategory {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]NetProtectCategory, 0, len(e.categories))
	for _, id := range categoryOrder {
		if cat, ok := e.categories[id]; ok {
			result = append(result, cat.meta)
		}
	}
	return result
}

// SetCategoryEnabled enables or disables a category
func (e *NetProtectEngine) SetCategoryEnabled(id string, enabled bool) error {
	e.mu.Lock()
	cat, ok := e.categories[id]
	e.mu.Unlock()

	if !ok {
		return fmt.Errorf("unknown category: %s", id)
	}

	cat.meta.Enabled = enabled

	// If enabling and no entries loaded yet, load now
	if enabled && cat.meta.EntryCount == 0 && len(cat.meta.Sources) > 0 {
		go e.loadCategory(id)
	}

	return nil
}

// SetGeoBlocked sets the list of blocked country codes
func (e *NetProtectEngine) SetGeoBlocked(codes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.geoCountries = make(map[string]bool)
	for _, cc := range codes {
		e.geoCountries[strings.ToUpper(strings.TrimSpace(cc))] = true
	}
}

// GetGeoBlocked returns the list of blocked country codes
func (e *NetProtectEngine) GetGeoBlocked() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]string, 0, len(e.geoCountries))
	for cc := range e.geoCountries {
		result = append(result, cc)
	}
	return result
}

// RefreshNow triggers an immediate refresh of all enabled feeds
func (e *NetProtectEngine) RefreshNow() {
	e.refreshAll()
}

// GetRefreshInterval returns the current auto-refresh interval in minutes
func (e *NetProtectEngine) GetRefreshInterval() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return int(e.refreshInterval.Minutes())
}

// SetRefreshInterval sets the auto-refresh interval in minutes
func (e *NetProtectEngine) SetRefreshInterval(minutes int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if minutes < 5 {
		minutes = 5
	}
	e.refreshInterval = time.Duration(minutes) * time.Minute
}

// GetCategoryEntries returns a sample of IPs/CIDRs from the given category (up to max)
func (e *NetProtectEngine) GetCategoryEntries(id string, max int) ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	cat, ok := e.categories[id]
	if !ok {
		return nil, fmt.Errorf("unknown category: %s", id)
	}

	result := make([]string, 0, max)
	for ip := range cat.ips {
		result = append(result, ip)
		if len(result) >= max {
			return result, nil
		}
	}
	for _, cidr := range cat.cidrs {
		result = append(result, cidr.String())
		if len(result) >= max {
			return result, nil
		}
	}
	return result, nil
}

// Start begins background refresh of enabled feeds
func (e *NetProtectEngine) Start() {
	// Initial load of enabled categories
	e.mu.RLock()
	for id, cat := range e.categories {
		if cat.meta.Enabled {
			go e.loadCategory(id)
		}
	}
	e.mu.RUnlock()

	// Periodic refresh
	go func() {
		for {
			e.mu.RLock()
			interval := e.refreshInterval
			e.mu.RUnlock()

			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
				e.refreshAll()
			case <-e.stopCh:
				timer.Stop()
				return
			}
		}
	}()
}

// Stop halts background refresh
func (e *NetProtectEngine) Stop() {
	close(e.stopCh)
}

func (e *NetProtectEngine) refreshAll() {
	e.mu.RLock()
	for id, cat := range e.categories {
		if cat.meta.Enabled {
			go e.loadCategory(id)
		}
	}
	e.mu.RUnlock()
}

func (e *NetProtectEngine) loadCategory(id string) {
	e.mu.RLock()
	cat, ok := e.categories[id]
	if !ok {
		e.mu.RUnlock()
		return
	}
	sources := cat.meta.Sources
	e.mu.RUnlock()

	newIPs := make(map[string]bool)
	var newCIDRs []*net.IPNet

	var lastErr string
	for _, src := range sources {
		ips, cidrs, err := fetchIPList(src)
		if err != nil {
			slog.Warn("failed to fetch threat feed", "component", "netprotect", "category", id, "source", src, "error", err)
			lastErr = fmt.Sprintf("fetch %s: %v", src, err)
			continue
		}
		for ip := range ips {
			newIPs[ip] = true
		}
		newCIDRs = append(newCIDRs, cidrs...)
	}

	total := len(newIPs) + len(newCIDRs)

	// Build fast matcher for O(1) IP and O(log N) CIDR lookups
	matcher := NewIPMatcher()
	for ip := range newIPs {
		matcher.AddIP(ip)
	}
	for _, cidr := range newCIDRs {
		matcher.AddCIDR(cidr)
	}
	matcher.Build()

	e.mu.Lock()
	cat.ips = newIPs
	cat.cidrs = newCIDRs
	cat.matcher = matcher
	cat.meta.EntryCount = total
	now := time.Now().UTC()
	cat.meta.LastUpdated = now.Format(time.RFC3339)
	cat.lastFetchTime = now
	if lastErr != "" && total == 0 {
		cat.lastFetchErr = lastErr
		cat.meta.LastFetchError = lastErr
		cat.meta.Stale = true
	} else {
		cat.lastFetchErr = ""
		cat.meta.LastFetchError = ""
		cat.meta.Stale = false
	}
	e.mu.Unlock()

	slog.Info("loaded threat feed", "component", "netprotect", "category", id, "ips", len(newIPs), "cidrs", len(newCIDRs))
}

// fetchIPList downloads and parses an IP/CIDR list from a URL
func fetchIPList(url string) (map[string]bool, []*net.IPNet, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ips := make(map[string]bool)
	var cidrs []*net.IPNet

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Strip inline comments (Spamhaus DROP format: "1.2.3.0/24 ; SBnnn")
		if idx := strings.IndexAny(line, ";#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Try CIDR
		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err == nil {
				cidrs = append(cidrs, cidr)
				continue
			}
		}

		// Try plain IP (may have port: "1.2.3.4:443" or extra columns)
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ipStr := fields[0]
			// Strip port if present
			if host, _, err := net.SplitHostPort(ipStr); err == nil {
				ipStr = host
			}
			if ip := net.ParseIP(ipStr); ip != nil {
				ips[ip.String()] = true
			}
		}
	}

	return ips, cidrs, scanner.Err()
}
