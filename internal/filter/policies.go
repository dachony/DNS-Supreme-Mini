package filter

import (
	"net"
	"strings"
	"sync"
)

type DevicePolicy struct {
	ClientIP           string              `json:"client_ip"`
	Name               string              `json:"name"`
	DisabledCategories map[Category]bool    `json:"disabled_categories"`
	CustomBlocks       map[string]string    `json:"custom_blocks"`
	CustomAllows       map[string]bool      `json:"custom_allows"`
}

type PolicyManager struct {
	policies map[string]*DevicePolicy // client IP -> policy
	mu       sync.RWMutex
}

func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make(map[string]*DevicePolicy),
	}
}

func (pm *PolicyManager) SetPolicy(p *DevicePolicy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	ip := normalizeIP(p.ClientIP)
	p.ClientIP = ip
	if p.DisabledCategories == nil {
		p.DisabledCategories = make(map[Category]bool)
	}
	if p.CustomBlocks == nil {
		p.CustomBlocks = make(map[string]string)
	}
	if p.CustomAllows == nil {
		p.CustomAllows = make(map[string]bool)
	}
	pm.policies[ip] = p
}

func (pm *PolicyManager) GetPolicy(clientIP string) *DevicePolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.policies[normalizeIP(clientIP)]
}

func (pm *PolicyManager) RemovePolicy(clientIP string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.policies, normalizeIP(clientIP))
}

func (pm *PolicyManager) ListPolicies() []*DevicePolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	result := make([]*DevicePolicy, 0, len(pm.policies))
	for _, p := range pm.policies {
		result = append(result, p)
	}
	return result
}

// CheckDevice applies device-specific policy on top of global filter result.
// Returns (overrideBlocked, overrideRule) or (false, "") if no override.
func (pm *PolicyManager) CheckDevice(clientIP, domain string, globalBlocked bool, globalRule string, category Category) (bool, string) {
	pm.mu.RLock()
	policy := pm.policies[normalizeIP(clientIP)]
	pm.mu.RUnlock()

	if policy == nil {
		return globalBlocked, globalRule
	}

	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	// Device-specific allow overrides everything
	if policy.CustomAllows[domain] {
		return false, ""
	}

	// Device-specific block
	if reason, ok := policy.CustomBlocks[domain]; ok {
		return true, "device-policy: " + reason
	}

	// Device disabled category — if the global block was from this category, unblock
	if globalBlocked && category != "" && policy.DisabledCategories[category] {
		return false, ""
	}

	return globalBlocked, globalRule
}

func normalizeIP(addr string) string {
	// Strip port if present
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip := net.ParseIP(addr)
	if ip != nil {
		return ip.String()
	}
	return addr
}
