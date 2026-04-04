package api

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

type Fail2Ban struct {
	mu         sync.RWMutex
	attempts   map[string]*loginAttempt
	banned     map[string]time.Time
	maxRetries int
	banSeconds int
	allowedIPs []net.IPNet
}

type loginAttempt struct {
	count    int
	lastFail time.Time
}

func NewFail2Ban() *Fail2Ban {
	f := &Fail2Ban{
		attempts:   make(map[string]*loginAttempt),
		banned:     make(map[string]time.Time),
		maxRetries: 5,
		banSeconds: 900, // 15 minutes
	}
	go f.cleanup()
	return f
}

func (f *Fail2Ban) SetConfig(maxRetries, banSeconds int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if maxRetries > 0 {
		f.maxRetries = maxRetries
	}
	if banSeconds > 0 {
		f.banSeconds = banSeconds
	}
}

func (f *Fail2Ban) GetConfig() (int, int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.maxRetries, f.banSeconds
}

func (f *Fail2Ban) SetAllowedIPs(cidrs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowedIPs = nil
	for _, cidr := range cidrs {
		if cidr == "" {
			continue
		}
		if !containsSlash(cidr) {
			cidr += "/32"
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			f.allowedIPs = append(f.allowedIPs, *ipnet)
		}
	}
}

func (f *Fail2Ban) GetAllowedIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]string, len(f.allowedIPs))
	for i, n := range f.allowedIPs {
		result[i] = n.String()
	}
	return result
}

func (f *Fail2Ban) IsAllowed(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.allowedIPs) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	// Loopback always allowed
	if parsed.IsLoopback() {
		return true
	}
	for _, n := range f.allowedIPs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (f *Fail2Ban) IsBanned(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if until, ok := f.banned[ip]; ok {
		if time.Now().Before(until) {
			return true
		}
	}
	return false
}

func (f *Fail2Ban) RecordFail(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	a, ok := f.attempts[ip]
	if !ok {
		f.attempts[ip] = &loginAttempt{count: 1, lastFail: time.Now()}
		return false
	}

	a.count++
	a.lastFail = time.Now()

	if a.count >= f.maxRetries {
		f.banned[ip] = time.Now().Add(time.Duration(f.banSeconds) * time.Second)
		delete(f.attempts, ip)
		slog.Warn("IP banned", "component", "fail2ban", "ip", ip, "duration_seconds", f.banSeconds)
		return true
	}
	return false
}

func (f *Fail2Ban) RecordSuccess(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attempts, ip)
}

func (f *Fail2Ban) UnbanIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.banned, ip)
}

func (f *Fail2Ban) GetBannedIPs() map[string]time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make(map[string]time.Time)
	now := time.Now()
	for ip, until := range f.banned {
		if until.After(now) {
			result[ip] = until
		}
	}
	return result
}

func (f *Fail2Ban) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		f.mu.Lock()
		now := time.Now()
		for ip, until := range f.banned {
			if now.After(until) {
				delete(f.banned, ip)
			}
		}
		for ip, a := range f.attempts {
			if now.Sub(a.lastFail) > 30*time.Minute {
				delete(f.attempts, ip)
			}
		}
		f.mu.Unlock()
	}
}

func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}
