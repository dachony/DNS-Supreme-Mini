package filter

import (
	"net"
	"net/netip"
	"sort"
)

// IPMatcher provides fast IP/CIDR matching using a hash map for exact IPs
// and sorted prefix lists per CIDR length for binary search.
type IPMatcher struct {
	ips    map[netip.Addr]bool
	byLen  map[int][]netip.Prefix
	lengths []int // unique prefix lengths, sorted desc (most specific first)
}

// NewIPMatcher creates a new empty IPMatcher.
func NewIPMatcher() *IPMatcher {
	return &IPMatcher{
		ips:   make(map[netip.Addr]bool),
		byLen: make(map[int][]netip.Prefix),
	}
}

// AddIP adds a single IP address for exact matching.
func (m *IPMatcher) AddIP(ipStr string) {
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		m.ips[addr.Unmap()] = true
	}
}

// AddCIDR adds a CIDR range for prefix matching.
func (m *IPMatcher) AddCIDR(cidr *net.IPNet) {
	addr, ok := netip.AddrFromSlice(cidr.IP)
	if !ok {
		return
	}
	ones, _ := cidr.Mask.Size()
	p := netip.PrefixFrom(addr.Unmap(), ones)
	m.byLen[ones] = append(m.byLen[ones], p.Masked())
}

// Build sorts internal structures for fast lookup. Call after all Add calls.
func (m *IPMatcher) Build() {
	m.lengths = make([]int, 0, len(m.byLen))
	for l := range m.byLen {
		m.lengths = append(m.lengths, l)
		sort.Slice(m.byLen[l], func(i, j int) bool {
			return m.byLen[l][i].Addr().Less(m.byLen[l][j].Addr())
		})
	}
	sort.Sort(sort.Reverse(sort.IntSlice(m.lengths)))
}

// Contains checks if an IP is in any of the stored IPs or CIDRs.
func (m *IPMatcher) Contains(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	// Exact IP check: O(1)
	if m.ips[addr] {
		return true
	}

	// CIDR check: iterate prefix lengths from most to least specific
	for _, l := range m.lengths {
		masked := netip.PrefixFrom(addr, l).Masked().Addr()
		prefixes := m.byLen[l]
		// Binary search for the masked address
		idx := sort.Search(len(prefixes), func(i int) bool {
			return !prefixes[i].Addr().Less(masked)
		})
		if idx < len(prefixes) && prefixes[idx].Addr() == masked {
			return true
		}
	}

	return false
}

// Len returns the total number of entries (IPs + CIDRs).
func (m *IPMatcher) Len() int {
	total := len(m.ips)
	for _, prefixes := range m.byLen {
		total += len(prefixes)
	}
	return total
}
