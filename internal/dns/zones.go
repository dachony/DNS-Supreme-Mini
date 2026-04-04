package dns

import (
	"fmt"
	"net"
	"strings"

	"dns-supreme-mini/internal/db"
	mdns "github.com/miekg/dns"
)

// suppress unused import
var _ = fmt.Sprintf

type ZoneLookupFunc func(name, rtype string) ([]db.DNSRecord, error)

func (s *Server) SetZoneLookup(fn ZoneLookupFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zoneLookup = fn
}

// resolveFromZones tries to answer a query from local zone data.
// Returns nil if no matching zone records exist.
func (s *Server) resolveFromZones(qname string, qtype uint16) *mdns.Msg {
	if s.zoneLookup == nil {
		return nil
	}

	name := strings.TrimSuffix(qname, ".")
	rtype := mdns.TypeToString[qtype]

	records, err := s.zoneLookup(name, rtype)
	if err != nil || len(records) == 0 {
		// Also try CNAME if direct type lookup failed
		if rtype != "CNAME" {
			cnames, _ := s.zoneLookup(name, "CNAME")
			if len(cnames) > 0 {
				records = cnames
			}
		}
	}

	if len(records) == 0 {
		return nil
	}

	msg := new(mdns.Msg)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	for _, rec := range records {
		rr := recordToRR(rec, qname)
		if rr != nil {
			msg.Answer = append(msg.Answer, rr)
		}
	}

	if len(msg.Answer) == 0 {
		return nil
	}

	return msg
}

func recordToRR(rec db.DNSRecord, qname string) mdns.RR {
	hdr := mdns.RR_Header{
		Name:   qname,
		Rrtype: mdns.StringToType[rec.Type],
		Class:  mdns.ClassINET,
		Ttl:    uint32(rec.TTL),
	}

	switch rec.Type {
	case "A":
		ip := net.ParseIP(rec.Value)
		if ip == nil {
			return nil
		}
		return &mdns.A{Hdr: hdr, A: ip.To4()}

	case "AAAA":
		ip := net.ParseIP(rec.Value)
		if ip == nil {
			return nil
		}
		return &mdns.AAAA{Hdr: hdr, AAAA: ip.To16()}

	case "CNAME":
		return &mdns.CNAME{Hdr: hdr, Target: mdns.Fqdn(rec.Value)}

	case "MX":
		return &mdns.MX{Hdr: hdr, Preference: uint16(rec.Priority), Mx: mdns.Fqdn(rec.Value)}

	case "TXT":
		return &mdns.TXT{Hdr: hdr, Txt: []string{rec.Value}}

	case "NS":
		return &mdns.NS{Hdr: hdr, Ns: mdns.Fqdn(rec.Value)}

	case "PTR":
		return &mdns.PTR{Hdr: hdr, Ptr: mdns.Fqdn(rec.Value)}

	case "CAA":
		return &mdns.CAA{Hdr: hdr, Flag: 0, Tag: "issue", Value: rec.Value}

	case "SRV":
		// Value format: "weight port target" (e.g., "0 5060 sip.example.com")
		parts := strings.Fields(rec.Value)
		if len(parts) < 3 {
			return nil
		}
		var weight, port uint16
		fmt.Sscanf(parts[0], "%d", &weight)
		fmt.Sscanf(parts[1], "%d", &port)
		return &mdns.SRV{
			Hdr:      hdr,
			Priority: uint16(rec.Priority),
			Weight:   weight,
			Port:     port,
			Target:   mdns.Fqdn(parts[2]),
		}
	}

	return nil
}
