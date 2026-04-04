package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"dns-supreme-mini/internal/db"
	mdns "github.com/miekg/dns"
)

type ZoneDataFunc func(zoneName string) (*db.Zone, []db.DNSRecord, error)

func (s *Server) SetZoneDataFunc(fn ZoneDataFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zoneDataFn = fn
}

// handleAXFR responds to AXFR requests (zone transfer)
func (s *Server) handleAXFR(w mdns.ResponseWriter, r *mdns.Msg) {
	if len(r.Question) == 0 {
		mdns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]

	clientAddr := w.RemoteAddr().String()
	if !s.isAXFRAllowed(clientAddr) {
		slog.Warn("AXFR transfer denied", "component", "axfr", "client", clientAddr, "reason", "not in allowed IPs")
		mdns.HandleFailed(w, r)
		return
	}

	zoneName := strings.TrimSuffix(q.Name, ".")

	s.mu.RLock()
	fn := s.zoneDataFn
	s.mu.RUnlock()

	if fn == nil {
		mdns.HandleFailed(w, r)
		return
	}

	zone, records, err := fn(zoneName)
	if err != nil || zone == nil {
		slog.Warn("AXFR zone not found", "component", "axfr", "zone", zoneName)
		mdns.HandleFailed(w, r)
		return
	}

	slog.Info("AXFR transfer requested", "component", "axfr", "zone", zoneName, "records", len(records))

	// Build SOA record
	soa := &mdns.SOA{
		Hdr: mdns.RR_Header{
			Name:   q.Name,
			Rrtype: mdns.TypeSOA,
			Class:  mdns.ClassINET,
			Ttl:    uint32(zone.TTL),
		},
		Ns:      "ns1." + q.Name,
		Mbox:    "admin." + q.Name,
		Serial:  zone.SOASerial,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  300,
	}

	// AXFR starts and ends with SOA
	ch := make(chan *mdns.Envelope, 1)
	tr := new(mdns.Transfer)

	rrs := make([]mdns.RR, 0, len(records)+2)
	rrs = append(rrs, soa)

	for _, rec := range records {
		fqdn := rec.Name + "." + q.Name
		if rec.Name == "@" {
			fqdn = q.Name
		}
		rr := zoneRecordToRR(rec, fqdn, uint32(rec.TTL))
		if rr != nil {
			rrs = append(rrs, rr)
		}
	}

	rrs = append(rrs, soa) // End with SOA

	go func() {
		ch <- &mdns.Envelope{RR: rrs}
		close(ch)
	}()

	tr.Out(w, r, ch)
}

func zoneRecordToRR(rec db.DNSRecord, fqdn string, ttl uint32) mdns.RR {
	hdr := mdns.RR_Header{
		Name:   fqdn,
		Rrtype: mdns.StringToType[rec.Type],
		Class:  mdns.ClassINET,
		Ttl:    ttl,
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
	}
	return nil
}

// RequestAXFR pulls zone data from a primary server (used by secondary)
func RequestAXFR(primaryAddr, zoneName string) ([]db.DNSRecord, uint32, error) {
	tr := new(mdns.Transfer)
	msg := new(mdns.Msg)
	msg.SetAxfr(mdns.Fqdn(zoneName))

	ch, err := tr.In(msg, primaryAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("AXFR connect failed: %w", err)
	}

	var records []db.DNSRecord
	var serial uint32

	for env := range ch {
		if env.Error != nil {
			return nil, 0, env.Error
		}
		for _, rr := range env.RR {
			if soa, ok := rr.(*mdns.SOA); ok {
				serial = soa.Serial
				continue
			}
			rec := rrToRecord(rr, zoneName)
			if rec != nil {
				records = append(records, *rec)
			}
		}
	}

	return records, serial, nil
}

func rrToRecord(rr mdns.RR, zoneName string) *db.DNSRecord {
	hdr := rr.Header()
	name := strings.TrimSuffix(hdr.Name, ".")
	fqdnZone := mdns.Fqdn(zoneName)

	// Strip zone suffix to get record name
	recName := strings.TrimSuffix(name, "."+strings.TrimSuffix(fqdnZone, "."))
	if recName == strings.TrimSuffix(fqdnZone, ".") {
		recName = "@"
	}

	rec := &db.DNSRecord{
		Name: recName,
		Type: mdns.TypeToString[hdr.Rrtype],
		TTL:  int(hdr.Ttl),
	}

	switch v := rr.(type) {
	case *mdns.A:
		rec.Value = v.A.String()
	case *mdns.AAAA:
		rec.Value = v.AAAA.String()
	case *mdns.CNAME:
		rec.Value = strings.TrimSuffix(v.Target, ".")
	case *mdns.MX:
		rec.Value = strings.TrimSuffix(v.Mx, ".")
		rec.Priority = int(v.Preference)
	case *mdns.TXT:
		rec.Value = strings.Join(v.Txt, " ")
	case *mdns.NS:
		rec.Value = strings.TrimSuffix(v.Ns, ".")
	default:
		return nil
	}

	return rec
}
