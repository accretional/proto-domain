// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from the bottom half of $GOROOT/src/net/dnsclient_unix.go
// (the goLookupX implementations). See ./README.md for fork policy.
//
// Differences from upstream:
//
//   - TTL preservation: every record returned carries its
//     ResourceHeader.TTL on TtlSeconds. Upstream parses this same
//     value and discards it.
//   - Returns *domainpb.DNSRecord directly rather than upstream's
//     net.IPAddr / net.MX / net.NS / etc. The proto schema is the
//     single source of typed records.
//   - No parallel A+AAAA fanout: upstream queries A and AAAA in
//     parallel via a goroutine + channel + dnsWaitGroup. We do them
//     sequentially. The wire savings of parallel only materialize on
//     slow servers, and the dnsWaitGroup orchestration pulls in
//     package-level state we'd rather not fork.
//   - No hostLookupOrder enum: we always do FilesDNS (try /etc/hosts
//     first, fall back to DNS).
//   - Errors are *net.DNSError (already exported from package net).
//
// Material changes vs upstream are flagged with "// fork:" comments.

package dns

import (
	"context"
	"net"

	"golang.org/x/net/dns/dnsmessage"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// goLookupIPCNAMEOrder is the workhorse behind LookupIP / LookupCNAME.
// It first tries /etc/hosts; if no entries exist it issues A and AAAA
// queries (and CNAME if asked) and walks the answer section.
//
// `network` selects which families to query:
//
//	"ip", "ip4+ip6"  → A + AAAA (and CNAME if "CNAME")
//	"ip4"            → A only
//	"ip6"            → AAAA only
//	"CNAME"          → A + AAAA + CNAME (used by goLookupCNAME)
func (r *Resolver) goLookupIPCNAMEOrder(ctx context.Context, network, name string, conf *dnsConfig) (records []*domainpb.DNSRecord, cname string, err error) {
	// /etc/hosts first.
	if addrs, canonical := lookupStaticHost(name); len(addrs) > 0 {
		// fork: upstream returns IPAddr; we synthesize ARecord/AAAARecord
		// proto bodies with TTL=0 (a hosts file has no TTL).
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			h := dnsmessage.ResourceHeader{TTL: 0, Class: dnsmessage.ClassINET}
			if v4 := ip.To4(); v4 != nil {
				h.Type = dnsmessage.TypeA
				records = append(records, newRecord(h, domainpb.DNSRecordType_A,
					&domainpb.ARecord{Ipv4: append([]byte(nil), v4...)}))
			} else {
				h.Type = dnsmessage.TypeAAAA
				records = append(records, newRecord(h, domainpb.DNSRecordType_AAAA,
					&domainpb.AAAARecord{Ipv6: append([]byte(nil), ip.To16()...)}))
			}
		}
		if len(records) > 0 {
			return records, canonical, nil
		}
	}

	if !isDomainName(name) {
		return nil, "", newDNSError(errNoSuchHost, name, "")
	}

	if conf == nil {
		conf = getSystemDNSConfig()
	}

	qtypes := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	if network == "CNAME" {
		qtypes = append(qtypes, dnsmessage.TypeCNAME)
	}
	switch network {
	case "ip4":
		qtypes = []dnsmessage.Type{dnsmessage.TypeA}
	case "ip6":
		qtypes = []dnsmessage.Type{dnsmessage.TypeAAAA}
	}

	var lastErr error
	for _, fqdn := range conf.nameList(name) {
		for _, qtype := range qtypes {
			p, server, err := r.tryOneName(ctx, conf, fqdn, qtype)
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Temporary() && r.strictErrors() {
					return nil, "", err
				}
				if lastErr == nil || fqdn == name+"." {
					lastErr = err
				}
				continue
			}

			recs, cn, parseErr := parseAddressAnswers(&p, server, name, qtype)
			if parseErr != nil {
				return nil, "", parseErr
			}
			records = append(records, recs...)
			if cname == "" && cn != "" {
				cname = cn
			}
		}
		if len(records) > 0 || (network == "CNAME" && cname != "") {
			break
		}
	}

	if dnsErr, ok := lastErr.(*net.DNSError); ok {
		dnsErr.Name = name
	}

	if len(records) == 0 && (network != "CNAME" || cname == "") {
		if lastErr != nil {
			return nil, "", lastErr
		}
		return nil, "", newDNSError(errNoSuchHost, name, "")
	}

	return records, cname, nil
}

// parseAddressAnswers walks an answer section for A / AAAA / CNAME
// records and returns them as DNSRecord values. Helper for
// goLookupIPCNAMEOrder.
func parseAddressAnswers(p *dnsmessage.Parser, server, name string, qtype dnsmessage.Type) ([]*domainpb.DNSRecord, string, error) {
	var records []*domainpb.DNSRecord
	var cname string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return records, cname, nil
		}
		if err != nil {
			return nil, "", &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return nil, "", &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			records = append(records, newRecord(h, domainpb.DNSRecordType_A,
				&domainpb.ARecord{Ipv4: append([]byte(nil), a.A[:]...)}))
			if cname == "" && h.Name.Length != 0 {
				cname = h.Name.String()
			}
		case dnsmessage.TypeAAAA:
			aaaa, err := p.AAAAResource()
			if err != nil {
				return nil, "", &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			records = append(records, newRecord(h, domainpb.DNSRecordType_AAAA,
				&domainpb.AAAARecord{Ipv6: append([]byte(nil), aaaa.AAAA[:]...)}))
			if cname == "" && h.Name.Length != 0 {
				cname = h.Name.String()
			}
		case dnsmessage.TypeCNAME:
			c, err := p.CNAMEResource()
			if err != nil {
				return nil, "", &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			target := c.CNAME.String()
			records = append(records, newRecord(h, domainpb.DNSRecordType_CNAME,
				&domainpb.CNAMERecord{Target: target}))
			if cname == "" && c.CNAME.Length > 0 {
				cname = target
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, "", &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
		}
	}
}

// goLookupCNAME issues a single A+AAAA+CNAME query and returns the
// canonical name. Faithful to upstream's "use the same engine as IP
// lookup" approach.
func (r *Resolver) goLookupCNAME(ctx context.Context, host string, conf *dnsConfig) (string, error) {
	_, cname, err := r.goLookupIPCNAMEOrder(ctx, "CNAME", host, conf)
	return cname, err
}

// goLookupNS returns NS records for name.
func (r *Resolver) goLookupNS(ctx context.Context, name string, conf *dnsConfig) ([]*domainpb.DNSRecord, error) {
	p, server, err := r.lookup(ctx, name, dnsmessage.TypeNS, conf)
	if err != nil {
		return nil, err
	}
	var out []*domainpb.DNSRecord
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return out, nil
		}
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		if h.Type != dnsmessage.TypeNS {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			continue
		}
		ns, err := p.NSResource()
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		out = append(out, newRecord(h, domainpb.DNSRecordType_NS,
			&domainpb.NSRecord{Host: ns.NS.String()}))
	}
}

// goLookupMX returns MX records for name, sorted by preference.
func (r *Resolver) goLookupMX(ctx context.Context, name string, conf *dnsConfig) ([]*domainpb.DNSRecord, error) {
	p, server, err := r.lookup(ctx, name, dnsmessage.TypeMX, conf)
	if err != nil {
		return nil, err
	}
	var out []*domainpb.DNSRecord
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		if h.Type != dnsmessage.TypeMX {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			continue
		}
		mx, err := p.MXResource()
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		out = append(out, newRecord(h, domainpb.DNSRecordType_MX,
			&domainpb.MXRecord{Pref: uint32(mx.Pref), Host: mx.MX.String()}))
	}
	sortMXRecords(out)
	return out, nil
}

// goLookupTXT returns TXT records for name.
//
// fork: upstream concatenates all character-strings inside a single TXT
// RR into one string. We preserve the per-fragment slice — callers that
// want stdlib-equivalent behavior can `strings.Join(rec.GetTxt().GetStrings(), "")`.
func (r *Resolver) goLookupTXT(ctx context.Context, name string, conf *dnsConfig) ([]*domainpb.DNSRecord, error) {
	p, server, err := r.lookup(ctx, name, dnsmessage.TypeTXT, conf)
	if err != nil {
		return nil, err
	}
	var out []*domainpb.DNSRecord
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		out = append(out, newRecord(h, domainpb.DNSRecordType_TXT,
			&domainpb.TXTRecord{Strings: append([]string(nil), txt.TXT...)}))
	}
	return out, nil
}

// goLookupSRV issues an SRV query and returns sorted records. SRV does
// not have a proto body type yet, so this still returns the local
// SRVRecord shape.
func (r *Resolver) goLookupSRV(ctx context.Context, service, proto, name string, conf *dnsConfig) (cname string, records []*SRVRecord, err error) {
	target := name
	if service != "" || proto != "" {
		target = "_" + service + "._" + proto + "." + name
	}
	p, server, err := r.lookup(ctx, target, dnsmessage.TypeSRV, conf)
	if err != nil {
		return "", nil, err
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		if h.Type != dnsmessage.TypeSRV {
			if err := p.SkipAnswer(); err != nil {
				return "", nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
			}
			continue
		}
		if cname == "" && h.Name.Length != 0 {
			cname = h.Name.String()
		}
		srv, err := p.SRVResource()
		if err != nil {
			return "", nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: name, Server: server}
		}
		records = append(records, &SRVRecord{
			Name:     h.Name.String(),
			TTL:      h.TTL,
			Priority: srv.Priority,
			Weight:   srv.Weight,
			Port:     srv.Port,
			Target:   srv.Target.String(),
		})
	}
	sortSRVRecords(records)
	return cname, records, nil
}

// goLookupPTR issues a PTR query for the reverse DNS name of addr.
// PTR has no proto body type yet, so this returns plain target strings.
func (r *Resolver) goLookupPTR(ctx context.Context, addr string, conf *dnsConfig) ([]string, error) {
	if names := lookupStaticAddr(addr); len(names) > 0 {
		return names, nil
	}
	arpa, err := reverseaddr(addr)
	if err != nil {
		return nil, err
	}
	p, server, err := r.lookup(ctx, arpa, dnsmessage.TypePTR, conf)
	if err != nil {
		return nil, err
	}
	var out []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: addr, Server: server}
		}
		if h.Type != dnsmessage.TypePTR {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: addr, Server: server}
			}
			continue
		}
		ptr, err := p.PTRResource()
		if err != nil {
			return nil, &net.DNSError{Err: errCannotUnmarshalDNSMessage.Error(), Name: addr, Server: server}
		}
		out = append(out, ptr.PTR.String())
	}
	return out, nil
}
