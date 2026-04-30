// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from $GOROOT/src/net/lookup.go (the Resolver.LookupX public
// methods). See ./README.md for fork policy.
//
// Differences from upstream:
//
//   - All Lookup* methods return TTL-aware typed records (defined in
//     records.go). Upstream returns TTL-less stdlib types — we expose
//     full Header on every record.
//   - LookupPort is omitted (it's an /etc/services lookup, not DNS).
//   - LookupHost / LookupIP / LookupNetIP wrappers omitted; callers
//     can read the IP off the returned ARecord / AAAARecord.
//   - No singleflight dedup (cheap to add later via golang.org/x/sync
//     if we observe duplicate concurrent lookups in practice).
//
// Material changes vs upstream are flagged with "// fork:" comments.

package dns

import (
	"context"

	"golang.org/x/net/dns/dnsmessage"
)

// LookupRecords is the generic entry point: send a single query for
// `qtype` against the system resolver, return every matching record
// from the answer section with TTLs preserved.
//
// Use this when you need a record type the typed Lookup* methods
// don't cover, or when you want a homogeneous []Record to walk
// generically (caching, rendering, validation).
func (r *Resolver) LookupRecords(ctx context.Context, name string, qtype dnsmessage.Type) ([]Record, error) {
	conf := getSystemDNSConfig()
	p, server, err := r.lookup(ctx, name, qtype, conf)
	if err != nil {
		return nil, err
	}
	return parseGenericAnswers(&p, server, name, qtype)
}

// parseGenericAnswers walks the answer section and returns one typed
// Record per RR matching qtype. Unsupported types are skipped silently
// — callers that need every type should use a typed Lookup* method
// (until we add records for the long-tail types in Layer 3).
func parseGenericAnswers(p *dnsmessage.Parser, server, name string, qtype dnsmessage.Type) ([]Record, error) {
	var out []Record
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return out, nil
		}
		if err != nil {
			return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
		}
		if h.Type != qtype {
			if err := p.SkipAnswer(); err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			continue
		}
		hdr := Header{Name: h.Name.String(), Type: h.Type, Class: h.Class, TTL: h.TTL}
		switch h.Type {
		case dnsmessage.TypeA:
			body, err := p.AResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &ARecord{Header: hdr, IP: body.A[:]})
		case dnsmessage.TypeAAAA:
			body, err := p.AAAAResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &AAAARecord{Header: hdr, IP: body.AAAA[:]})
		case dnsmessage.TypeCNAME:
			body, err := p.CNAMEResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &CNAMERecord{Header: hdr, Target: body.CNAME.String()})
		case dnsmessage.TypeNS:
			body, err := p.NSResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &NSRecord{Header: hdr, Host: body.NS.String()})
		case dnsmessage.TypeMX:
			body, err := p.MXResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &MXRecord{Header: hdr, Pref: body.Pref, Host: body.MX.String()})
		case dnsmessage.TypeTXT:
			body, err := p.TXTResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &TXTRecord{Header: hdr, Strings: append([]string(nil), body.TXT...)})
		case dnsmessage.TypeSRV:
			body, err := p.SRVResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &SRVRecord{
				Header: hdr, Priority: body.Priority, Weight: body.Weight,
				Port: body.Port, Target: body.Target.String(),
			})
		case dnsmessage.TypePTR:
			body, err := p.PTRResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &PTRRecord{Header: hdr, Target: body.PTR.String()})
		default:
			// Unknown type for our typed records. Skip — long-tail
			// record types will plug in here once Layer 3 lands.
			if err := p.SkipAnswer(); err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
		}
	}
}

// DefaultResolver is a usable Resolver with no fields set. Mirrors
// upstream's net.DefaultResolver convenience.
var DefaultResolver = &Resolver{}

// LookupA returns A (IPv4) records for name with TTLs preserved.
// Equivalent to calling LookupRecords with dnsmessage.TypeA, but
// type-narrowed to []*ARecord at the API.
func (r *Resolver) LookupA(ctx context.Context, name string) ([]*ARecord, error) {
	recs, _, err := r.goLookupIPCNAMEOrder(ctx, "ip4", name, nil)
	if err != nil {
		return nil, err
	}
	out := make([]*ARecord, 0, len(recs))
	for _, rec := range recs {
		if a, ok := rec.(*ARecord); ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// LookupAAAA returns AAAA (IPv6) records for name with TTLs preserved.
func (r *Resolver) LookupAAAA(ctx context.Context, name string) ([]*AAAARecord, error) {
	recs, _, err := r.goLookupIPCNAMEOrder(ctx, "ip6", name, nil)
	if err != nil {
		return nil, err
	}
	out := make([]*AAAARecord, 0, len(recs))
	for _, rec := range recs {
		if aaaa, ok := rec.(*AAAARecord); ok {
			out = append(out, aaaa)
		}
	}
	return out, nil
}

// LookupIP returns A and AAAA records for name with TTLs preserved.
// Returned records are *ARecord or *AAAARecord; callers can type-switch.
func (r *Resolver) LookupIP(ctx context.Context, name string) ([]Record, error) {
	recs, _, err := r.goLookupIPCNAMEOrder(ctx, "ip", name, nil)
	return recs, err
}

// LookupCNAME returns the canonical name of a host. Equivalent to
// upstream's net.Resolver.LookupCNAME but reports an empty string when
// no CNAME chain was followed (rather than echoing the queried name —
// upstream-quirk we don't replicate).
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r.goLookupCNAME(ctx, host, nil)
}

// LookupNS returns NS records for name with TTLs preserved.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*NSRecord, error) {
	return r.goLookupNS(ctx, name, nil)
}

// LookupMX returns MX records for name, sorted by preference, with
// TTLs preserved.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*MXRecord, error) {
	return r.goLookupMX(ctx, name, nil)
}

// LookupTXT returns TXT records for name with TTLs preserved. Each
// returned record's Strings field carries the raw character-string
// fragments from the wire (most TXT records have exactly one).
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]*TXTRecord, error) {
	return r.goLookupTXT(ctx, name, nil)
}

// LookupSRV returns SRV records for an _<service>._<proto>.<name>
// query (or for `name` directly when both service and proto are
// empty). The returned records are sorted by priority + weight.
// `cname` echoes any CNAME the answer chain reported.
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (cname string, records []*SRVRecord, err error) {
	return r.goLookupSRV(ctx, service, proto, name, nil)
}

// LookupPTR returns PTR records for an IP literal (reverse DNS) with
// TTLs preserved. Tries /etc/hosts first; falls back to the in-addr.arpa
// or ip6.arpa name on the system resolver.
func (r *Resolver) LookupPTR(ctx context.Context, addr string) ([]*PTRRecord, error) {
	return r.goLookupPTR(ctx, addr, nil)
}
