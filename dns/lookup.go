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
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// RR type codes not defined by golang.org/x/net/dns/dnsmessage.
const (
	TypeRP    dnsmessage.Type = 17
	TypeAFSDB dnsmessage.Type = 18
	TypeDNAME dnsmessage.Type = 39
	TypeNAPTR dnsmessage.Type = 35
	TypeKX    dnsmessage.Type = 36
	TypeSSHFP dnsmessage.Type = 44
	TypeTLSA  dnsmessage.Type = 52
	TypeSVCB  dnsmessage.Type = 64
	TypeHTTPS dnsmessage.Type = 65
	TypeCAA   dnsmessage.Type = 257
	TypeURI   dnsmessage.Type = 256
)

// parseCharString reads a length-prefixed DNS character-string from data[off:]
// and returns the string and the new offset. ok is false on truncation.
func parseCharString(data []byte, off int) (s string, newOff int, ok bool) {
	if off >= len(data) {
		return "", off, false
	}
	n := int(data[off])
	off++
	if off+n > len(data) {
		return "", off, false
	}
	return string(data[off : off+n]), off + n, true
}

// parseWireName reads a wire-format domain name from data[off:] without
// compression-pointer support (callers only have RDATA bytes, not the full
// message, so pointers cannot be resolved). Returns the presentation-form
// name (with trailing dot), the new offset, and ok=false on any error.
func parseWireName(data []byte, off int) (name string, newOff int, ok bool) {
	start := off
	var labels []string
	for {
		if off >= len(data) {
			return "", start, false
		}
		n := int(data[off])
		off++
		if n == 0 {
			break
		}
		if n >= 0xC0 { // compression pointer or extended label — need full message context
			return "", start, false
		}
		if off+n > len(data) {
			return "", start, false
		}
		labels = append(labels, string(data[off:off+n]))
		off += n
	}
	if len(labels) == 0 {
		return ".", off, true
	}
	return strings.Join(labels, ".") + ".", off, true
}

// parseSVCBParams reads SVCB/HTTPS SvcParams from data[off:end].
// Each param is: 2-byte key, 2-byte value-length, value bytes.
func parseSVCBParams(data []byte, off int) ([]SVCBParam, bool) {
	var params []SVCBParam
	for off < len(data) {
		if off+4 > len(data) {
			return nil, false
		}
		key := uint16(data[off])<<8 | uint16(data[off+1])
		vlen := int(uint16(data[off+2])<<8 | uint16(data[off+3]))
		off += 4
		if off+vlen > len(data) {
			return nil, false
		}
		val := make([]byte, vlen)
		copy(val, data[off:off+vlen])
		params = append(params, SVCBParam{Key: key, Value: val})
		off += vlen
	}
	return params, true
}

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
		case TypeDNAME:
			// RFC 6672: RDATA is a single domain name in wire format.
			raw, err := p.UnknownResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			target, _, ok := parseWireName(raw.Data, 0)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &DNAMERecord{Header: hdr, Target: target})
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
		case dnsmessage.TypeSOA:
			body, err := p.SOAResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &SOARecord{
				Header:  hdr,
				NS:      body.NS.String(),
				MBox:    body.MBox.String(),
				Serial:  body.Serial,
				Refresh: body.Refresh,
				Retry:   body.Retry,
				Expire:  body.Expire,
				MinTTL:  body.MinTTL,
			})
		case dnsmessage.TypeHINFO:
			// RFC 1035 §3.3.2: two character-strings (CPU, OS).
			raw, err := p.UnknownResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			cpu, off, ok := parseCharString(raw.Data, 0)
			os_, _, ok2 := parseCharString(raw.Data, off)
			if !ok || !ok2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &HINFORecord{Header: hdr, CPU: cpu, OS: os_})
		case TypeRP:
			// RFC 1183: two uncompressed wire-format names (mbox, txt).
			raw, err := p.UnknownResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			mbox, off, ok := parseWireName(raw.Data, 0)
			txt, _, ok2 := parseWireName(raw.Data, off)
			if !ok || !ok2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &RPRecord{Header: hdr, Mbox: mbox, Txt: txt})
		case TypeAFSDB:
			// RFC 1183: 2-byte subtype, uncompressed domain name.
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			subtype := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			host, _, ok := parseWireName(raw.Data, 2)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &AFSDBRecord{Header: hdr, Subtype: subtype, Hostname: host})
		case TypeNAPTR:
			// RFC 3403: order(2), preference(2), flags(cs), service(cs), regexp(cs), replacement(name).
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 4 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			order := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			pref := uint16(raw.Data[2])<<8 | uint16(raw.Data[3])
			flags, off, ok1 := parseCharString(raw.Data, 4)
			svc, off, ok2 := parseCharString(raw.Data, off)
			re, off, ok3 := parseCharString(raw.Data, off)
			repl, _, ok4 := parseWireName(raw.Data, off)
			if !ok1 || !ok2 || !ok3 || !ok4 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &NAPTRRecord{
				Header: hdr, Order: order, Preference: pref,
				Flags: flags, Service: svc, Regexp: re, Replacement: repl,
			})
		case TypeKX:
			// RFC 2230: 2-byte preference, uncompressed domain name.
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			pref := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			host, _, ok := parseWireName(raw.Data, 2)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &KXRecord{Header: hdr, Preference: pref, Exchanger: host})
		case TypeSSHFP:
			// RFC 4255: algorithm(1), fp_type(1), fingerprint(rest).
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			fp := make([]byte, len(raw.Data)-2)
			copy(fp, raw.Data[2:])
			out = append(out, &SSHFPRecord{
				Header: hdr, Algorithm: raw.Data[0], FpType: raw.Data[1], Fingerprint: fp,
			})
		case TypeTLSA:
			// RFC 6698: usage(1), selector(1), matching_type(1), cert_assoc_data(rest).
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 3 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			cad := make([]byte, len(raw.Data)-3)
			copy(cad, raw.Data[3:])
			out = append(out, &TLSARecord{
				Header: hdr, Usage: raw.Data[0], Selector: raw.Data[1],
				MatchingType: raw.Data[2], CertAssocData: cad,
			})
		case TypeSVCB:
			// RFC 9460: priority(2), target-name(wire), svcparams(rest).
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			pri := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			target, off, ok := parseWireName(raw.Data, 2)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			params, ok := parseSVCBParams(raw.Data, off)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &SVCBRecord{Header: hdr, Priority: pri, TargetName: target, Params: params})
		case TypeHTTPS:
			// RFC 9460: same wire format as SVCB, distinct RR type.
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			pri := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			target, off, ok := parseWireName(raw.Data, 2)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			params, ok := parseSVCBParams(raw.Data, off)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &HTTPSRecord{Header: hdr, Priority: pri, TargetName: target, Params: params})
		case TypeCAA:
			// RFC 8659: flags(1), tag-length(1), tag(tag-length bytes), value(rest).
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			flags := raw.Data[0]
			tagLen := int(raw.Data[1])
			if 2+tagLen > len(raw.Data) {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			tag := string(raw.Data[2 : 2+tagLen])
			value := string(raw.Data[2+tagLen:])
			out = append(out, &CAARecord{Header: hdr, Flags: flags, Tag: tag, Value: value})
		case TypeURI:
			// RFC 7553: priority(2), weight(2), target(rest).
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 4 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, &URIRecord{
				Header:   hdr,
				Priority: uint16(raw.Data[0])<<8 | uint16(raw.Data[1]),
				Weight:   uint16(raw.Data[2])<<8 | uint16(raw.Data[3]),
				Target:   string(raw.Data[4:]),
			})
		default:
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

// LookupSOA returns SOA records for name with TTLs preserved. Most zones
// have exactly one SOA; the slice form mirrors the other Lookup* methods.
func (r *Resolver) LookupSOA(ctx context.Context, name string) ([]*SOARecord, error) {
	recs, err := r.LookupRecords(ctx, name, dnsmessage.TypeSOA)
	if err != nil {
		return nil, err
	}
	out := make([]*SOARecord, 0, len(recs))
	for _, rec := range recs {
		if soa, ok := rec.(*SOARecord); ok {
			out = append(out, soa)
		}
	}
	return out, nil
}

// LookupHINFO returns HINFO records (RFC 1035 §3.3.2) for name.
func (r *Resolver) LookupHINFO(ctx context.Context, name string) ([]*HINFORecord, error) {
	recs, err := r.LookupRecords(ctx, name, dnsmessage.TypeHINFO)
	if err != nil {
		return nil, err
	}
	out := make([]*HINFORecord, 0, len(recs))
	for _, rec := range recs {
		if h, ok := rec.(*HINFORecord); ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// LookupRP returns RP records (RFC 1183) for name.
func (r *Resolver) LookupRP(ctx context.Context, name string) ([]*RPRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeRP)
	if err != nil {
		return nil, err
	}
	out := make([]*RPRecord, 0, len(recs))
	for _, rec := range recs {
		if rp, ok := rec.(*RPRecord); ok {
			out = append(out, rp)
		}
	}
	return out, nil
}

// LookupAFSDB returns AFSDB records (RFC 1183) for name.
func (r *Resolver) LookupAFSDB(ctx context.Context, name string) ([]*AFSDBRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeAFSDB)
	if err != nil {
		return nil, err
	}
	out := make([]*AFSDBRecord, 0, len(recs))
	for _, rec := range recs {
		if a, ok := rec.(*AFSDBRecord); ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// LookupNAPTR returns NAPTR records (RFC 3403) for name.
func (r *Resolver) LookupNAPTR(ctx context.Context, name string) ([]*NAPTRRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeNAPTR)
	if err != nil {
		return nil, err
	}
	out := make([]*NAPTRRecord, 0, len(recs))
	for _, rec := range recs {
		if n, ok := rec.(*NAPTRRecord); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// LookupKX returns KX records (RFC 2230) for name.
func (r *Resolver) LookupKX(ctx context.Context, name string) ([]*KXRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeKX)
	if err != nil {
		return nil, err
	}
	out := make([]*KXRecord, 0, len(recs))
	for _, rec := range recs {
		if kx, ok := rec.(*KXRecord); ok {
			out = append(out, kx)
		}
	}
	return out, nil
}

// LookupSSHFP returns SSHFP records (RFC 4255) for name.
func (r *Resolver) LookupSSHFP(ctx context.Context, name string) ([]*SSHFPRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeSSHFP)
	if err != nil {
		return nil, err
	}
	out := make([]*SSHFPRecord, 0, len(recs))
	for _, rec := range recs {
		if s, ok := rec.(*SSHFPRecord); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// LookupTLSA returns TLSA records (RFC 6698) for name. The conventional
// owner name for a service is _<port>._<proto>.<host> (e.g.
// "_443._tcp.example.com").
func (r *Resolver) LookupTLSA(ctx context.Context, name string) ([]*TLSARecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeTLSA)
	if err != nil {
		return nil, err
	}
	out := make([]*TLSARecord, 0, len(recs))
	for _, rec := range recs {
		if t, ok := rec.(*TLSARecord); ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// LookupSVCB returns SVCB records (RFC 9460) for name.
func (r *Resolver) LookupSVCB(ctx context.Context, name string) ([]*SVCBRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeSVCB)
	if err != nil {
		return nil, err
	}
	out := make([]*SVCBRecord, 0, len(recs))
	for _, rec := range recs {
		if s, ok := rec.(*SVCBRecord); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// LookupHTTPS returns HTTPS records (RFC 9460) for name.
func (r *Resolver) LookupHTTPS(ctx context.Context, name string) ([]*HTTPSRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeHTTPS)
	if err != nil {
		return nil, err
	}
	out := make([]*HTTPSRecord, 0, len(recs))
	for _, rec := range recs {
		if h, ok := rec.(*HTTPSRecord); ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// LookupCAA returns CAA records (RFC 8659) for name.
func (r *Resolver) LookupCAA(ctx context.Context, name string) ([]*CAARecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeCAA)
	if err != nil {
		return nil, err
	}
	out := make([]*CAARecord, 0, len(recs))
	for _, rec := range recs {
		if c, ok := rec.(*CAARecord); ok {
			out = append(out, c)
		}
	}
	return out, nil
}

// LookupURI returns URI records (RFC 7553) for name.
func (r *Resolver) LookupURI(ctx context.Context, name string) ([]*URIRecord, error) {
	recs, err := r.LookupRecords(ctx, name, TypeURI)
	if err != nil {
		return nil, err
	}
	out := make([]*URIRecord, 0, len(recs))
	for _, rec := range recs {
		if u, ok := rec.(*URIRecord); ok {
			out = append(out, u)
		}
	}
	return out, nil
}
