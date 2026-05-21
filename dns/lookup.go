// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from $GOROOT/src/net/lookup.go (the Resolver.LookupX public
// methods). See ./README.md for fork policy.
//
// Differences from upstream:
//
//   - All Lookup* methods return []*domainpb.DNSRecord with the typed
//     body populated. Upstream returns TTL-less stdlib types; we
//     expose the wire-faithful proto schema directly so callers don't
//     need a translation layer.
//   - LookupPort is omitted (it's an /etc/services lookup, not DNS).
//   - LookupHost / LookupIP / LookupNetIP wrappers omitted; callers
//     can read the IP off the returned ARecord / AAAARecord body.
//   - No singleflight dedup (cheap to add later via golang.org/x/sync
//     if we observe duplicate concurrent lookups in practice).

package dns

import (
	"context"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// RR type codes not defined by golang.org/x/net/dns/dnsmessage.
const (
	TypeRP    dnsmessage.Type = 17
	TypeAFSDB dnsmessage.Type = 18
	TypeLOC   dnsmessage.Type = 29
	TypeNAPTR dnsmessage.Type = 35
	TypeKX    dnsmessage.Type = 36
	TypeDNAME dnsmessage.Type = 39
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
func parseSVCBParams(data []byte, off int) ([]*domainpb.SvcbParam, bool) {
	var params []*domainpb.SvcbParam
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
		params = append(params, &domainpb.SvcbParam{Key: uint32(key), Value: val})
		off += vlen
	}
	return params, true
}

// newRecord constructs a DNSRecord with type and ttl from the wire header
// and the supplied typed body case. Target and Class are caller-owned
// (see internal/resolver/resolver.go).
func newRecord(h dnsmessage.ResourceHeader, t domainpb.DNSRecordType, body isDNSRecordBody) *domainpb.DNSRecord {
	rec := &domainpb.DNSRecord{Type: t, TtlSeconds: int32(h.TTL)}
	switch b := body.(type) {
	case *domainpb.ARecord:
		rec.Body = &domainpb.DNSRecord_A{A: b}
	case *domainpb.AAAARecord:
		rec.Body = &domainpb.DNSRecord_Aaaa{Aaaa: b}
	case *domainpb.CNAMERecord:
		rec.Body = &domainpb.DNSRecord_Cname{Cname: b}
	case *domainpb.DNAMERecord:
		rec.Body = &domainpb.DNSRecord_Dname{Dname: b}
	case *domainpb.NSRecord:
		rec.Body = &domainpb.DNSRecord_Ns{Ns: b}
	case *domainpb.MXRecord:
		rec.Body = &domainpb.DNSRecord_Mx{Mx: b}
	case *domainpb.TXTRecord:
		rec.Body = &domainpb.DNSRecord_Txt{Txt: b}
	case *domainpb.SOARecord:
		rec.Body = &domainpb.DNSRecord_Soa{Soa: b}
	case *domainpb.LOCRecord:
		rec.Body = &domainpb.DNSRecord_Loc{Loc: b}
	case *domainpb.HINFORecord:
		rec.Body = &domainpb.DNSRecord_Hinfo{Hinfo: b}
	case *domainpb.RPRecord:
		rec.Body = &domainpb.DNSRecord_Rp{Rp: b}
	case *domainpb.AFSDBRecord:
		rec.Body = &domainpb.DNSRecord_Afsdb{Afsdb: b}
	case *domainpb.NAPTRRecord:
		rec.Body = &domainpb.DNSRecord_Naptr{Naptr: b}
	case *domainpb.KXRecord:
		rec.Body = &domainpb.DNSRecord_Kx{Kx: b}
	case *domainpb.SSHFPRecord:
		rec.Body = &domainpb.DNSRecord_Sshfp{Sshfp: b}
	case *domainpb.SVCBRecord:
		rec.Body = &domainpb.DNSRecord_Svcb{Svcb: b}
	case *domainpb.HTTPSRecord:
		rec.Body = &domainpb.DNSRecord_Https{Https: b}
	case *domainpb.CAARecord:
		rec.Body = &domainpb.DNSRecord_Caa{Caa: b}
	case *domainpb.URIRecord:
		rec.Body = &domainpb.DNSRecord_Uri{Uri: b}
	}
	return rec
}

// isDNSRecordBody is the local marker for typed body messages. Each
// per-type proto message satisfies it implicitly via being a possible
// argument to newRecord. (We can't reference domainpb's unexported
// isDNSRecord_Body interface from outside that package.)
type isDNSRecordBody any

// SRVRecord is the only typed body proto-domain still keeps outside of
// domainpb. SRV isn't emitted by GetDNSRecords (it requires a service-
// prefixed query name, not the apex), but the LookupSRV API is exposed
// for direct callers — and proto-domain hasn't yet added an SRVRecord
// proto message. When that changes, this type can move to domainpb
// and the SRV-specific paths in sort.go can use the proto body.
type SRVRecord struct {
	Name     string
	TTL      uint32
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// LookupRecords is the generic entry point: send a single query for
// `qtype` against the system resolver, return every matching record
// from the answer section. Body cases match the type.
func (r *Resolver) LookupRecords(ctx context.Context, name string, qtype dnsmessage.Type) ([]*domainpb.DNSRecord, error) {
	conf := getSystemDNSConfig()
	p, server, err := r.lookup(ctx, name, qtype, conf)
	if err != nil {
		return nil, err
	}
	return parseGenericAnswers(&p, server, name, qtype)
}

// parseGenericAnswers walks the answer section and returns one DNSRecord
// per RR matching qtype. Unsupported types are skipped silently.
func parseGenericAnswers(p *dnsmessage.Parser, server, name string, qtype dnsmessage.Type) ([]*domainpb.DNSRecord, error) {
	var out []*domainpb.DNSRecord
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
		switch h.Type {
		case dnsmessage.TypeA:
			body, err := p.AResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_A,
				&domainpb.ARecord{Ipv4: append([]byte(nil), body.A[:]...)}))
		case dnsmessage.TypeAAAA:
			body, err := p.AAAAResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_AAAA,
				&domainpb.AAAARecord{Ipv6: append([]byte(nil), body.AAAA[:]...)}))
		case dnsmessage.TypeCNAME:
			body, err := p.CNAMEResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_CNAME,
				&domainpb.CNAMERecord{Target: body.CNAME.String()}))
		case TypeDNAME:
			raw, err := p.UnknownResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			target, _, ok := parseWireName(raw.Data, 0)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_DNAME,
				&domainpb.DNAMERecord{Target: target}))
		case dnsmessage.TypeNS:
			body, err := p.NSResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_NS,
				&domainpb.NSRecord{Host: body.NS.String()}))
		case dnsmessage.TypeMX:
			body, err := p.MXResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_MX,
				&domainpb.MXRecord{Pref: uint32(body.Pref), Host: body.MX.String()}))
		case dnsmessage.TypeTXT:
			body, err := p.TXTResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_TXT,
				&domainpb.TXTRecord{Strings: append([]string(nil), body.TXT...)}))
		case dnsmessage.TypePTR:
			// PTR has no proto body type; skip. PTRs come back via
			// LookupPTR, which has its own custom path.
			if err := p.SkipAnswer(); err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
		case dnsmessage.TypeSOA:
			body, err := p.SOAResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_SOA,
				&domainpb.SOARecord{
					Ns:      body.NS.String(),
					Mbox:    body.MBox.String(),
					Serial:  body.Serial,
					Refresh: body.Refresh,
					Retry:   body.Retry,
					Expire:  body.Expire,
					MinTtl:  body.MinTTL,
				}))
		case dnsmessage.TypeHINFO:
			raw, err := p.UnknownResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			cpu, off, ok := parseCharString(raw.Data, 0)
			os_, _, ok2 := parseCharString(raw.Data, off)
			if !ok || !ok2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_HINFO,
				&domainpb.HINFORecord{Cpu: cpu, Os: os_}))
		case TypeRP:
			raw, err := p.UnknownResource()
			if err != nil {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			mbox, off, ok := parseWireName(raw.Data, 0)
			txt, _, ok2 := parseWireName(raw.Data, off)
			if !ok || !ok2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_RP,
				&domainpb.RPRecord{Mbox: mbox, Txt: txt}))
		case TypeAFSDB:
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			subtype := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			host, _, ok := parseWireName(raw.Data, 2)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_AFSDB,
				&domainpb.AFSDBRecord{Subtype: uint32(subtype), Hostname: host}))
		case TypeLOC:
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 16 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			d := raw.Data
			u32 := func(i int) uint32 {
				return uint32(d[i])<<24 | uint32(d[i+1])<<16 | uint32(d[i+2])<<8 | uint32(d[i+3])
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_LOC,
				&domainpb.LOCRecord{
					Version:   uint32(d[0]),
					Size:      uint32(d[1]),
					HorizPre:  uint32(d[2]),
					VertPre:   uint32(d[3]),
					Latitude:  u32(4),
					Longitude: u32(8),
					Altitude:  u32(12),
				}))
		case TypeNAPTR:
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
			out = append(out, newRecord(h, domainpb.DNSRecordType_NAPTR,
				&domainpb.NAPTRRecord{
					Order:       uint32(order),
					Preference:  uint32(pref),
					Flags:       flags,
					Service:     svc,
					Regexp:      re,
					Replacement: repl,
				}))
		case TypeKX:
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			pref := uint16(raw.Data[0])<<8 | uint16(raw.Data[1])
			host, _, ok := parseWireName(raw.Data, 2)
			if !ok {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_KX,
				&domainpb.KXRecord{Preference: uint32(pref), Exchanger: host}))
		case TypeSSHFP:
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 2 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			fp := make([]byte, len(raw.Data)-2)
			copy(fp, raw.Data[2:])
			out = append(out, newRecord(h, domainpb.DNSRecordType_SSHFP,
				&domainpb.SSHFPRecord{
					Algorithm:   uint32(raw.Data[0]),
					FpType:      uint32(raw.Data[1]),
					Fingerprint: fp,
				}))
		case TypeSVCB:
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
			out = append(out, newRecord(h, domainpb.DNSRecordType_SVCB,
				&domainpb.SVCBRecord{Priority: uint32(pri), TargetName: target, Params: params}))
		case TypeHTTPS:
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
			out = append(out, newRecord(h, domainpb.DNSRecordType_HTTPS,
				&domainpb.HTTPSRecord{Priority: uint32(pri), TargetName: target, Params: params}))
		case TypeCAA:
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
			out = append(out, newRecord(h, domainpb.DNSRecordType_CAA,
				&domainpb.CAARecord{Flags: uint32(flags), Tag: tag, Value: value}))
		case TypeURI:
			raw, err := p.UnknownResource()
			if err != nil || len(raw.Data) < 4 {
				return nil, newDNSError(errCannotUnmarshalDNSMessage, name, server)
			}
			out = append(out, newRecord(h, domainpb.DNSRecordType_URI,
				&domainpb.URIRecord{
					Priority: uint32(uint16(raw.Data[0])<<8 | uint16(raw.Data[1])),
					Weight:   uint32(uint16(raw.Data[2])<<8 | uint16(raw.Data[3])),
					Target:   string(raw.Data[4:]),
				}))
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

// LookupIP returns A and AAAA records for name. Each result has a Body
// of *DNSRecord_A or *DNSRecord_Aaaa; callers can switch.
func (r *Resolver) LookupIP(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	recs, _, err := r.goLookupIPCNAMEOrder(ctx, "ip", name, nil)
	return recs, err
}

// LookupCNAME returns the canonical name of a host. Equivalent to
// upstream's net.Resolver.LookupCNAME but reports an empty string when
// no CNAME chain was followed.
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return r.goLookupCNAME(ctx, host, nil)
}

// LookupNS returns NS records for name.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.goLookupNS(ctx, name, nil)
}

// LookupMX returns MX records for name, sorted by preference.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.goLookupMX(ctx, name, nil)
}

// LookupTXT returns TXT records for name. Each record's TXTRecord.Strings
// carries the raw character-string fragments from the wire.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.goLookupTXT(ctx, name, nil)
}

// LookupSRV returns SRV records for an _<service>._<proto>.<name>
// query (or for `name` directly when both service and proto are
// empty). The returned records are sorted by priority + weight.
// `cname` echoes any CNAME the answer chain reported.
//
// SRV isn't in the proto's body oneof yet, so this still returns the
// local SRVRecord shape rather than *domainpb.DNSRecord.
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (cname string, records []*SRVRecord, err error) {
	return r.goLookupSRV(ctx, service, proto, name, nil)
}

// LookupPTR returns PTR records for an IP literal (reverse DNS).
// PTR isn't in the proto's body oneof yet, so this returns presentation-
// form target strings directly.
func (r *Resolver) LookupPTR(ctx context.Context, addr string) ([]string, error) {
	return r.goLookupPTR(ctx, addr, nil)
}

// LookupSOA returns SOA records for name.
func (r *Resolver) LookupSOA(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, dnsmessage.TypeSOA)
}

// LookupLOC returns LOC records (RFC 1876) for name.
func (r *Resolver) LookupLOC(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeLOC)
}

// LookupHINFO returns HINFO records (RFC 1035 §3.3.2) for name.
func (r *Resolver) LookupHINFO(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, dnsmessage.TypeHINFO)
}

// LookupRP returns RP records (RFC 1183) for name.
func (r *Resolver) LookupRP(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeRP)
}

// LookupAFSDB returns AFSDB records (RFC 1183) for name.
func (r *Resolver) LookupAFSDB(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeAFSDB)
}

// LookupNAPTR returns NAPTR records (RFC 3403) for name.
func (r *Resolver) LookupNAPTR(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeNAPTR)
}

// LookupKX returns KX records (RFC 2230) for name.
func (r *Resolver) LookupKX(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeKX)
}

// LookupSSHFP returns SSHFP records (RFC 4255) for name.
func (r *Resolver) LookupSSHFP(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeSSHFP)
}

// LookupSVCB returns SVCB records (RFC 9460) for name.
func (r *Resolver) LookupSVCB(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeSVCB)
}

// LookupHTTPS returns HTTPS records (RFC 9460) for name.
func (r *Resolver) LookupHTTPS(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeHTTPS)
}

// LookupCAA returns CAA records (RFC 8659) for name.
func (r *Resolver) LookupCAA(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeCAA)
}

// LookupURI returns URI records (RFC 7553) for name.
func (r *Resolver) LookupURI(ctx context.Context, name string) ([]*domainpb.DNSRecord, error) {
	return r.LookupRecords(ctx, name, TypeURI)
}
