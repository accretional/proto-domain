// Package resolver implements the proto-domain Resolver gRPC service
// against the dns/ stdlib fork (which exposes per-record TTLs).
//
// Behavior:
//   - Default *dns.Resolver, so we follow the same DNS path the host
//     itself uses (/etc/resolv.conf, /etc/hosts) — minus cgo and
//     Windows. See dns/COVERAGE.md for what's covered. NewWithUpstream
//     overrides this to force all queries at a single addr, used to
//     point at a local recursive resolver without touching resolv.conf.
//   - All queries are issued as fully-qualified names (trailing dot) so
//     that nameList() skips /etc/resolv.conf search-domain suffix
//     expansion — which otherwise doubles UDP round-trips for NXDOMAIN.
//   - Queried types: A/AAAA, CNAME, DNAME, NS, MX, TXT, SOA, LOC,
//     HINFO, RP, AFSDB, NAPTR, KX, SSHFP, SVCB, HTTPS, CAA, URI.
//     TLSA omitted (canonical owner is _<port>._<proto>.<host>, not
//     the apex). DNSSEC types (DS, DNSKEY, RRSIG, NSEC, NSEC3, CDS,
//     CDNSKEY) intentionally excluded — see proto-domain Task #20.
//   - Lookups are issued sequentially. Per-domain fanout was tested
//     (see proto-ct bench_fanout.sh on 2026-05-20) and consistently
//     lost to sequential — the bottleneck is the upstream resolver,
//     not our orchestration, and a fast upstream (local unbound)
//     benefits from sequential cache locality.
//   - Each emitted DNSRecord carries a typed body in the proto schema
//     — no presentation-form string. Clients walk the body oneof to
//     access wire-faithful fields.
//   - "No records" / NXDOMAIN per type is silently skipped.
package resolver

import (
	"context"
	"errors"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/accretional/proto-domain/dns"
	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// Service implements pb.ResolverServer. Wired up by cmd/server.
type Service struct {
	domainpb.UnimplementedResolverServer

	// resolver is the underlying dns.Resolver. nil falls back to
	// dns.DefaultResolver, which uses the host's /etc/resolv.conf.
	resolver *dns.Resolver
}

// New returns a Service backed by the host resolver.
func New() *Service { return &Service{} }

// NewWithUpstream returns a Service that forces every DNS query to the
// supplied address (e.g. "127.0.0.1:5353"), bypassing the system
// resolver list. Used to point dnsfetch at a local recursive resolver
// without modifying /etc/resolv.conf.
func NewWithUpstream(upstream string) *Service {
	r := &dns.Resolver{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream)
		},
	}
	return &Service{resolver: r}
}

// recordSink is the surface GetDNSRecords needs from its output. The
// real gRPC stream satisfies it; tests substitute an in-memory sink.
type recordSink interface {
	Send(*domainpb.DNSRecord) error
}

// GetDNSRecords streams every DNSRecord the host resolver returns for
// the supplied Domain, across all record types we support.
func (s *Service) GetDNSRecords(req *domainpb.Domain, srv domainpb.Resolver_GetDNSRecordsServer) error {
	return s.resolveStream(srv.Context(), req, srv)
}

func (s *Service) resolveStream(ctx context.Context, req *domainpb.Domain, out recordSink) error {
	if req == nil {
		return errors.New("resolver: nil Domain")
	}
	name := canonicalName(req)
	if name == "" {
		return errors.New("resolver: empty Domain")
	}
	r := s.resolver
	if r == nil {
		r = dns.DefaultResolver
	}

	// send fills in the common fields (target/class) on a DNSRecord
	// that the caller has already populated with type, ttl, and body,
	// then hands it to the gRPC stream. Inlining body construction at
	// each call site keeps the oneof case local and avoids needing to
	// plumb the unexported isDNSRecord_Body interface.
	send := func(rec *domainpb.DNSRecord) error {
		rec.Target = req
		rec.Class = domainpb.Class_Internet
		return out.Send(rec)
	}

	// A + AAAA via the typed IP lookup.
	if recs, err := r.LookupIP(ctx, name); err == nil {
		for _, rec := range recs {
			switch v := rec.(type) {
			case *dns.ARecord:
				ip4 := v.IP.To4()
				if ip4 == nil {
					continue
				}
				if err := send(&domainpb.DNSRecord{
					Type:       domainpb.DNSRecordType_A,
					TtlSeconds: int32(v.TTL),
					Body:       &domainpb.DNSRecord_A{A: &domainpb.ARecord{Ipv4: ip4}},
				}); err != nil {
					return err
				}
			case *dns.AAAARecord:
				ip16 := v.IP.To16()
				if ip16 == nil {
					continue
				}
				if err := send(&domainpb.DNSRecord{
					Type:       domainpb.DNSRecordType_AAAA,
					TtlSeconds: int32(v.TTL),
					Body:       &domainpb.DNSRecord_Aaaa{Aaaa: &domainpb.AAAARecord{Ipv6: ip16}},
				}); err != nil {
					return err
				}
			}
		}
	}

	if recs, err := r.LookupRecords(ctx, name, dnsmessage.TypeCNAME); err == nil {
		for _, rec := range recs {
			cr, ok := rec.(*dns.CNAMERecord)
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSuffix(cr.Target, "."), strings.TrimSuffix(name, ".")) {
				continue
			}
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_CNAME,
				TtlSeconds: int32(cr.TTL),
				Body:       &domainpb.DNSRecord_Cname{Cname: &domainpb.CNAMERecord{Target: cr.Target}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupRecords(ctx, name, dns.TypeDNAME); err == nil {
		for _, rec := range recs {
			dr, ok := rec.(*dns.DNAMERecord)
			if !ok {
				continue
			}
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_DNAME,
				TtlSeconds: int32(dr.TTL),
				Body:       &domainpb.DNSRecord_Dname{Dname: &domainpb.DNAMERecord{Target: dr.Target}},
			}); err != nil {
				return err
			}
		}
	}

	if nss, err := r.LookupNS(ctx, name); err == nil {
		for _, ns := range nss {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_NS,
				TtlSeconds: int32(ns.TTL),
				Body:       &domainpb.DNSRecord_Ns{Ns: &domainpb.NSRecord{Host: ns.Host}},
			}); err != nil {
				return err
			}
		}
	}

	if mxs, err := r.LookupMX(ctx, name); err == nil {
		for _, mx := range mxs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_MX,
				TtlSeconds: int32(mx.TTL),
				Body:       &domainpb.DNSRecord_Mx{Mx: &domainpb.MXRecord{Pref: uint32(mx.Pref), Host: mx.Host}},
			}); err != nil {
				return err
			}
		}
	}

	if txts, err := r.LookupTXT(ctx, name); err == nil {
		for _, txt := range txts {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_TXT,
				TtlSeconds: int32(txt.TTL),
				Body:       &domainpb.DNSRecord_Txt{Txt: &domainpb.TXTRecord{Strings: append([]string(nil), txt.Strings...)}},
			}); err != nil {
				return err
			}
		}
	}

	if soas, err := r.LookupSOA(ctx, name); err == nil {
		for _, soa := range soas {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_SOA,
				TtlSeconds: int32(soa.TTL),
				Body: &domainpb.DNSRecord_Soa{Soa: &domainpb.SOARecord{
					Ns:      soa.NS,
					Mbox:    soa.MBox,
					Serial:  soa.Serial,
					Refresh: soa.Refresh,
					Retry:   soa.Retry,
					Expire:  soa.Expire,
					MinTtl:  soa.MinTTL,
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupLOC(ctx, name); err == nil {
		for _, l := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_LOC,
				TtlSeconds: int32(l.TTL),
				Body: &domainpb.DNSRecord_Loc{Loc: &domainpb.LOCRecord{
					Version:   uint32(l.Version),
					Size:      uint32(l.Size),
					HorizPre:  uint32(l.HorizPre),
					VertPre:   uint32(l.VertPre),
					Latitude:  l.Latitude,
					Longitude: l.Longitude,
					Altitude:  l.Altitude,
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupHINFO(ctx, name); err == nil {
		for _, h := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_HINFO,
				TtlSeconds: int32(h.TTL),
				Body:       &domainpb.DNSRecord_Hinfo{Hinfo: &domainpb.HINFORecord{Cpu: h.CPU, Os: h.OS}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupRP(ctx, name); err == nil {
		for _, rp := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_RP,
				TtlSeconds: int32(rp.TTL),
				Body:       &domainpb.DNSRecord_Rp{Rp: &domainpb.RPRecord{Mbox: rp.Mbox, Txt: rp.Txt}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupAFSDB(ctx, name); err == nil {
		for _, a := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_AFSDB,
				TtlSeconds: int32(a.TTL),
				Body: &domainpb.DNSRecord_Afsdb{Afsdb: &domainpb.AFSDBRecord{
					Subtype: uint32(a.Subtype), Hostname: a.Hostname,
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupNAPTR(ctx, name); err == nil {
		for _, n := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_NAPTR,
				TtlSeconds: int32(n.TTL),
				Body: &domainpb.DNSRecord_Naptr{Naptr: &domainpb.NAPTRRecord{
					Order:       uint32(n.Order),
					Preference:  uint32(n.Preference),
					Flags:       n.Flags,
					Service:     n.Service,
					Regexp:      n.Regexp,
					Replacement: n.Replacement,
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupKX(ctx, name); err == nil {
		for _, kx := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_KX,
				TtlSeconds: int32(kx.TTL),
				Body: &domainpb.DNSRecord_Kx{Kx: &domainpb.KXRecord{
					Preference: uint32(kx.Preference), Exchanger: kx.Exchanger,
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupSSHFP(ctx, name); err == nil {
		for _, s := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_SSHFP,
				TtlSeconds: int32(s.TTL),
				Body: &domainpb.DNSRecord_Sshfp{Sshfp: &domainpb.SSHFPRecord{
					Algorithm:   uint32(s.Algorithm),
					FpType:      uint32(s.FpType),
					Fingerprint: append([]byte(nil), s.Fingerprint...),
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupSVCB(ctx, name); err == nil {
		for _, s := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_SVCB,
				TtlSeconds: int32(s.TTL),
				Body: &domainpb.DNSRecord_Svcb{Svcb: &domainpb.SVCBRecord{
					Priority:   uint32(s.Priority),
					TargetName: s.TargetName,
					Params:     toSvcbParams(s.Params),
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupHTTPS(ctx, name); err == nil {
		for _, h := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_HTTPS,
				TtlSeconds: int32(h.TTL),
				Body: &domainpb.DNSRecord_Https{Https: &domainpb.HTTPSRecord{
					Priority:   uint32(h.Priority),
					TargetName: h.TargetName,
					Params:     toSvcbParams(h.Params),
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupCAA(ctx, name); err == nil {
		for _, c := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_CAA,
				TtlSeconds: int32(c.TTL),
				Body: &domainpb.DNSRecord_Caa{Caa: &domainpb.CAARecord{
					Flags: uint32(c.Flags), Tag: c.Tag, Value: c.Value,
				}},
			}); err != nil {
				return err
			}
		}
	}

	if recs, err := r.LookupURI(ctx, name); err == nil {
		for _, u := range recs {
			if err := send(&domainpb.DNSRecord{
				Type:       domainpb.DNSRecordType_URI,
				TtlSeconds: int32(u.TTL),
				Body: &domainpb.DNSRecord_Uri{Uri: &domainpb.URIRecord{
					Priority: uint32(u.Priority),
					Weight:   uint32(u.Weight),
					Target:   u.Target,
				}},
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// toSvcbParams converts wire-parse SVCB params to proto form.
func toSvcbParams(in []dns.SVCBParam) []*domainpb.SvcbParam {
	if len(in) == 0 {
		return nil
	}
	out := make([]*domainpb.SvcbParam, len(in))
	for i, p := range in {
		out[i] = &domainpb.SvcbParam{Key: uint32(p.Key), Value: append([]byte(nil), p.Value...)}
	}
	return out
}

// canonicalName recovers the queryable string from a Domain message and
// ensures it is fully-qualified (trailing dot). A rooted name causes
// nameList() to return a single-entry slice, skipping /etc/resolv.conf
// search-domain suffix expansion which otherwise doubles UDP round-trips
// for every NXDOMAIN response.
func canonicalName(d *domainpb.Domain) string {
	parts := make([]string, 0, len(d.GetLabels())+1)
	parts = append(parts, d.GetLabels()...)
	if t := tldString(d.GetTld()); t != "" {
		parts = append(parts, t)
	}
	var name string
	if len(parts) == 0 {
		name = strings.TrimSuffix(d.GetHostname(), ".")
	} else {
		name = strings.Join(parts, ".")
	}
	if name == "" {
		return ""
	}
	return name + "."
}

func tldString(t *domainpb.TLD) string {
	if t == nil {
		return ""
	}
	switch v := t.GetFormat().(type) {
	case *domainpb.TLD_Internet:
		if v.Internet == domainpb.InternetTLD_COM {
			return "com"
		}
	case *domainpb.TLD_Custom:
		return v.Custom
	}
	return ""
}
