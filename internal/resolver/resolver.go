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
//   - "No records" / NXDOMAIN per type is silently skipped.
package resolver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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

	emit := func(t domainpb.DNSRecordType, ttl uint32, text string) error {
		return out.Send(&domainpb.DNSRecord{
			Type:       t,
			Target:     req,
			Class:      domainpb.Class_Internet,
			TtlSeconds: int32(ttl),
			Format:     &domainpb.DNSRecord_Text{Text: text},
		})
	}

	// A + AAAA via the typed IP lookup. dns.Resolver.LookupIP returns
	// []dns.Record (mix of *ARecord / *AAAARecord), each carrying its
	// own TTL.
	if recs, err := r.LookupIP(ctx, name); err == nil {
		for _, rec := range recs {
			switch v := rec.(type) {
			case *dns.ARecord:
				if err := emit(domainpb.DNSRecordType_A, v.TTL, v.IP.String()); err != nil {
					return err
				}
			case *dns.AAAARecord:
				if err := emit(domainpb.DNSRecordType_AAAA, v.TTL, v.IP.String()); err != nil {
					return err
				}
			}
		}
	}

	// CNAME — single LookupRecords call gives both target and TTL,
	// avoiding the original two-call (LookupCNAME + LookupRecords) path.
	if recs, err := r.LookupRecords(ctx, name, dnsmessage.TypeCNAME); err == nil {
		for _, rec := range recs {
			cr, ok := rec.(*dns.CNAMERecord)
			if !ok {
				continue
			}
			if !strings.EqualFold(strings.TrimSuffix(cr.Target, "."), strings.TrimSuffix(name, ".")) {
				if err := emit(domainpb.DNSRecordType_CNAME, cr.TTL, cr.Target); err != nil {
					return err
				}
			}
		}
	}

	// DNAME — RFC 6672: maps the entire subtree below the owner name.
	if recs, err := r.LookupRecords(ctx, name, dns.TypeDNAME); err == nil {
		for _, rec := range recs {
			dr, ok := rec.(*dns.DNAMERecord)
			if !ok {
				continue
			}
			if err := emit(domainpb.DNSRecordType_DNAME, dr.TTL, dr.Target); err != nil {
				return err
			}
		}
	}

	if nss, err := r.LookupNS(ctx, name); err == nil {
		for _, ns := range nss {
			if err := emit(domainpb.DNSRecordType_NS, ns.TTL, ns.Host); err != nil {
				return err
			}
		}
	}

	if mxs, err := r.LookupMX(ctx, name); err == nil {
		for _, mx := range mxs {
			if err := emit(domainpb.DNSRecordType_MX, mx.TTL, fmt.Sprintf("%d %s", mx.Pref, mx.Host)); err != nil {
				return err
			}
		}
	}

	if txts, err := r.LookupTXT(ctx, name); err == nil {
		for _, txt := range txts {
			joined := strings.Join(txt.Strings, "")
			if err := emit(domainpb.DNSRecordType_TXT, txt.TTL, joined); err != nil {
				return err
			}
		}
	}

	// SOA — zone file presentation: "<ns> <mbox> <serial> <refresh> <retry> <expire> <minttl>"
	if soas, err := r.LookupSOA(ctx, name); err == nil {
		for _, soa := range soas {
			text := fmt.Sprintf("%s %s %d %d %d %d %d",
				soa.NS, soa.MBox,
				soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.MinTTL)
			if err := emit(domainpb.DNSRecordType_SOA, soa.TTL, text); err != nil {
				return err
			}
		}
	}

	// LOC — RFC 1876, converted to "<lat-deg> <lon-deg> <alt-m>m size=<m> hp=<m> vp=<m>"
	if recs, err := r.LookupLOC(ctx, name); err == nil {
		for _, l := range recs {
			if err := emit(domainpb.DNSRecordType_LOC, l.TTL, locText(l)); err != nil {
				return err
			}
		}
	}

	// HINFO — RFC 1035 §3.3.2: "<cpu>" "<os>"
	if recs, err := r.LookupHINFO(ctx, name); err == nil {
		for _, h := range recs {
			if err := emit(domainpb.DNSRecordType_HINFO, h.TTL, fmt.Sprintf("%q %q", h.CPU, h.OS)); err != nil {
				return err
			}
		}
	}

	// RP — RFC 1183: <mbox> <txt>
	if recs, err := r.LookupRP(ctx, name); err == nil {
		for _, rp := range recs {
			if err := emit(domainpb.DNSRecordType_RP, rp.TTL, fmt.Sprintf("%s %s", rp.Mbox, rp.Txt)); err != nil {
				return err
			}
		}
	}

	// AFSDB — RFC 1183: <subtype> <hostname>
	if recs, err := r.LookupAFSDB(ctx, name); err == nil {
		for _, a := range recs {
			if err := emit(domainpb.DNSRecordType_AFSDB, a.TTL, fmt.Sprintf("%d %s", a.Subtype, a.Hostname)); err != nil {
				return err
			}
		}
	}

	// NAPTR — RFC 3403: <order> <preference> "<flags>" "<service>" "<regexp>" <replacement>
	if recs, err := r.LookupNAPTR(ctx, name); err == nil {
		for _, n := range recs {
			text := fmt.Sprintf("%d %d %q %q %q %s", n.Order, n.Preference, n.Flags, n.Service, n.Regexp, n.Replacement)
			if err := emit(domainpb.DNSRecordType_NAPTR, n.TTL, text); err != nil {
				return err
			}
		}
	}

	// KX — RFC 2230: <preference> <exchanger>
	if recs, err := r.LookupKX(ctx, name); err == nil {
		for _, kx := range recs {
			if err := emit(domainpb.DNSRecordType_KX, kx.TTL, fmt.Sprintf("%d %s", kx.Preference, kx.Exchanger)); err != nil {
				return err
			}
		}
	}

	// SSHFP — RFC 4255 presentation: <algorithm> <fptype> <hex-fingerprint>
	if recs, err := r.LookupSSHFP(ctx, name); err == nil {
		for _, s := range recs {
			text := fmt.Sprintf("%d %d %s", s.Algorithm, s.FpType, hex.EncodeToString(s.Fingerprint))
			if err := emit(domainpb.DNSRecordType_SSHFP, s.TTL, text); err != nil {
				return err
			}
		}
	}

	// SVCB — "<priority> <target> [key=hexval ...]"
	if recs, err := r.LookupSVCB(ctx, name); err == nil {
		for _, s := range recs {
			if err := emit(domainpb.DNSRecordType_SVCB, s.TTL, svcbText(s.Priority, s.TargetName, s.Params)); err != nil {
				return err
			}
		}
	}

	// HTTPS — same presentation as SVCB, distinct type
	if recs, err := r.LookupHTTPS(ctx, name); err == nil {
		for _, h := range recs {
			if err := emit(domainpb.DNSRecordType_HTTPS, h.TTL, svcbText(h.Priority, h.TargetName, h.Params)); err != nil {
				return err
			}
		}
	}

	// CAA — RFC 8659 presentation: <flags> <tag> "<value>"
	if recs, err := r.LookupCAA(ctx, name); err == nil {
		for _, c := range recs {
			if err := emit(domainpb.DNSRecordType_CAA, c.TTL, fmt.Sprintf("%d %s %q", c.Flags, c.Tag, c.Value)); err != nil {
				return err
			}
		}
	}

	// URI — RFC 7553 presentation: <priority> <weight> "<target>"
	if recs, err := r.LookupURI(ctx, name); err == nil {
		for _, u := range recs {
			if err := emit(domainpb.DNSRecordType_URI, u.TTL, fmt.Sprintf("%d %d %q", u.Priority, u.Weight, u.Target)); err != nil {
				return err
			}
		}
	}

	return nil
}

// locText converts a LOC record (RFC 1876) to a compact, parseable form
// preserving all wire fields: latitude and longitude as signed decimal
// degrees, altitude in meters, and the three precision bytes decoded
// to meters via locPrecision.
func locText(l *dns.LOCRecord) string {
	const latLonBias = 1 << 31   // equator / prime meridian
	const altBiasCm = 10_000_000 // so that 0 == -100 000 m
	latDeg := float64(int64(l.Latitude)-latLonBias) / 3_600_000.0
	lonDeg := float64(int64(l.Longitude)-latLonBias) / 3_600_000.0
	altM := float64(int64(l.Altitude)-altBiasCm) / 100.0
	return fmt.Sprintf("%.6f %.6f %.2fm size=%s hp=%s vp=%s",
		latDeg, lonDeg, altM,
		locPrecision(l.Size), locPrecision(l.HorizPre), locPrecision(l.VertPre))
}

// locPrecision decodes an RFC 1876 precision byte. High nibble is the
// mantissa (1–9), low nibble the base-10 exponent in centimeters.
// Returns the value in meters with "m" suffix.
func locPrecision(b uint8) string {
	mant := float64(b >> 4)
	exp := int(b & 0x0F)
	cm := mant
	for i := 0; i < exp; i++ {
		cm *= 10
	}
	return fmt.Sprintf("%.2fm", cm/100.0)
}

// svcbText formats SVCB/HTTPS record text. Params are rendered as
// key=hexval pairs; callers that need parsed param values should use
// dns.LookupSVCB / dns.LookupHTTPS directly.
func svcbText(priority uint16, target string, params []dns.SVCBParam) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %s", priority, target)
	for _, p := range params {
		fmt.Fprintf(&b, " %d=%s", p.Key, hex.EncodeToString(p.Value))
	}
	return b.String()
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
