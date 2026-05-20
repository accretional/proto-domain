// Package resolver implements the proto-domain Resolver gRPC service
// against the dns/ stdlib fork (which exposes per-record TTLs).
//
// Behavior:
//   - Default *dns.Resolver, so we follow the same DNS path the host
//     itself uses (/etc/resolv.conf, /etc/hosts) — minus cgo and
//     Windows. See dns/COVERAGE.md for what's covered.
//   - All queries are issued as fully-qualified names (trailing dot) so
//     that nameList() skips /etc/resolv.conf search-domain suffix
//     expansion — which otherwise doubles UDP round-trips for NXDOMAIN.
//   - Queried types: A/AAAA, CNAME, DNAME, NS, MX, TXT, SOA, SSHFP,
//     SVCB, HTTPS, CAA, URI. Omitted: HINFO, RP, AFSDB, NAPTR, KX
//     (zero hits in a 34K-domain sample, each costs a round-trip);
//     DNSSEC types (DS, DNSKEY) intentionally excluded.
//   - "No records" / NXDOMAIN per type is silently skipped.
package resolver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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
