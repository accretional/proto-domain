// Package resolver implements the proto-domain Resolver gRPC service
// against the dns/ stdlib fork (which exposes per-record TTLs).
//
// Behavior:
//   - Default *dns.Resolver, so we follow the same DNS path the host
//     itself uses (/etc/resolv.conf, /etc/hosts) — minus cgo and
//     Windows. See dns/COVERAGE.md for what's covered.
//   - For each record type we currently care about (A, AAAA, CNAME,
//     NS, MX, TXT) we issue one lookup per request and stream the
//     results back as DNSRecords with `ttl_seconds` populated from
//     the wire.
//   - "No records" / NXDOMAIN per type is silently skipped.
//   - Long-tail record types (SOA, CAA, SSHFP, …) are tracked in
//     dns/COVERAGE.md as Layer 3 work.
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

	// CNAME.
	if cname, err := r.LookupCNAME(ctx, name); err == nil && cname != "" {
		if !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(name, ".")) {
			// dns.Resolver.LookupCNAME returns just the canonical name;
			// for TTL we have to reach for LookupRecords. Cheap.
			ttl := lookupCNAMETTL(ctx, r, name)
			if err := emit(domainpb.DNSRecordType_CNAME, ttl, cname); err != nil {
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
			// Concatenate fragments per stdlib's TXT semantics; any
			// caller wanting the raw fragments can hit dns/ directly.
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

	// HINFO — "<cpu> <os>"
	if recs, err := r.LookupHINFO(ctx, name); err == nil {
		for _, h := range recs {
			if err := emit(domainpb.DNSRecordType_HINFO, h.TTL, fmt.Sprintf("%q %q", h.CPU, h.OS)); err != nil {
				return err
			}
		}
	}

	// RP — "<mbox> <txt>"
	if recs, err := r.LookupRP(ctx, name); err == nil {
		for _, rp := range recs {
			if err := emit(domainpb.DNSRecordType_RP, rp.TTL, rp.Mbox+" "+rp.Txt); err != nil {
				return err
			}
		}
	}

	// AFSDB — "<subtype> <hostname>"
	if recs, err := r.LookupAFSDB(ctx, name); err == nil {
		for _, a := range recs {
			if err := emit(domainpb.DNSRecordType_AFSDB, a.TTL, fmt.Sprintf("%d %s", a.Subtype, a.Hostname)); err != nil {
				return err
			}
		}
	}

	// NAPTR — RFC 3403 presentation: <order> <pref> "<flags>" "<service>" "<regexp>" <replacement>
	if recs, err := r.LookupNAPTR(ctx, name); err == nil {
		for _, n := range recs {
			text := fmt.Sprintf(`%d %d %q %q %q %s`, n.Order, n.Preference, n.Flags, n.Service, n.Regexp, n.Replacement)
			if err := emit(domainpb.DNSRecordType_NAPTR, n.TTL, text); err != nil {
				return err
			}
		}
	}

	// KX — "<preference> <exchanger>"
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

// lookupCNAMETTL fetches the TTL for the CNAME chain head. Used only
// when LookupCNAME succeeded — we already know there's a record.
// Returns 0 if the secondary lookup fails (the CNAME emit still goes
// out with whatever TTL we have).
func lookupCNAMETTL(ctx context.Context, r *dns.Resolver, name string) uint32 {
	recs, err := r.LookupRecords(ctx, name, dnsmessage.TypeCNAME)
	if err != nil || len(recs) == 0 {
		return 0
	}
	return recs[0].Hdr().TTL
}

// canonicalName recovers the queryable string from a Domain message.
// Prefers the structured (labels + TLD) representation, falling back
// to `hostname` for partially-populated messages.
func canonicalName(d *domainpb.Domain) string {
	parts := make([]string, 0, len(d.GetLabels())+1)
	parts = append(parts, d.GetLabels()...)
	if t := tldString(d.GetTld()); t != "" {
		parts = append(parts, t)
	}
	if len(parts) == 0 {
		return strings.TrimSuffix(d.GetHostname(), ".")
	}
	return strings.Join(parts, ".")
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
