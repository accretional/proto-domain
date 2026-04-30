// Package resolver implements the proto-domain Resolver gRPC service
// against the host's stub resolver via Go's net package.
//
// Behavior:
//   - Default *net.Resolver, so we follow the same DNS path the host
//     itself uses (/etc/resolv.conf or the OS analogue).
//   - For each record type Go's stdlib exposes (A/AAAA via LookupIPAddr,
//     CNAME, NS, MX, TXT) we issue one lookup per request and stream the
//     results back as DNSRecords.
//   - "No records" / NXDOMAIN per type is silently skipped.
//   - TTLs aren't surfaced by net.Resolver; ttl_seconds stays 0. The
//     forked dns/ package (work in progress) will replace this and
//     populate TTLs.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// Service implements pb.ResolverServer. Wired up by cmd/server.
type Service struct {
	domainpb.UnimplementedResolverServer

	// resolver is the underlying net.Resolver. nil means use the
	// default stdlib resolver (host resolver).
	resolver *net.Resolver
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
		r = net.DefaultResolver
	}

	emit := func(t domainpb.DNSRecordType, text string) error {
		return out.Send(&domainpb.DNSRecord{
			Type:   t,
			Target: req,
			Class:  domainpb.Class_Internet,
			Format: &domainpb.DNSRecord_Text{Text: text},
		})
	}

	// A / AAAA via LookupIPAddr.
	if ips, err := r.LookupIPAddr(ctx, name); err == nil {
		for _, ip := range ips {
			t := domainpb.DNSRecordType_AAAA
			if v4 := ip.IP.To4(); v4 != nil {
				t = domainpb.DNSRecordType_A
			}
			text := ip.IP.String()
			if ip.Zone != "" {
				text = text + "%" + ip.Zone
			}
			if err := emit(t, text); err != nil {
				return err
			}
		}
	}

	// CNAME. Stdlib returns the queried name when no CNAME exists; skip
	// that uninformative case.
	if cname, err := r.LookupCNAME(ctx, name); err == nil {
		if !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(name, ".")) {
			if err := emit(domainpb.DNSRecordType_CNAME, cname); err != nil {
				return err
			}
		}
	}

	if nss, err := r.LookupNS(ctx, name); err == nil {
		for _, ns := range nss {
			if err := emit(domainpb.DNSRecordType_NS, ns.Host); err != nil {
				return err
			}
		}
	}

	if mxs, err := r.LookupMX(ctx, name); err == nil {
		for _, mx := range mxs {
			if err := emit(domainpb.DNSRecordType_MX, fmt.Sprintf("%d %s", mx.Pref, mx.Host)); err != nil {
				return err
			}
		}
	}

	if txts, err := r.LookupTXT(ctx, name); err == nil {
		for _, txt := range txts {
			if err := emit(domainpb.DNSRecordType_TXT, txt); err != nil {
				return err
			}
		}
	}

	return nil
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
