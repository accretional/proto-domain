// Package resolver implements the proto-domain Resolver gRPC service
// against the dns/ stdlib fork.
//
// Behavior:
//   - Default *dns.Resolver, so we follow the same DNS path the host
//     itself uses (/etc/resolv.conf, /etc/hosts) — minus cgo and
//     Windows. NewWithUpstream overrides this to force all queries at
//     a single addr, used to point at a local recursive resolver
//     without touching resolv.conf.
//   - All queries are issued as fully-qualified names (trailing dot) so
//     that nameList() skips /etc/resolv.conf search-domain suffix
//     expansion — which otherwise doubles UDP round-trips for NXDOMAIN.
//   - Queried types: A/AAAA, CNAME, DNAME, NS, MX, TXT, SOA, LOC,
//     HINFO, RP, AFSDB, NAPTR, KX, SSHFP, SVCB, HTTPS, CAA, URI.
//     TLSA omitted (canonical owner is _<port>._<proto>.<host>, not
//     the apex). DNSSEC types intentionally excluded.
//   - Lookups are issued sequentially.
//   - The first lookup (LookupIP) doubles as a presence probe: if it
//     returns NXDOMAIN, the name doesn't exist for any type (RFC 2308),
//     so the remaining 17 lookups are skipped. This saves ~17× of the
//     per-domain work on dead names.
//   - The dns/ layer already returns *domainpb.DNSRecord with Type,
//     TtlSeconds, and Body populated; this service just sets the
//     caller-owned Target and Class fields and forwards to the stream.
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

	// emit forwards a batch of records returned by a dns/ Lookup* call,
	// setting the common fields the dns/ layer leaves for us.
	emit := func(recs []*domainpb.DNSRecord, err error) error {
		if err != nil {
			return nil // "no records" is silent; the dns/ layer wraps it as DNSError
		}
		for _, rec := range recs {
			rec.Target = req
			rec.Class = domainpb.Class_Internet
			if err := out.Send(rec); err != nil {
				return err
			}
		}
		return nil
	}
	// emitOnTypeMatch is the same but filters out CNAME echoes of the
	// queried name (resolver pads CNAMEs into A/AAAA answers when the
	// stdlib's IP lookup chases them).
	emitCNAME := func(recs []*domainpb.DNSRecord, err error) error {
		if err != nil {
			return nil
		}
		for _, rec := range recs {
			cn := rec.GetCname()
			if cn == nil {
				continue
			}
			if strings.EqualFold(strings.TrimSuffix(cn.GetTarget(), "."), strings.TrimSuffix(name, ".")) {
				continue
			}
			rec.Target = req
			rec.Class = domainpb.Class_Internet
			if err := out.Send(rec); err != nil {
				return err
			}
		}
		return nil
	}

	ipRecs, ipErr := r.LookupIP(ctx, name)
	if isNXDOMAIN(ipErr) {
		// RFC 2308: NXDOMAIN means the name doesn't exist for any type.
		// Skip the remaining 17 lookups — they would all return the same
		// negative result.
		return nil
	}
	if err := emit(ipRecs, ipErr); err != nil {
		return err
	}
	if err := emitCNAME(r.LookupRecords(ctx, name, dnsmessage.TypeCNAME)); err != nil {
		return err
	}
	if err := emit(r.LookupRecords(ctx, name, dns.TypeDNAME)); err != nil {
		return err
	}
	if err := emit(r.LookupNS(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupMX(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupTXT(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupSOA(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupLOC(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupHINFO(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupRP(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupAFSDB(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupNAPTR(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupKX(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupSSHFP(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupSVCB(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupHTTPS(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupCAA(ctx, name)); err != nil {
		return err
	}
	if err := emit(r.LookupURI(ctx, name)); err != nil {
		return err
	}
	return nil
}

// isNXDOMAIN reports whether err is the dns/ layer's "name doesn't
// exist" signal. The dns/ layer surfaces NXDOMAIN as *net.DNSError
// with IsNotFound=true, mirroring stdlib's net package.
func isNXDOMAIN(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
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
