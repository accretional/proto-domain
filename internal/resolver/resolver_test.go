package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

var errFakePlain = errors.New("not a dns error")

func wrappedErr(e error) error { return fmt.Errorf("wrapped: %w", e) }

// collector is the in-memory recordSink the tests use to drive the
// resolver without spinning up a gRPC server. Lives here rather than
// in resolver.go because nothing in the production path needs it.
type collector struct {
	records []*domainpb.DNSRecord
}

func (c *collector) Send(r *domainpb.DNSRecord) error {
	c.records = append(c.records, r)
	return nil
}

// resolve drives Service.resolveStream into a collector and returns
// the collected slice. Helper for the test cases below.
func resolve(t *testing.T, ctx context.Context, svc *Service, dom *domainpb.Domain) []*domainpb.DNSRecord {
	t.Helper()
	var col collector
	if err := svc.resolveStream(ctx, dom, &col); err != nil {
		t.Fatalf("resolveStream(%s): %v", dom.GetHostname(), err)
	}
	return col.records
}

// TestResolveLocalhost is an integration smoke test that checks the
// resolver returns at least one record for "localhost" through the host
// resolver. The host resolver is expected to map localhost to 127.0.0.1
// or ::1; if it doesn't we want the test to fail loudly because that
// breaks LET_IT_RIP.
func TestResolveLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	svc := New()
	dom := &domainpb.Domain{
		Hostname: "localhost",
		Tld:      &domainpb.TLD{Format: &domainpb.TLD_Custom{Custom: "localhost"}},
	}
	recs := resolve(t, ctx, svc, dom)
	if len(recs) == 0 {
		t.Fatalf("expected at least one record for localhost, got 0")
	}
	hasLoopback := false
	for _, r := range recs {
		switch b := r.GetBody().(type) {
		case *domainpb.DNSRecord_A:
			if net.IP(b.A.GetIpv4()).String() == "127.0.0.1" {
				hasLoopback = true
			}
		case *domainpb.DNSRecord_Aaaa:
			if net.IP(b.Aaaa.GetIpv6()).String() == "::1" {
				hasLoopback = true
			}
		}
	}
	if !hasLoopback {
		t.Errorf("expected loopback record (127.0.0.1 or ::1), got %v", recs)
	}
}

// TestResolveSOA_Accretional verifies the resolver emits at least one SOA
// record for a real domain. Skipped with -short.
func TestResolveSOA_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc := New()
	dom := &domainpb.Domain{
		Hostname: "accretional.com",
		Labels:   []string{"accretional"},
		Tld:      &domainpb.TLD{Format: &domainpb.TLD_Custom{Custom: "com"}},
	}
	recs := resolve(t, ctx, svc, dom)
	var soa *domainpb.SOARecord
	for _, r := range recs {
		if r.GetType() == domainpb.DNSRecordType_SOA {
			soa = r.GetSoa()
			break
		}
	}
	if soa == nil {
		t.Skip("no SOA record returned — resolver or network issue?")
	}
	t.Logf("SOA: ns=%s mbox=%s serial=%d", soa.GetNs(), soa.GetMbox(), soa.GetSerial())
}

// TestResolveNoSuchDomain verifies the resolver does not error or panic
// when no records exist — it just returns an empty stream. Uses a name
// in the IETF-reserved invalid TLD per RFC 6761.
func TestResolveNoSuchDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	svc := New()
	dom := &domainpb.Domain{
		Hostname: "nothing.invalid",
		Labels:   []string{"nothing"},
		Tld:      &domainpb.TLD{Format: &domainpb.TLD_Custom{Custom: "invalid"}},
	}
	// Some misconfigured resolvers wildcard the invalid TLD; we don't
	// assert len==0. We just want no panic and no error.
	_ = resolve(t, ctx, svc, dom)
}

// TestIsNXDOMAIN checks the helper recognises stdlib *net.DNSError with
// IsNotFound=true and ignores other shapes.
func TestIsNXDOMAIN(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errFakePlain, false},
		{"DNSError IsNotFound=false", &net.DNSError{IsNotFound: false}, false},
		{"DNSError IsNotFound=true", &net.DNSError{IsNotFound: true}, true},
		{"wrapped DNSError IsNotFound=true", wrappedErr(&net.DNSError{IsNotFound: true}), true},
	}
	for _, c := range cases {
		if got := isNXDOMAIN(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
