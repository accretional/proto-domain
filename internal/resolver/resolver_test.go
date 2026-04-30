package resolver

import (
	"context"
	"testing"
	"time"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

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
		if r.GetText() == "127.0.0.1" || r.GetText() == "::1" {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Errorf("expected loopback record (127.0.0.1 or ::1), got %v", recs)
	}
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
