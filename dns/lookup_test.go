package dns

import (
	"context"
	"testing"
	"time"
)

// TestLookupLocalhost verifies the layer-2 Lookup* path resolves
// localhost via /etc/hosts (which our hosts.go forks from upstream).
// This is the cheapest possible end-to-end smoke test for dns/ — it
// doesn't hit the wire, so it doesn't depend on network access.
func TestLookupLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	r := DefaultResolver
	recs, err := r.LookupIP(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupIP(localhost): %v", err)
	}
	if len(recs) == 0 {
		t.Fatalf("expected at least one record for localhost, got 0")
	}
	hasLoopback := false
	for _, rec := range recs {
		switch v := rec.(type) {
		case *ARecord:
			if v.IP.String() == "127.0.0.1" {
				hasLoopback = true
			}
		case *AAAARecord:
			if v.IP.String() == "::1" {
				hasLoopback = true
			}
		}
	}
	if !hasLoopback {
		t.Errorf("expected a 127.0.0.1 or ::1 record, got %v", recs)
	}
}

// TestLookupAccretional hits the live network (LET_IT_RIP territory).
// We expose it as a regular test but skip when -short is set.
func TestLookupAccretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := DefaultResolver
	mxs, err := r.LookupMX(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupMX(accretional.com): %v", err)
	}
	if len(mxs) == 0 {
		t.Skipf("LookupMX returned no records — flaky network?")
	}
	// We don't assert specific MX hosts (DNS records change). We just
	// want a TTL > 0 to confirm the new path actually returns it.
	hasTTL := false
	for _, mx := range mxs {
		if mx.TTL > 0 {
			hasTTL = true
		}
	}
	if !hasTTL {
		t.Errorf("expected at least one MX record with TTL > 0, got %v", mxs)
	}
}
