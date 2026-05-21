package dns

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// TestLookupLocalhost verifies the layer-2 Lookup* path resolves
// localhost via /etc/hosts. Doesn't hit the wire.
func TestLookupLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupIP(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupIP(localhost): %v", err)
	}
	if len(recs) == 0 {
		t.Fatalf("expected at least one record for localhost, got 0")
	}
	hasLoopback := false
	for _, rec := range recs {
		switch b := rec.GetBody().(type) {
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
		t.Errorf("expected a 127.0.0.1 or ::1 record, got %d records", len(recs))
	}
}

// TestLookupSOA_Accretional verifies LookupSOA returns a record with
// populated fields for a live domain. Skipped with -short.
func TestLookupSOA_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupSOA(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupSOA(accretional.com): %v", err)
	}
	if len(recs) == 0 {
		t.Skip("LookupSOA returned no records — no SOA published for accretional.com?")
	}
	soa := recs[0].GetSoa()
	if soa == nil {
		t.Fatal("first record has no SOA body")
	}
	if soa.GetNs() == "" {
		t.Error("SOA.Ns is empty")
	}
	if soa.GetMbox() == "" {
		t.Error("SOA.Mbox is empty")
	}
	t.Logf("SOA: NS=%s MBox=%s serial=%d TTL=%d", soa.GetNs(), soa.GetMbox(), soa.GetSerial(), recs[0].GetTtlSeconds())
}

// ── Wire-format parser unit tests ────────────────────────────────────────────

func TestParseCharString(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		off     int
		wantS   string
		wantOff int
		wantOK  bool
	}{
		{"normal", []byte{3, 'f', 'o', 'o'}, 0, "foo", 4, true},
		{"offset", []byte{0, 3, 'b', 'a', 'r'}, 1, "bar", 5, true},
		{"empty string", []byte{0}, 0, "", 1, true},
		{"truncated length", []byte{}, 0, "", 0, false},
		{"truncated content", []byte{5, 'a', 'b'}, 0, "", 1, false},
	}
	for _, c := range cases {
		s, off, ok := parseCharString(c.data, c.off)
		if ok != c.wantOK || s != c.wantS || off != c.wantOff {
			t.Errorf("%s: got (%q, %d, %v) want (%q, %d, %v)", c.name, s, off, ok, c.wantS, c.wantOff, c.wantOK)
		}
	}
}

func TestParseWireName(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		off     int
		wantN   string
		wantOff int
		wantOK  bool
	}{
		{
			"example.com",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			0, "example.com.", 13, true,
		},
		{"root", []byte{0}, 0, ".", 1, true},
		{"compression pointer rejected", []byte{0xC0, 0x0C}, 0, "", 0, false},
		{"truncated", []byte{3, 'f', 'o'}, 0, "", 0, false},
	}
	for _, c := range cases {
		n, off, ok := parseWireName(c.data, c.off)
		if ok != c.wantOK || n != c.wantN || off != c.wantOff {
			t.Errorf("%s: got (%q, %d, %v) want (%q, %d, %v)", c.name, n, off, ok, c.wantN, c.wantOff, c.wantOK)
		}
	}
}

func TestParseSVCBParamsWire(t *testing.T) {
	// Two params: key=1 val=[0,1], key=4 val=[10,0,0,1]
	data := []byte{
		0, 1, 0, 2, 0, 1, // key=1 len=2 val=[0,1]
		0, 4, 0, 4, 10, 0, 0, 1, // key=4 len=4 val=[10,0,0,1]
	}
	params, ok := parseSVCBParams(data, 0)
	if !ok || len(params) != 2 {
		t.Fatalf("parseSVCBParams: ok=%v len=%d", ok, len(params))
	}
	if params[0].GetKey() != 1 || len(params[0].GetValue()) != 2 {
		t.Errorf("param[0]: %+v", params[0])
	}
	if params[1].GetKey() != 4 || len(params[1].GetValue()) != 4 {
		t.Errorf("param[1]: %+v", params[1])
	}
}

// ── Live DNS smoke tests ──────────────────────────────────────────────────────

func TestLookupAccretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mxs, err := DefaultResolver.LookupMX(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupMX(accretional.com): %v", err)
	}
	if len(mxs) == 0 {
		t.Skipf("LookupMX returned no records — flaky network?")
	}
	hasTTL := false
	for _, rec := range mxs {
		if rec.GetTtlSeconds() > 0 {
			hasTTL = true
		}
	}
	if !hasTTL {
		t.Errorf("expected at least one MX record with TTL > 0, got %d records", len(mxs))
	}
}

func TestLookupCAA_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupCAA(ctx, "accretional.com")
	if err != nil || len(recs) == 0 {
		t.Skipf("no CAA records for accretional.com (err=%v)", err)
	}
	for _, rec := range recs {
		caa := rec.GetCaa()
		t.Logf("CAA: flags=%d tag=%q value=%q TTL=%d", caa.GetFlags(), caa.GetTag(), caa.GetValue(), rec.GetTtlSeconds())
	}
}

func TestLookupHTTPS_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupHTTPS(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupHTTPS(accretional.com): %v", err)
	}
	if len(recs) == 0 {
		t.Skip("no HTTPS records published for accretional.com")
	}
	for _, rec := range recs {
		https := rec.GetHttps()
		t.Logf("HTTPS: priority=%d target=%q params=%d TTL=%d",
			https.GetPriority(), https.GetTargetName(), len(https.GetParams()), rec.GetTtlSeconds())
	}
}

func TestLookupSSHFP_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupSSHFP(ctx, "accretional.com")
	if err != nil || len(recs) == 0 {
		t.Skipf("no SSHFP records for accretional.com (err=%v)", err)
	}
	for _, rec := range recs {
		s := rec.GetSshfp()
		t.Logf("SSHFP: algo=%d fptype=%d fp=%s TTL=%d",
			s.GetAlgorithm(), s.GetFpType(), hex.EncodeToString(s.GetFingerprint()), rec.GetTtlSeconds())
	}
}

func TestLookupURI_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupURI(ctx, "accretional.com")
	if err != nil || len(recs) == 0 {
		t.Skipf("no URI records for accretional.com yet (err=%v)", err)
	}
	for _, rec := range recs {
		u := rec.GetUri()
		t.Logf("URI: priority=%d weight=%d target=%q TTL=%d",
			u.GetPriority(), u.GetWeight(), u.GetTarget(), rec.GetTtlSeconds())
	}
}
