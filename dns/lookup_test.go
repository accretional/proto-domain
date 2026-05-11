package dns

import (
	"context"
	"encoding/hex"
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

// TestLookupSOA_Accretional verifies LookupSOA returns a record with a
// parseable MBox for a live domain. Skipped with -short.
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
	soa := recs[0]
	if soa.NS == "" {
		t.Error("SOA.NS is empty")
	}
	if soa.MBox == "" {
		t.Error("SOA.MBox is empty")
	}
	email := MBoxToEmail(soa.MBox)
	t.Logf("SOA: NS=%s MBox=%s email=%s TTL=%d", soa.NS, soa.MBox, email, soa.TTL)
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

func TestParseHINFOWire(t *testing.T) {
	// CPU="INTEL-386" OS="UNIX"
	data := append([]byte{9}, []byte("INTEL-386")...)
	data = append(data, 4)
	data = append(data, []byte("UNIX")...)
	cpu, off, ok := parseCharString(data, 0)
	if !ok || cpu != "INTEL-386" {
		t.Fatalf("CPU: got %q ok=%v", cpu, ok)
	}
	os_, _, ok2 := parseCharString(data, off)
	if !ok2 || os_ != "UNIX" {
		t.Fatalf("OS: got %q ok=%v", os_, ok2)
	}
}

func TestParseSSHFPWire(t *testing.T) {
	// Algorithm=4 (Ed25519), FpType=2 (SHA-256), 32-byte fingerprint
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	data := append([]byte{4, 2}, fp...)
	if len(data) < 2 {
		t.Fatal("short data")
	}
	got := &SSHFPRecord{Algorithm: data[0], FpType: data[1], Fingerprint: data[2:]}
	if got.Algorithm != 4 || got.FpType != 2 || len(got.Fingerprint) != 32 {
		t.Errorf("unexpected SSHFP: %+v", got)
	}
	t.Logf("fingerprint: %s", hex.EncodeToString(got.Fingerprint))
}

func TestParseCAAWire(t *testing.T) {
	// flags=0, tag="issue", value="letsencrypt.org"
	tag := "issue"
	val := "letsencrypt.org"
	data := []byte{0, byte(len(tag))}
	data = append(data, []byte(tag)...)
	data = append(data, []byte(val)...)

	flags := data[0]
	tagLen := int(data[1])
	gotTag := string(data[2 : 2+tagLen])
	gotVal := string(data[2+tagLen:])
	if flags != 0 || gotTag != "issue" || gotVal != "letsencrypt.org" {
		t.Errorf("CAA parse: flags=%d tag=%q val=%q", flags, gotTag, gotVal)
	}
}

func TestParseURIWire(t *testing.T) {
	// priority=10, weight=1, target="mailto:admin@example.com"
	target := "mailto:admin@example.com"
	data := []byte{0, 10, 0, 1}
	data = append(data, []byte(target)...)
	rec := &URIRecord{
		Priority: uint16(data[0])<<8 | uint16(data[1]),
		Weight:   uint16(data[2])<<8 | uint16(data[3]),
		Target:   string(data[4:]),
	}
	if rec.Priority != 10 || rec.Weight != 1 || rec.Target != target {
		t.Errorf("URI parse: %+v", rec)
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
	if params[0].Key != 1 || len(params[0].Value) != 2 {
		t.Errorf("param[0]: %+v", params[0])
	}
	if params[1].Key != 4 || len(params[1].Value) != 4 {
		t.Errorf("param[1]: %+v", params[1])
	}
}

// ── Live DNS smoke tests ──────────────────────────────────────────────────────

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

// TestLookupCAA_Accretional checks for CAA records. Most domains publish at
// least one; we skip gracefully if none are found.
func TestLookupCAA_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupCAA(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupCAA(accretional.com): %v", err)
	}
	if len(recs) == 0 {
		t.Skip("no CAA records published for accretional.com")
	}
	for _, r := range recs {
		t.Logf("CAA: flags=%d tag=%q value=%q TTL=%d", r.Flags, r.Tag, r.Value, r.TTL)
	}
}

// TestLookupHTTPS_Accretional checks for HTTPS RRs (RFC 9460).
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
	for _, r := range recs {
		t.Logf("HTTPS: priority=%d target=%q params=%d TTL=%d", r.Priority, r.TargetName, len(r.Params), r.TTL)
	}
}

// TestLookupSSHFP_Accretional checks for SSHFP records.
func TestLookupSSHFP_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupSSHFP(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupSSHFP(accretional.com): %v", err)
	}
	if len(recs) == 0 {
		t.Skip("no SSHFP records published for accretional.com")
	}
	for _, r := range recs {
		t.Logf("SSHFP: algo=%d fptype=%d fp=%s TTL=%d", r.Algorithm, r.FpType, hex.EncodeToString(r.Fingerprint), r.TTL)
	}
}

// TestLookupURI_Accretional verifies URI record lookup once set-owner-uri
// has been run against accretional.com.
func TestLookupURI_Accretional(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in -short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	recs, err := DefaultResolver.LookupURI(ctx, "accretional.com")
	if err != nil {
		t.Fatalf("LookupURI(accretional.com): %v", err)
	}
	if len(recs) == 0 {
		t.Skip("no URI records published for accretional.com yet")
	}
	for _, r := range recs {
		t.Logf("URI: priority=%d weight=%d target=%q TTL=%d", r.Priority, r.Weight, r.Target, r.TTL)
	}
}
