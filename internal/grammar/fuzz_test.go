package grammar

import (
	"strings"
	"testing"
)

// FuzzDomain checks two invariants about ParseDomain:
//
//  1. Outcome is deterministic per input — fuzzed twice gives the same
//     result.
//  2. Successful parses round-trip: PrintDomain(ParseDomain(s)) parses
//     again to an equivalent Domain. This catches printer/parser drift,
//     which is what fuzzing is best at finding.
//
// We do NOT panic-check; ParseDomain is allowed to error on most random
// input. The fuzz target's job is to ensure no panics, no infinite
// recursion, and no round-trip divergence.
//
// Seed corpus covers the canonical happy paths plus a few weird inputs
// that should all reject cleanly.
func FuzzDomain(f *testing.F) {
	for _, s := range []string{
		"example.com",
		"a.b.c.example.com",
		"localhost",
		"accretional.com.",
		"foo-bar.example.org",
		"xn--bcher-kva.ch",
		"",
		".",
		"..",
		"a..b",
		"-a.com",
		"a-.com",
		"a..",
		strings.Repeat("a", 64) + ".com",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Bound input size to keep the fuzz loop cheap on the host.
		if len(s) > 256 {
			return
		}
		d1, err1 := ParseDomain(s)
		d2, err2 := ParseDomain(s)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("nondeterministic parse for %q", s)
		}
		if err1 != nil {
			return
		}
		out := PrintDomain(d1)
		d3, err3 := ParseDomain(out)
		if err3 != nil {
			t.Fatalf("round-trip parse failed: in=%q printed=%q err=%v", s, out, err3)
		}
		if PrintDomain(d3) != out {
			t.Fatalf("round-trip diverged: %q -> %q -> %q", s, out, PrintDomain(d3))
		}
		_ = d2
	})
}

// FuzzHostname checks the same round-trip / determinism invariants for
// the single-label hostname grammar.
func FuzzHostname(f *testing.F) {
	for _, s := range []string{
		"localhost",
		"a",
		"x1",
		"foo-bar",
		"xn--bcher-kva",
		"",
		"-foo",
		"foo-",
		"foo.bar",
		"foo bar",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64 {
			return
		}
		d1, err1 := ParseHostname(s)
		d2, err2 := ParseHostname(s)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("nondeterministic parse for %q", s)
		}
		if err1 != nil {
			return
		}
		// A successful hostname must contain no dots.
		if strings.Contains(d1.GetHostname(), ".") {
			t.Fatalf("hostname contains dot: %q", d1.GetHostname())
		}
		_ = d2
	})
}

// FuzzTLD checks determinism + no panics. TLDs don't have a structural
// round-trip beyond lowercasing; that's already covered by unit tests.
func FuzzTLD(f *testing.F) {
	for _, s := range []string{
		"com",
		"net",
		"museum",
		"xn--bcher-kva",
		"",
		"1com",
		"-com",
		"co m",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64 {
			return
		}
		t1, err1 := ParseTLD(s)
		t2, err2 := ParseTLD(s)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("nondeterministic parse for %q", s)
		}
		if err1 != nil {
			return
		}
		if tldString(t1) != tldString(t2) {
			t.Fatalf("nondeterministic TLD: %q vs %q", tldString(t1), tldString(t2))
		}
	})
}
