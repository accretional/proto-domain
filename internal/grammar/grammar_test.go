package grammar

import (
	"strings"
	"testing"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// allGrammars returns every bundled grammar singleton. Lives in
// _test.go because nothing in the production code path enumerates
// them — only this file's TestGrammarsLoad smoke test does.
func allGrammars() []*Grammar {
	return []*Grammar{DomainGrammar, HostnameGrammar, TLDGrammar, FQDNGrammar}
}

// TestGrammarsLoad validates that every embedded .ebnf file parses into
// a non-empty GrammarDescriptor. Cheap canary that catches typos in the
// grammars before any test attempts to parse a real input.
func TestGrammarsLoad(t *testing.T) {
	for _, g := range allGrammars() {
		gd, err := g.Descriptor()
		if err != nil {
			t.Fatalf("loading %s grammar: %v", g.Name, err)
		}
		if len(gd.GetRules()) == 0 {
			t.Fatalf("%s grammar has no rules", g.Name)
		}
	}
}

// TestParseDomain_Valid covers shapes the grammar should accept.
func TestParseDomain_Valid(t *testing.T) {
	cases := []struct {
		in        string
		labels    []string
		tld       string
		fq        bool
		hostname  string
	}{
		{"example.com", []string{"example"}, "com", false, "example.com"},
		{"Example.COM", []string{"example"}, "com", false, "example.com"},
		{"a.b.c.example.com", []string{"a", "b", "c", "example"}, "com", false, "a.b.c.example.com"},
		{"foo-bar.example.com", []string{"foo-bar", "example"}, "com", false, "foo-bar.example.com"},
		{"123.example.com", []string{"123", "example"}, "com", false, "123.example.com"},
		{"x1.y2.z3.com", []string{"x1", "y2", "z3"}, "com", false, "x1.y2.z3.com"},
		{"localhost", nil, "localhost", false, "localhost"},
		{"accretional.com.", []string{"accretional"}, "com", true, "accretional.com"},
		{"r.example.museum", []string{"r", "example"}, "museum", false, "r.example.museum"},
		{"xn--bcher-kva.ch", []string{"xn--bcher-kva"}, "ch", false, "xn--bcher-kva.ch"},
		{"a.b", []string{"a"}, "b", false, "a.b"},
		// 63-char label (boundary).
		{strings.Repeat("a", 63) + ".com", []string{strings.Repeat("a", 63)}, "com", false, strings.Repeat("a", 63) + ".com"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			d, err := ParseDomain(tc.in)
			if err != nil {
				t.Fatalf("ParseDomain(%q) error: %v", tc.in, err)
			}
			if d.GetHostname() != tc.hostname {
				t.Errorf("hostname: got %q want %q", d.GetHostname(), tc.hostname)
			}
			if got := d.GetLabels(); !sliceEqual(got, tc.labels) {
				t.Errorf("labels: got %v want %v", got, tc.labels)
			}
			if got := tldString(d.GetTld()); got != tc.tld {
				t.Errorf("tld: got %q want %q", got, tc.tld)
			}
			if d.GetFullyQualified() != tc.fq {
				t.Errorf("fully_qualified: got %v want %v", d.GetFullyQualified(), tc.fq)
			}
			// Round-trip: print → re-parse → identical structure.
			out := PrintDomain(d)
			d2, err := ParseDomain(out)
			if err != nil {
				t.Fatalf("re-ParseDomain(%q) error: %v", out, err)
			}
			if d2.GetHostname() != d.GetHostname() ||
				!sliceEqual(d2.GetLabels(), d.GetLabels()) ||
				tldString(d2.GetTld()) != tldString(d.GetTld()) ||
				d2.GetFullyQualified() != d.GetFullyQualified() {
				t.Errorf("round-trip diverged:\n  in1: %#v\n  out: %#v", d, d2)
			}
		})
	}
}

// TestParseDomain_Invalid covers strings the grammar/validator must
// reject — empty, whitespace, double dots, leading/trailing hyphens,
// length overruns.
func TestParseDomain_Invalid(t *testing.T) {
	cases := []string{
		"",
		" ",
		".",
		"..com",
		"example..com",
		"-example.com",
		"example-.com",
		"exa mple.com",                            // whitespace
		"example.com/",                            // stray slash
		"example#com",                             // bad char
		strings.Repeat("a", 64) + ".com",          // 64-char label > 63 cap
		strings.Repeat("a.", 130) + "com",         // > 253-byte total
	}
	for _, in := range cases {
		in := in
		t.Run(safeName(in), func(t *testing.T) {
			if d, err := ParseDomain(in); err == nil {
				t.Errorf("ParseDomain(%q) unexpectedly succeeded: %#v", in, d)
			}
		})
	}
}

func TestParseHostname_Valid(t *testing.T) {
	cases := []string{
		"localhost",
		"example",
		"a",
		"x1",
		"foo-bar",
		"xn--bcher-kva",
		strings.Repeat("a", 63),
	}
	for _, in := range cases {
		in := in
		t.Run(in, func(t *testing.T) {
			if _, err := ParseHostname(in); err != nil {
				t.Fatalf("ParseHostname(%q): %v", in, err)
			}
		})
	}
}

func TestParseHostname_Invalid(t *testing.T) {
	cases := []string{
		"",
		" ",
		"-foo",
		"foo-",
		"foo.bar", // contains a dot
		"foo bar",
		"foo/bar",
		strings.Repeat("a", 64),
	}
	for _, in := range cases {
		in := in
		t.Run(safeName(in), func(t *testing.T) {
			if _, err := ParseHostname(in); err == nil {
				t.Errorf("ParseHostname(%q) unexpectedly succeeded", in)
			}
		})
	}
}

func TestParseTLD_Valid(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		isEnum bool
	}{
		{"com", "com", true},
		{"COM", "com", true},
		{"net", "net", false},
		{"museum", "museum", false},
		{"xn--bcher-kva", "xn--bcher-kva", false},
		{"co", "co", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			tld, err := ParseTLD(tc.in)
			if err != nil {
				t.Fatalf("ParseTLD(%q): %v", tc.in, err)
			}
			if got := tldString(tld); got != tc.want {
				t.Errorf("text form: got %q want %q", got, tc.want)
			}
			_, isInternet := tld.GetFormat().(*domainpb.TLD_Internet)
			if isInternet != tc.isEnum {
				t.Errorf("internet enum: got %v want %v", isInternet, tc.isEnum)
			}
		})
	}
}

func TestParseTLD_Invalid(t *testing.T) {
	cases := []string{"", " ", "1com", "-com", "com-", "co m", ".com"}
	for _, in := range cases {
		in := in
		t.Run(safeName(in), func(t *testing.T) {
			if _, err := ParseTLD(in); err == nil {
				t.Errorf("ParseTLD(%q) unexpectedly succeeded", in)
			}
		})
	}
}

func TestPrintDomain_Roundtrip(t *testing.T) {
	cases := []string{
		"example.com",
		"a.b.c.d.example.com",
		"localhost",
		"accretional.com.",
		"x1.y2.z3.example.com.",
	}
	for _, in := range cases {
		in := in
		t.Run(in, func(t *testing.T) {
			d, err := ParseDomain(in)
			if err != nil {
				t.Fatalf("ParseDomain(%q): %v", in, err)
			}
			got := PrintDomain(d)
			want := strings.ToLower(in)
			if got != want {
				t.Errorf("PrintDomain: got %q want %q", got, want)
			}
		})
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// safeName produces a t.Run subtest name that doesn't collide with
// path separators or reserved characters.
func safeName(s string) string {
	if s == "" {
		return "<empty>"
	}
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
