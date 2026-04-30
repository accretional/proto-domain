package grammar

import (
	"errors"
	"fmt"
	"strings"

	gluonpb "github.com/accretional/gluon/v2/pb"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// Maximum byte budgets per RFC 1035 § 2.3.4.
const (
	MaxLabelOctets  = 63
	MaxDomainOctets = 253
)

// ParseDomain parses s as a canonical domain name and returns a typed
// Domain proto. The returned Domain has:
//
//   - hostname:        the input lowercased, with the trailing dot
//                      stripped (so "Example.COM." → "example.com").
//   - labels:          all labels except the rightmost, in order.
//   - tld:             the rightmost label, mapped to InternetTLD when
//                      it matches a known constant; otherwise carried as
//                      a custom string.
//   - fully_qualified: true iff the input ended with ".".
//
// Length budgets per RFC 1035 are enforced after the syntactic parse —
// labels must be 1..63 bytes and the total must be <= 253 bytes.
func ParseDomain(s string) (*domainpb.Domain, error) {
	if s == "" {
		return nil, errors.New("empty domain")
	}
	ast, err := DomainGrammar.ParseAST(s)
	if err != nil {
		return nil, err
	}

	labels := extractLabels(ast.GetRoot())
	fq := strings.HasSuffix(s, ".")

	if err := validateDomain(labels); err != nil {
		return nil, err
	}

	all := make([]string, len(labels))
	for i, l := range labels {
		all[i] = strings.ToLower(l)
	}

	tldLabel := all[len(all)-1]
	body := all[:len(all)-1]

	hostname := strings.Join(all, ".")

	return &domainpb.Domain{
		Hostname:       hostname,
		Labels:         body,
		Tld:            tldFromLabel(tldLabel),
		FullyQualified: fq,
	}, nil
}

// ParseHostname parses s as a single hostname label (no dots). Returns
// a Domain with labels=[] and tld set from the single label.
func ParseHostname(s string) (*domainpb.Domain, error) {
	if s == "" {
		return nil, errors.New("empty hostname")
	}
	if _, err := HostnameGrammar.ParseAST(s); err != nil {
		return nil, err
	}
	if err := validateLabel(s); err != nil {
		return nil, err
	}
	low := strings.ToLower(s)
	return &domainpb.Domain{
		Hostname: low,
		Tld:      tldFromLabel(low),
	}, nil
}

// ParseTLD parses s as a TLD label and returns a typed TLD.
func ParseTLD(s string) (*domainpb.TLD, error) {
	if s == "" {
		return nil, errors.New("empty TLD")
	}
	if _, err := TLDGrammar.ParseAST(s); err != nil {
		return nil, err
	}
	if err := validateLabel(s); err != nil {
		return nil, err
	}
	return tldFromLabel(strings.ToLower(s)), nil
}

// PrintDomain serializes a typed Domain back to canonical text form.
// The result equals d.Hostname plus an optional trailing "." when
// d.FullyQualified is true. PrintDomain ignores d.Hostname when labels
// + tld are populated, since those are the structured source of truth;
// it falls back to d.Hostname if the structured fields are empty.
func PrintDomain(d *domainpb.Domain) string {
	if d == nil {
		return ""
	}
	parts := make([]string, 0, len(d.GetLabels())+1)
	parts = append(parts, d.GetLabels()...)
	if t := tldString(d.GetTld()); t != "" {
		parts = append(parts, t)
	}
	out := strings.Join(parts, ".")
	if out == "" {
		out = d.GetHostname()
	}
	if d.GetFullyQualified() {
		out += "."
	}
	return out
}

// extractLabels walks an AST produced by DomainGrammar and returns the
// list of label strings in left-to-right order. Each label sub-tree's
// matched text is reconstituted via concatLeaves.
func extractLabels(n *gluonpb.ASTNode) []string {
	if n == nil {
		return nil
	}
	var out []string
	var walk func(*gluonpb.ASTNode)
	walk = func(x *gluonpb.ASTNode) {
		if x == nil {
			return
		}
		if x.GetKind() == "label" {
			out = append(out, concatLeaves(x))
			return
		}
		for _, c := range x.GetChildren() {
			walk(c)
		}
	}
	walk(n)
	return out
}

func validateDomain(labels []string) error {
	if len(labels) == 0 {
		return errors.New("domain has zero labels")
	}
	total := 0
	for i, l := range labels {
		if err := validateLabel(l); err != nil {
			return fmt.Errorf("label %d (%q): %w", i, l, err)
		}
		total += len(l) + 1 // label + dot separator
	}
	if total-1 > MaxDomainOctets {
		return fmt.Errorf("domain length %d exceeds %d octets",
			total-1, MaxDomainOctets)
	}
	return nil
}

func validateLabel(l string) error {
	switch {
	case len(l) == 0:
		return errors.New("label is empty")
	case len(l) > MaxLabelOctets:
		return fmt.Errorf("label length %d exceeds %d", len(l), MaxLabelOctets)
	case strings.HasPrefix(l, "-"):
		return errors.New("label starts with hyphen")
	case strings.HasSuffix(l, "-"):
		return errors.New("label ends with hyphen")
	}
	return nil
}

// tldFromLabel maps a label to the typed TLD message. Known internet
// TLDs map to the InternetTLD enum; everything else rides in the custom
// string slot.
func tldFromLabel(label string) *domainpb.TLD {
	switch strings.ToLower(label) {
	case "com":
		return &domainpb.TLD{
			Format: &domainpb.TLD_Internet{Internet: domainpb.InternetTLD_COM},
		}
	}
	return &domainpb.TLD{Format: &domainpb.TLD_Custom{Custom: label}}
}

// tldString returns the canonical text form of a TLD message.
func tldString(t *domainpb.TLD) string {
	if t == nil {
		return ""
	}
	switch v := t.GetFormat().(type) {
	case *domainpb.TLD_Internet:
		switch v.Internet {
		case domainpb.InternetTLD_COM:
			return "com"
		case domainpb.InternetTLD_None:
			return ""
		}
	case *domainpb.TLD_Custom:
		return v.Custom
	}
	return ""
}
