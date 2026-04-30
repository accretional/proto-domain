// Package grammar loads and parses the proto-domain EBNF grammars via
// github.com/accretional/gluon/v2/metaparser. Each grammar lives in
// /lang/<name>.ebnf and is embedded into the binary at build time.
//
// Public entry points are intentionally small:
//
//   ParseDomain(s)   string → *domainpb.Domain
//   ParseHostname(s) string → *domainpb.Domain (single-label form)
//   ParseTLD(s)      string → *domainpb.TLD
//   PrintDomain(d)   *domainpb.Domain → string (canonical form)
//
// The grammars themselves are loaded lazily on first use and cached.
package grammar

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/accretional/gluon/v2/metaparser"
	gluonpb "github.com/accretional/gluon/v2/pb"
)

//go:embed lang/domain.ebnf
var domainEBNF string

//go:embed lang/hostname.ebnf
var hostnameEBNF string

//go:embed lang/tld.ebnf
var tldEBNF string

//go:embed lang/fqdn.ebnf
var fqdnEBNF string

// Grammar bundles a parsed gluon GrammarDescriptor with the start-rule
// name expected for that grammar's source files. Callers go through one
// of the package-level singletons (DomainGrammar, HostnameGrammar, …)
// so the underlying GrammarDescriptor is built once and reused.
type Grammar struct {
	Name      string
	StartRule string

	once sync.Once
	src  string
	gd   *gluonpb.GrammarDescriptor
	err  error
}

func (g *Grammar) load() (*gluonpb.GrammarDescriptor, error) {
	g.once.Do(func() {
		doc := metaparser.WrapString(g.src)
		doc.Name = g.Name
		gd, err := metaparser.ParseEBNF(doc)
		if err != nil {
			g.err = fmt.Errorf("loading %s grammar: %w", g.Name, err)
			return
		}
		g.gd = gd
	})
	return g.gd, g.err
}

// Descriptor returns the parsed GrammarDescriptor, loading it on first
// access. Subsequent calls return the cached descriptor.
func (g *Grammar) Descriptor() (*gluonpb.GrammarDescriptor, error) {
	return g.load()
}

// ParseAST parses src against this grammar and returns the resulting
// ASTDescriptor. Callers usually want one of the typed parsers
// (ParseDomain, ParseHostname, ParseTLD) instead — those wrap this
// method and convert the AST into a typed proto.
func (g *Grammar) ParseAST(src string) (*gluonpb.ASTDescriptor, error) {
	gd, err := g.load()
	if err != nil {
		return nil, err
	}
	doc := metaparser.WrapString(src)
	doc.Name = g.Name + "-input"
	ast, err := metaparser.ParseCST(&gluonpb.CstRequest{
		Grammar:  gd,
		Document: doc,
	})
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", g.Name, err)
	}
	if ast == nil || ast.GetRoot() == nil {
		return nil, fmt.Errorf("parsing %s: empty AST", g.Name)
	}
	if root := ast.GetRoot(); root.GetKind() != g.StartRule {
		return nil, fmt.Errorf("parsing %s: root kind %q, want %q",
			g.Name, root.GetKind(), g.StartRule)
	}
	// As of gluon commit e121e84 (lexkit: require ParseAST to consume
	// entire input), trailing-text rejection is enforced upstream.
	return ast, nil
}

func concatLeaves(n *gluonpb.ASTNode) string {
	if n == nil {
		return ""
	}
	if len(n.GetChildren()) == 0 {
		return n.GetValue()
	}
	var b strings.Builder
	for _, c := range n.GetChildren() {
		b.WriteString(concatLeaves(c))
	}
	return b.String()
}

// Package-level singletons for the four bundled grammars.
var (
	DomainGrammar = &Grammar{
		Name:      "domain",
		StartRule: "domain",
		src:       domainEBNF,
	}
	HostnameGrammar = &Grammar{
		Name:      "hostname",
		StartRule: "hostname",
		src:       hostnameEBNF,
	}
	TLDGrammar = &Grammar{
		Name:      "tld",
		StartRule: "tld",
		src:       tldEBNF,
	}
	FQDNGrammar = &Grammar{
		Name:      "fqdn",
		StartRule: "fqdn",
		src:       fqdnEBNF,
	}
)
