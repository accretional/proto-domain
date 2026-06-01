// Package rdap implements a domain RDAP client backed by the IANA
// bootstrap registry (RFC 7484). Bootstrap data is fetched once on
// construction and held in memory for the lifetime of the process.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const ianaDNSBootstrap = "https://data.iana.org/rdap/dns.json"

// fallbackServers covers ccTLD registries that operate public RDAP servers
// but do not participate in the IANA bootstrap registry. Entries here are
// tried when the bootstrap lookup returns no result for a TLD.
//
// Notable absences: .jp (JPRS), .ru (TCINET), .io, .co — all either have no
// public RDAP endpoint or their servers are not globally reachable.
var fallbackServers = map[string]string{
	// DENIC (.de) — ~17M domains; returns nameservers + status but strips
	// registrant data by policy (see denic.de/en/domains/whois-service).
	"de": "https://rdap.denic.de/",
}

// Bootstrap maps TLD labels to RDAP server base URLs.
type Bootstrap struct {
	tlds map[string]string // lowercase TLD → base URL (always ends with "/")
}

// bootstrapFile mirrors the RFC 7484 JSON structure.
type bootstrapFile struct {
	Services [][]json.RawMessage `json:"services"`
}

// NewBootstrap fetches the IANA DNS bootstrap file and returns a
// ready-to-use Bootstrap. Cancelling ctx aborts the fetch.
func NewBootstrap(ctx context.Context) (*Bootstrap, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ianaDNSBootstrap, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap bootstrap dns: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap bootstrap dns: HTTP %d", resp.StatusCode)
	}

	var bf bootstrapFile
	if err := json.NewDecoder(resp.Body).Decode(&bf); err != nil {
		return nil, fmt.Errorf("rdap bootstrap dns: decode: %w", err)
	}

	tlds := make(map[string]string)
	for _, svc := range bf.Services {
		if len(svc) < 2 {
			continue
		}
		var labels []string
		if err := json.Unmarshal(svc[0], &labels); err != nil {
			continue
		}
		var urls []string
		if err := json.Unmarshal(svc[1], &urls); err != nil {
			continue
		}
		if len(urls) == 0 {
			continue
		}
		u := urls[0]
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		for _, label := range labels {
			tlds[strings.ToLower(label)] = u
		}
	}
	return &Bootstrap{tlds: tlds}, nil
}

// Resolve returns the base URL of the RDAP server responsible for domain.
// It extracts the rightmost label (TLD) and looks it up in the bootstrap map,
// falling back to fallbackServers for ccTLDs absent from the IANA registry.
// The returned URL always ends with "/".
func (b *Bootstrap) Resolve(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]
	if u, ok := b.tlds[tld]; ok {
		return u, nil
	}
	if u, ok := fallbackServers[tld]; ok {
		return u, nil
	}
	return "", fmt.Errorf("no RDAP server found for TLD %q (domain %q)", tld, domain)
}
