// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from $GOROOT/src/net/dnsclient.go (byPriorityWeight, byPref).

package dns

import (
	"cmp"
	"slices"

	domainpb "github.com/accretional/proto-domain/proto/domainpb"
)

// sortMXRecords sorts MX records by Pref ascending. Records with equal
// Pref are shuffled (RFC 5321). All records must carry an MX body.
func sortMXRecords(out []*domainpb.DNSRecord) {
	for i := range out {
		j := randIntn(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	slices.SortFunc(out, func(a, b *domainpb.DNSRecord) int {
		return cmp.Compare(a.GetMx().GetPref(), b.GetMx().GetPref())
	})
}

// sortSRVRecords sorts SRV records by Priority ascending, then by
// weighted shuffle within each Priority bucket (RFC 2782).
func sortSRVRecords(out []*SRVRecord) {
	slices.SortFunc(out, func(a, b *SRVRecord) int {
		if r := cmp.Compare(a.Priority, b.Priority); r != 0 {
			return r
		}
		return cmp.Compare(a.Weight, b.Weight)
	})
	i := 0
	for j := 1; j < len(out); j++ {
		if out[i].Priority != out[j].Priority {
			shuffleByWeight(out[i:j])
			i = j
		}
	}
	shuffleByWeight(out[i:])
}

// shuffleByWeight implements RFC 2782's weighted random ordering.
func shuffleByWeight(out []*SRVRecord) {
	sum := 0
	for _, r := range out {
		sum += int(r.Weight)
	}
	for sum > 0 && len(out) > 1 {
		s := 0
		n := randIntn(sum)
		for i := range out {
			s += int(out[i].Weight)
			if s > n {
				if i > 0 {
					out[0], out[i] = out[i], out[0]
				}
				break
			}
		}
		sum -= int(out[0].Weight)
		out = out[1:]
	}
}
