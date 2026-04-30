// Copyright 2026 The proto-domain authors.
// Use of this source code is governed by a BSD-style license that can
// be found in the LICENSE_GO file (BSD compatible).
//
// records.go is proto-domain-original (not a fork): a TTL-aware
// typed-record API on top of the wire engine forked from upstream.
// Upstream's Lookup* methods return typed values that drop TTL on the
// floor; this file is what we add to keep TTLs.

package dns

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

// Header carries the metadata every DNS resource record has on the
// wire: owner name, type, class, TTL. Mirrors dnsmessage.ResourceHeader
// but in presentation form (string names) and with a stable shape that
// doesn't depend on dnsmessage's internals.
type Header struct {
	// Name is the owner name in presentation form (with trailing dot).
	Name string

	// Type is the DNS RR type code (A=1, AAAA=28, MX=15, …).
	Type dnsmessage.Type

	// Class is normally ClassINET on the public Internet.
	Class dnsmessage.Class

	// TTL is the time-to-live in seconds, taken verbatim from the wire
	// response. This is what stdlib's net.Resolver throws away.
	TTL uint32
}

// Record is the interface every typed RR record satisfies. The single
// method returns the embedded *Header so generic walkers (caching,
// renderers, validators) can read TTL/Name/Type without a type switch.
type Record interface {
	Hdr() *Header
}

// ARecord represents an A (IPv4 address) RR.
type ARecord struct {
	Header
	IP net.IP // 4 bytes
}

func (r *ARecord) Hdr() *Header { return &r.Header }

// AAAARecord represents an AAAA (IPv6 address) RR.
type AAAARecord struct {
	Header
	IP net.IP // 16 bytes
}

func (r *AAAARecord) Hdr() *Header { return &r.Header }

// CNAMERecord represents a CNAME (canonical name) RR.
type CNAMERecord struct {
	Header
	Target string // canonical name in presentation form
}

func (r *CNAMERecord) Hdr() *Header { return &r.Header }

// NSRecord represents an NS (authoritative name server) RR.
type NSRecord struct {
	Header
	Host string
}

func (r *NSRecord) Hdr() *Header { return &r.Header }

// MXRecord represents an MX (mail exchange) RR. Pref is the preference
// (lower is preferred per RFC 5321).
type MXRecord struct {
	Header
	Pref uint16
	Host string
}

func (r *MXRecord) Hdr() *Header { return &r.Header }

// TXTRecord represents a TXT (text) RR. A single TXT record may contain
// multiple character-string fragments on the wire (RFC 1035 §3.3.14);
// we expose them as a slice. Most callers concat with no separator,
// which is the stdlib net.Resolver behavior.
type TXTRecord struct {
	Header
	Strings []string
}

func (r *TXTRecord) Hdr() *Header { return &r.Header }

// SRVRecord represents an SRV (service location) RR per RFC 2782.
type SRVRecord struct {
	Header
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func (r *SRVRecord) Hdr() *Header { return &r.Header }

// PTRRecord represents a PTR (pointer / reverse DNS) RR.
type PTRRecord struct {
	Header
	Target string
}

func (r *PTRRecord) Hdr() *Header { return &r.Header }
