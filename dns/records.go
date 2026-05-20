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
	"strings"

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

// DNAMERecord represents a DNAME (delegation name) RR per RFC 6672.
// DNAME redirects an entire subtree: all names below the owner name
// are mapped to the corresponding names below Target.
type DNAMERecord struct {
	Header
	Target string // target domain name in presentation form
}

func (r *DNAMERecord) Hdr() *Header { return &r.Header }

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

// SOARecord represents a SOA (Start of Authority) RR per RFC 1035.
type SOARecord struct {
	Header
	NS      string // primary name server in presentation form
	MBox    string // responsible mailbox in DNS name form (e.g. "hostmaster.example.com.")
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

func (r *SOARecord) Hdr() *Header { return &r.Header }

// HINFORecord represents an HINFO (host information) RR per RFC 1035 §3.3.2.
type HINFORecord struct {
	Header
	CPU string
	OS  string
}

func (r *HINFORecord) Hdr() *Header { return &r.Header }

// RPRecord represents an RP (responsible person) RR per RFC 1183.
// Mbox is a domain name encoding the mailbox (same format as SOA RNAME).
// Txt is a domain name of a TXT record with additional information.
type RPRecord struct {
	Header
	Mbox string
	Txt  string
}

func (r *RPRecord) Hdr() *Header { return &r.Header }

// AFSDBRecord represents an AFSDB RR per RFC 1183. Subtype 1 = AFS
// cell database server; subtype 2 = DCE/NCA root cell directory node.
type AFSDBRecord struct {
	Header
	Subtype  uint16
	Hostname string
}

func (r *AFSDBRecord) Hdr() *Header { return &r.Header }

// NAPTRRecord represents a NAPTR (naming authority pointer) RR per RFC 3403.
type NAPTRRecord struct {
	Header
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string // domain name in presentation form
}

func (r *NAPTRRecord) Hdr() *Header { return &r.Header }

// KXRecord represents a KX (key exchange) RR per RFC 2230.
type KXRecord struct {
	Header
	Preference uint16
	Exchanger  string
}

func (r *KXRecord) Hdr() *Header { return &r.Header }

// LOCRecord represents a LOC (location information) RR per RFC 1876.
// Latitude, Longitude, and Altitude are stored as the raw biased wire
// values (lat/lon: milli-arcseconds biased by 2^31, equator/prime
// meridian = 2^31; altitude: centimeters biased by 10_000_000 so that
// 0 == -100 000 m). Size, HorizPre, VertPre are the precision bytes:
// high nibble is the base-10 mantissa (1–9), low nibble the exponent
// in centimeters. Callers wanting presentation form should convert.
type LOCRecord struct {
	Header
	Version   uint8
	Size      uint8
	HorizPre  uint8
	VertPre   uint8
	Latitude  uint32
	Longitude uint32
	Altitude  uint32
}

func (r *LOCRecord) Hdr() *Header { return &r.Header }

// SSHFPRecord represents an SSHFP (SSH fingerprint) RR per RFC 4255.
// Algorithm: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519. FpType: 1=SHA-1, 2=SHA-256.
type SSHFPRecord struct {
	Header
	Algorithm   uint8
	FpType      uint8
	Fingerprint []byte
}

func (r *SSHFPRecord) Hdr() *Header { return &r.Header }

// TLSARecord represents a TLSA (TLS authentication) RR per RFC 6698 (DANE).
// Usage, Selector, and MatchingType encode how CertAssocData should be
// interpreted; see RFC 6698 §2.1 for values.
type TLSARecord struct {
	Header
	Usage         uint8
	Selector      uint8
	MatchingType  uint8
	CertAssocData []byte
}

func (r *TLSARecord) Hdr() *Header { return &r.Header }

// SVCBParam is a single SVCB/HTTPS service parameter key-value pair.
type SVCBParam struct {
	Key   uint16
	Value []byte
}

// SVCBRecord represents an SVCB RR per RFC 9460. Priority 0 means AliasMode
// (TargetName is an alias); any other value is ServiceMode.
type SVCBRecord struct {
	Header
	Priority   uint16
	TargetName string // "." means the SVCB owner name itself
	Params     []SVCBParam
}

func (r *SVCBRecord) Hdr() *Header { return &r.Header }

// HTTPSRecord represents an HTTPS RR per RFC 9460. It has the same wire
// format as SVCB but is a distinct RR type (65 vs 64).
type HTTPSRecord struct {
	Header
	Priority   uint16
	TargetName string
	Params     []SVCBParam
}

func (r *HTTPSRecord) Hdr() *Header { return &r.Header }

// CAARecord represents a CAA (certification authority authorization) RR
// per RFC 8659. Tag is typically "issue", "issuewild", or "iodef".
// Flags bit 7 (0x01) is the issuer critical flag.
type CAARecord struct {
	Header
	Flags uint8
	Tag   string
	Value string
}

func (r *CAARecord) Hdr() *Header { return &r.Header }

// URIRecord represents a URI (RFC 7553) RR. The Target is the full URI string
// (e.g. "mailto:admin@example.com" or "tel:+15551234567").
type URIRecord struct {
	Header
	Priority uint16
	Weight   uint16
	Target   string
}

func (r *URIRecord) Hdr() *Header { return &r.Header }

// MBoxToEmail converts a DNS SOA RNAME to an email address. Per RFC 1035 §8,
// the first label is the local-part and remaining labels (minus trailing dot)
// form the domain: "hostmaster.example.com." → "hostmaster@example.com".
func MBoxToEmail(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")
	idx := strings.IndexByte(mbox, '.')
	if idx < 0 {
		return mbox
	}
	return mbox[:idx] + "@" + mbox[idx+1:]
}
