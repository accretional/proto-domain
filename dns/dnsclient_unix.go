// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from $GOROOT/src/net/dnsclient_unix.go (see ./README.md).
// Material changes vs upstream are listed in dns/README.md and marked
// inline with "// fork:" comments.
//
// What was kept: the wire-level query loop — newRequest, the round-trip
// helpers, exchange, checkHeader, skipToAnswer, extractExtendedRCode,
// tryOneName, the resolverConfig + tryUpdate machinery, lookup,
// avoidDNS, nameList. These are the parts that talk DNS bytes.
//
// What was dropped: hostLookupOrder, goLookupHostOrder, goLookupIP*,
// goLookupCNAME, goLookupPTR, goLookupSRV, goLookupMX, goLookupNS,
// goLookupTXT — the high-level Lookup* layer that's tightly glued to
// the rest of `net`. We re-implement those in dns/lookup.go on top of
// the wire-level (r *Resolver).lookup primitive that this file keeps.

// DNS client: see RFC 1035.

// TODO(rsc):
//	Could potentially handle many outstanding lookups faster.
//	Random UDP source port (net.Dial should do that for us).
//	Random request IDs.

//go:build !windows

package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// to be used as a useTCP parameter to exchange
	useTCPOnly  = true
	useUDPOrTCP = false

	// Maximum DNS packet size.
	// Value taken from https://dnsflagday.net/2020/.
	maxDNSPacketSize = 1232
)

var (
	errLameReferral              = errors.New("lame referral")
	errCannotUnmarshalDNSMessage = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage   = errors.New("cannot marshal DNS message")
	errServerMisbehaving         = errors.New("server misbehaving")
	errInvalidDNSResponse        = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer     = errors.New("no answer from DNS server")

	// errServerTemporarilyMisbehaving is like errServerMisbehaving, except
	// that when it gets translated to a DNSError, the IsTemporary field
	// gets set to true.
	errServerTemporarilyMisbehaving = &temporaryError{"server misbehaving"}
)

// fork: upstream gates EDNS0 on a `netedns0` GODEBUG flag via
// internal/godebug. We always send EDNS0 — the off-switch is irrelevant
// outside the stdlib's compatibility goals.
const sendEDNS0 = true

func newRequest(q dnsmessage.Question, ad bool) (id uint16, udpReq, tcpReq []byte, err error) {
	id = uint16(randInt())
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true, AuthenticData: ad})
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}

	if sendEDNS0 {
		// Accept packets up to maxDNSPacketSize.  RFC 6891.
		if err := b.StartAdditionals(); err != nil {
			return 0, nil, nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false); err != nil {
			return 0, nil, nil, err
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			return 0, nil, nil, err
		}
	}

	tcpReq, err = b.Finish()
	if err != nil {
		return 0, nil, nil, err
	}
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, nil
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

// fork: net.Conn / net.PacketConn (originally bare Conn / PacketConn
// from package net).
func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}

	b = make([]byte, maxDNSPacketSize)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		// Ignore invalid responses as they may be malicious
		// forgery attempts. Instead continue waiting until
		// timeout. See golang.org/issue/13281.
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}

	b = make([]byte, 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

// exchange sends a query on the connection and hopes for a response.
func (r *Resolver) exchange(ctx context.Context, server string, q dnsmessage.Question, timeout time.Duration, useTCP, ad bool) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q, ad)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}
	var networks []string
	if useTCP {
		networks = []string{"tcp"}
	} else {
		networks = []string{"udp", "tcp"}
	}
	for _, network := range networks {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		c, err := r.dial(ctx, network, server)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			c.SetDeadline(d)
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		// fork: net.PacketConn (was bare PacketConn).
		if _, ok := c.(net.PacketConn); ok {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, mapErr(err)
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		// RFC 5966 indicates that when a client receives a UDP response with
		// the TC flag set, it should take the TC flag as an indication that it
		// should retry over TCP instead.
		// The case when the TC flag is set in a TCP response is not well specified,
		// so this implements the glibc resolver behavior, returning the existing
		// dns response instead of returning a "errNoAnswerFromDNSServer" error.
		// See go.dev/issue/64896
		if h.Truncated && network == "udp" {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

// checkHeader performs basic sanity checks on the header.
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	rcode, hasAdd := extractExtendedRCode(*p, h)

	if rcode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}

	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}

	// libresolv continues to the next server when it receives
	// an invalid referral response. See golang.org/issue/15434.
	if rcode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone && !hasAdd {
		return errLameReferral
	}

	if rcode != dnsmessage.RCodeSuccess && rcode != dnsmessage.RCodeNameError {
		// None of the error codes make sense
		// for the query we sent. If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly or
		// having temporary trouble.
		if rcode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}

	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

// extractExtendedRCode extracts the extended RCode from the OPT resource (EDNS(0))
// If an OPT record is not found, the RCode from the hdr is returned.
// Another return value indicates whether an additional resource was found.
func extractExtendedRCode(p dnsmessage.Parser, hdr dnsmessage.Header) (dnsmessage.RCode, bool) {
	p.SkipAllAnswers()
	p.SkipAllAuthorities()
	hasAdd := false
	for {
		ahdr, err := p.AdditionalHeader()
		if err != nil {
			return hdr.RCode, hasAdd
		}
		hasAdd = true
		if ahdr.Type == dnsmessage.TypeOPT {
			return ahdr.ExtendedRCode(hdr.RCode), hasAdd
		}
		if err := p.SkipAdditional(); err != nil {
			return hdr.RCode, hasAdd
		}
	}
}

// Do a lookup for a single name, which must be rooted
// (otherwise answer will not find the answers).
func (r *Resolver) tryOneName(ctx context.Context, cfg *dnsConfig, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error
	serverOffset := cfg.serverOffset()
	sLen := uint32(len(cfg.servers))

	n, err := dnsmessage.NewName(name)
	if err != nil {
		// fork: &DNSError{...} (bare type) → &net.DNSError{...}.
		return dnsmessage.Parser{}, "", &net.DNSError{Err: errCannotMarshalDNSMessage.Error(), Name: name}
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	for i := 0; i < cfg.attempts; i++ {
		for j := uint32(0); j < sLen; j++ {
			server := cfg.servers[(serverOffset+j)%sLen]

			p, h, err := r.exchange(ctx, server, q, cfg.timeout, cfg.useTCP, cfg.trustAD)
			if err != nil {
				dnsErr := newDNSError(err, name, server)
				// Set IsTemporary for socket-level errors. Note that this flag
				// may also be used to indicate a SERVFAIL response.
				// fork: *OpError → *net.OpError.
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				if err == errNoSuchHost {
					// The name does not exist, so trying
					// another server won't help.
					return p, server, newDNSError(errNoSuchHost, name, server)
				}
				lastErr = newDNSError(err, name, server)
				continue
			}

			if err := skipToAnswer(&p, qtype); err != nil {
				if err == errNoSuchHost {
					// The name does not exist, so trying
					// another server won't help.
					return p, server, newDNSError(errNoSuchHost, name, server)
				}
				lastErr = newDNSError(err, name, server)
				continue
			}

			return p, server, nil
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

// A resolverConfig represents a DNS stub resolver configuration.
type resolverConfig struct {
	initOnce sync.Once // guards init of resolverConfig

	// ch is used as a semaphore that only allows one lookup at a
	// time to recheck resolv.conf.
	ch          chan struct{} // guards lastChecked and modTime
	lastChecked time.Time     // last time resolv.conf was checked

	dnsConfig atomic.Pointer[dnsConfig] // parsed resolv.conf structure used in lookups
}

var resolvConf resolverConfig

func getSystemDNSConfig() *dnsConfig {
	resolvConf.tryUpdate("/etc/resolv.conf")
	return resolvConf.dnsConfig.Load()
}

// init initializes conf and is only called via conf.initOnce.
func (conf *resolverConfig) init() {
	// Set dnsConfig and lastChecked so we don't parse
	// resolv.conf twice the first time.
	conf.dnsConfig.Store(dnsReadConfig("/etc/resolv.conf"))
	conf.lastChecked = time.Now()

	// Prepare ch so that only one update of resolverConfig may
	// run at once.
	conf.ch = make(chan struct{}, 1)
}

// tryUpdate tries to update conf with the named resolv.conf file.
// The name variable only exists for testing. It is otherwise always
// "/etc/resolv.conf".
func (conf *resolverConfig) tryUpdate(name string) {
	conf.initOnce.Do(conf.init)

	if conf.dnsConfig.Load().noReload {
		return
	}

	// Ensure only one update at a time checks resolv.conf.
	if !conf.tryAcquireSema() {
		return
	}
	defer conf.releaseSema()

	now := time.Now()
	if conf.lastChecked.After(now.Add(-5 * time.Second)) {
		return
	}
	conf.lastChecked = now

	// fork: upstream switches on runtime.GOOS == "windows" to skip
	// the file stat (Windows has no resolv.conf on disk). This file
	// has //go:build !windows so the windows branch is unreachable.
	var mtime time.Time
	if fi, err := os.Stat(name); err == nil {
		mtime = fi.ModTime()
	}
	if mtime.Equal(conf.dnsConfig.Load().mtime) {
		return
	}

	dnsConf := dnsReadConfig(name)
	conf.dnsConfig.Store(dnsConf)
}

func (conf *resolverConfig) tryAcquireSema() bool {
	select {
	case conf.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (conf *resolverConfig) releaseSema() {
	<-conf.ch
}

func (r *Resolver) lookup(ctx context.Context, name string, qtype dnsmessage.Type, conf *dnsConfig) (dnsmessage.Parser, string, error) {
	if !isDomainName(name) {
		// We used to use "invalid domain name" as the error,
		// but that is a detail of the specific lookup mechanism.
		// Other lookups might allow broader name syntax
		// (for example Multicast DNS allows UTF-8; see RFC 6762).
		// For consistency with libc resolvers, report no such host.
		return dnsmessage.Parser{}, "", newDNSError(errNoSuchHost, name, "")
	}

	if conf == nil {
		conf = getSystemDNSConfig()
	}

	var (
		p      dnsmessage.Parser
		server string
		err    error
	)
	for _, fqdn := range conf.nameList(name) {
		p, server, err = r.tryOneName(ctx, conf, fqdn, qtype)
		if err == nil {
			break
		}
		// fork: type Error from package net → net.Error.
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() && r.strictErrors() {
			// If we hit a temporary error with StrictErrors enabled,
			// stop immediately instead of trying more names.
			break
		}
	}
	if err == nil {
		return p, server, nil
	}
	// fork: *DNSError → *net.DNSError.
	if err, ok := err.(*net.DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		err.Name = name
	}
	return dnsmessage.Parser{}, "", err
}

// avoidDNS reports whether this is a hostname for which we should not
// use DNS. Currently this includes only .onion, per RFC 7686. See
// golang.org/issue/13705. Does not cover .local names (RFC 6762),
// see golang.org/issue/16739.
func avoidDNS(name string) bool {
	if name == "" {
		return true
	}
	// fork: stringslite.TrimSuffix → strings.TrimSuffix.
	name = strings.TrimSuffix(name, ".")
	return stringsHasSuffixFold(name, ".onion")
}

// nameList returns a list of names for sequential DNS queries.
func (conf *dnsConfig) nameList(name string) []string {
	// Check name length (see isDomainName).
	l := len(name)
	rooted := l > 0 && name[l-1] == '.'
	if l > 254 || l == 254 && !rooted {
		return nil
	}

	// If name is rooted (trailing dot), try only that name.
	if rooted {
		if avoidDNS(name) {
			return nil
		}
		return []string{name}
	}

	// fork: bytealg.CountString(name, '.') → strings.Count(name, ".").
	hasNdots := strings.Count(name, ".") >= conf.ndots
	name += "."
	l++

	// Build list of search choices.
	names := make([]string, 0, 1+len(conf.search))
	// If name has enough dots, try unsuffixed first.
	if hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	// Try suffixes that are not too long (see isDomainName).
	for _, suffix := range conf.search {
		fqdn := name + suffix
		if !avoidDNS(fqdn) && len(fqdn) <= 254 {
			names = append(names, fqdn)
		}
	}
	// Try unsuffixed, if not tried first above.
	if !hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	return names
}
