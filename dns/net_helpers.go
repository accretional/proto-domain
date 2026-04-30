// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_GO file.
//
// Adapted from $GOROOT/src/net/net.go and $GOROOT/src/net/parse.go.
// Just the small helpers our forked DNS files reference: the
// temporaryError type, mapErr(), errNoSuchHost, the
// stringsHasSuffixFold ASCII fold, and a tiny Resolver shim that
// stands in for upstream's full net.Resolver.
//
// Material changes vs upstream are listed in dns/README.md and marked
// inline with "// fork:" comments.

package dns

import (
	"context"
	"errors"
	"net"
)

// fork: errNoSuchHost is upstream's "name not found" sentinel
// (defined in net/net.go around the DNS error wiring). We expose it
// at package level for our Lookup* layer.
var errNoSuchHost = errors.New("no such host")

// fork: errCanceled / errTimeout — upstream's mapErr translates
// context errors into these sentinels.
var (
	errCanceled = errors.New("operation was canceled")
	errTimeout  = errors.New("i/o timeout")
)

// temporaryError implements net.Error with Temporary() == true.
// Mirrors upstream net.go.
type temporaryError struct{ s string }

func (e *temporaryError) Error() string   { return e.s }
func (e *temporaryError) Temporary() bool { return true }
func (e *temporaryError) Timeout() bool   { return false }

// mapErr maps context errors to net's historical internal sentinels.
// Mirrors upstream net.go.
func mapErr(err error) error {
	switch err {
	case context.Canceled:
		return errCanceled
	case context.DeadlineExceeded:
		return errTimeout
	}
	return err
}

// stringsHasSuffixFold reports whether s ends in suffix,
// ASCII-case-insensitively. Mirrors upstream parse.go helper.
func stringsHasSuffixFold(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	tail := s[len(s)-len(suffix):]
	if len(tail) != len(suffix) {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		a, b := tail[i], suffix[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

// Resolver is the local stand-in for upstream's net.Resolver. We keep
// only the fields the forked query loop reads: a custom Dial and the
// StrictErrors flag. Anything else (PreferGo, etc.) is irrelevant to a
// pure-Go-only fork.
//
// Field shapes match upstream so consumers used to net.Resolver can
// translate trivially.
type Resolver struct {
	// Dial optionally specifies an alternate dialer for use by the
	// forked DNS resolver. If nil, net.Dialer{} is used.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// StrictErrors makes the resolver abort the entire query as soon
	// as a single sub-query returns a temporary error, instead of
	// trying the next server / search suffix. Off by default.
	StrictErrors bool
}

// dial picks the correct dialer for a query. Mirrors upstream
// (r *Resolver) dial.
func (r *Resolver) dial(ctx context.Context, network, server string) (net.Conn, error) {
	if r != nil && r.Dial != nil {
		return r.Dial(ctx, network, server)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, server)
}

// strictErrors mirrors upstream (r *Resolver) strictErrors.
func (r *Resolver) strictErrors() bool {
	return r != nil && r.StrictErrors
}

// newDNSError wraps an underlying error as a *net.DNSError matching
// upstream's helper. Upstream stores extra IsTimeout/IsTemporary/
// IsNotFound fields; we set the same flags so callers' type
// assertions keep working.
func newDNSError(err error, name, server string) *net.DNSError {
	var (
		isTimeout   bool
		isTemporary bool
		unwrap      error
	)
	if e, ok := err.(net.Error); ok {
		isTimeout = e.Timeout()
		isTemporary = e.Temporary()
	}

	isNotFound := errors.Is(err, errNoSuchHost)

	// Upstream extracts the wrapped err for OpError to keep the
	// chain crisp.
	if oe, ok := err.(*net.OpError); ok {
		unwrap = oe.Err
	}

	return &net.DNSError{
		UnwrapErr:   unwrap,
		Err:         err.Error(),
		Name:        name,
		Server:      server,
		IsTimeout:   isTimeout,
		IsTemporary: isTemporary,
		IsNotFound:  isNotFound,
	}
}
