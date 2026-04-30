# dns

A minimal pure-Go DNS resolver, **forked from Go's standard library**
`net` package, with the explicit goal of exposing per-record TTLs that
the stdlib resolver hides.

## Why this exists

`net.Resolver`'s `Lookup*` methods strip TTLs out of the parsed DNS
response before returning to callers. For `proto-domain`'s
`DNSRecord.ttl_seconds` field we need them. Switching to a third-party
DNS library (`miekg/dns`, `bluele/gcache-dns`, etc.) was the obvious
alternative, but:

- The stdlib's resolver is widely deployed, well-tested, and matches
  the behavior the rest of the host already uses (resolv.conf,
  /etc/hosts, search domain semantics).
- Forking a small surface lets us track upstream changes by re-diffing
  against `$GOROOT/src/net/` rather than auditing a separate library
  for behavior drift.

Forking inside the project keeps both properties: stdlib-equivalent
behavior + visible TTLs.

## Provenance

Sources are adapted from these files in the Go standard library:

| Local file       | Upstream file (in `$GOROOT/src/net/`) | Purpose                          |
|------------------|---------------------------------------|----------------------------------|
| `dns.go`         | `dnsclient.go`                        | Typed records, helpers           |
| `config.go`      | `dnsconfig.go` + `dnsconfig_unix.go`  | resolv.conf parser, dnsConfig    |
| `hosts.go`       | `hosts.go`                            | /etc/hosts file lookup           |
| `client.go`      | `dnsclient_unix.go`                   | DNS query loop (UDP+TCP)         |
| `lookup.go`      | `lookup.go` + `lookup_unix.go`        | High-level Lookup* with TTLs     |

**Pinned upstream version**: see `UPSTREAM_VERSION` (a single-line file
recording `go version` at the time of fork). Re-fork by overwriting the
files above against a newer Go's `src/net/` and updating
`UPSTREAM_VERSION`.

**Upstream tracking**:

- Source browser: <https://go.googlesource.com/go/+/refs/heads/master/src/net/>
- GitHub mirror:  <https://github.com/golang/go/tree/master/src/net>
- Recent net DNS changes by file:
  <https://go.googlesource.com/go/+log/master/src/net/dnsclient_unix.go>

The `dnsmessage` low-level wire-format library is **not** forked — we
import `golang.org/x/net/dns/dnsmessage` directly, which is the same
public package the stdlib's `net` package uses internally. Tracking
that dependency happens through `go.mod` like any other.

## Modifications relative to upstream

Material changes (in addition to mechanical package-rename + import
adjustments):

1. **TTL exposure.** Every `Lookup*` returns `[]*Record` (or a
   record-typed equivalent) where each `Record` carries the matched
   resource's `Header().TTL` from the wire response. Upstream parses
   this same field and discards it.
2. **No cgo path.** Upstream's `Resolver` can defer to libc via cgo;
   this fork is pure-Go only. All cgo branches are removed.
3. **No Windows.** `dnsconfig_windows.go` is not forked. Only
   `unix`-style /etc/resolv.conf parsing.
4. **No search-domain rewriting in our public API.** Upstream's
   `nameList()` does ndots+search expansion; we keep the implementation
   for parity but the public Lookup API takes already-rooted names by
   convention. Callers that want search expansion can pass an unrooted
   name; the expansion logic still runs.
5. **Internal-package replacements.** Upstream uses
   `internal/bytealg`, `internal/godebug`, `internal/strconv`,
   `internal/stringslite` — packages that are not importable outside
   the standard library. We swap in the equivalent stdlib `bytes`,
   `strconv`, `strings` calls. These are mechanical replacements and
   should be re-applied verbatim on each re-fork.
6. **No DNSError struct.** We pass through underlying errors plus a
   sentinel `errNoSuchHost`. Upstream's `*DNSError` carries server,
   name, IsTemporary etc.; we don't surface those today and would add
   them only if a caller needed them.
7. **Dropped `linkname` hacks** for `defaultNS` and `isDomainName`.
   These exist in upstream to keep accidental external consumers
   working; nothing outside our project links into us.

## Re-forking from upstream

```sh
GOROOT=$(go env GOROOT)
diff -ru "$GOROOT/src/net/dnsclient_unix.go" dns/client.go      | less
diff -ru "$GOROOT/src/net/dnsconfig_unix.go" dns/config.go      | less
diff -ru "$GOROOT/src/net/hosts.go"          dns/hosts.go       | less
# Apply non-mechanical upstream changes by hand, keeping our
# modifications above. Update UPSTREAM_VERSION when done.
```

A refresh that touches only stdlib internals (e.g. switching
`internal/bytealg` calls between revisions) needs no manual merge.
Behavioral changes — new resolv.conf option, new EDNS handling — should
be inspected.

## License

Go's standard library is BSD-licensed. The header on every file in
this package preserves the original copyright + license notice. See
`LICENSE_GO` for the upstream text.
