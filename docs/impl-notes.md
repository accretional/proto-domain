# proto-domain implementation notes

## Goal recap

- Define EBNF grammars for canonical Domain / Hostname / FQDN / TLD textual
  forms based on the proto types in this repo (`domain.proto`,
  `dns_record.proto`, `resolver.proto`, `url.proto`).
- Use `github.com/accretional/gluon` for grammar parsing. Prefer v2 surface
  where it exists; fall back to v1 `lexkit` for direct calls.
- Build a local gRPC implementation of the `Resolver.GetDNSRecords` RPC
  (declared in `resolver.proto`) and validate against real DNS using the Go
  standard library's `net.Resolver`.
- LET_IT_RIP.sh resolves `localhost` and `accretional.com` through the
  local server, end-to-end.
- Track progress frequently in docs/progress-log.md.

## Repository layout decisions

Mirroring the proto-ip layout the user has been moving toward:

    .
    ├── proto/domainpb/         # .proto sources + generated *.pb.go
    │   ├── domain.proto
    │   ├── dns_record.proto
    │   ├── resolver.proto
    │   └── url.proto
    ├── lang/                   # EBNF grammars (one per format)
    ├── internal/grammar/       # Go: load grammar, parse, AST→proto, proto→string, fuzz
    ├── internal/resolver/      # Go: net.Resolver-backed Resolver service impl
    ├── cmd/server/             # gRPC server binary
    ├── cmd/client/             # CLI client (LET_IT_RIP smoke test)
    ├── setup.sh build.sh test.sh LET_IT_RIP.sh
    └── docs/                   # impl-notes.md, progress-log.md

The user's pre-existing `domain.proto`, `dns_record.proto`,
`resolver.proto`, `url.proto` at the repo root are moved into
`proto/domainpb/`. `option go_package` updated to
`github.com/accretional/proto-domain/proto/domainpb;domainpb` so generated
Go ends up next to the .proto files.

`url.proto` originally imported `accretional/proto-ip/ip.proto`, but
proto-ip moved its IP message to `proto/ippb/ip.proto`. We update the
import path accordingly. Since the URL message is not on the critical
path for the Resolver work, we do this only as much as needed to keep the
tree compiling — if proto-ip churn breaks things, we can drop URL from
codegen until it stabilizes.

## Gluon usage strategy

`gluon/v2/metaparser` is the new entrypoint, but it currently delegates
EBNF + CST parsing to v1 `lexkit` internally (see v2/README.md). For our
purposes we either:

1. Use v2 in-process: `metaparser.WrapString(s)` →
   `metaparser.ParseEBNF(doc)` → `metaparser.ParseCST(req)`.
2. Or call v1 `lexkit.Parse` + `lexkit.ParseAST` directly.

Both paths produce an ASTDescriptor we can walk. We pick **v2** as the
public surface because the user explicitly asked for v2 where possible;
internally v2 still rides on v1 so we get the same matured engine.

The CST output is a tree of `pb.ASTNode { kind, value, children, location }`.
Converting to typed protos (Domain / TLD / etc.) is a tree walk: dispatch
on `kind` matching the rule names in our `.ebnf` files.

## EBNF grammar design

The proto types we need to mirror:

- `Domain { hostname, repeated labels, TLD tld }` — implies a parser that
  produces an ordered label sequence plus a final TLD label.
- `TLD { oneof { InternetTLD internet, string custom } }` — known TLDs
  (just `COM` for now per `domain.proto`) get the enum mapping; everything
  else stays as a custom string.

Grammars (in priority order):

1. `lang/domain.ebnf` — RFC 1035 / RFC 5890 LDH hostname, dot-separated
   labels, optional trailing dot for absolute FQDN, max 63 chars per
   label (enforced syntactically via repetition bounds where practical;
   numeric checks done in Go after parse).
2. `lang/hostname.ebnf` — single label (LDH).
3. `lang/tld.ebnf` — single label following stricter TLD rules
   (alphabetic-start, ICANN-conformant character set).
4. `lang/fqdn.ebnf` — domain ending in `.` (absolute form).

Lowercase rule names are treated as lexical by lexkit's parser
(`DefaultIsLexical`), which suppresses whitespace skipping inside them —
critical for hostnames where any whitespace is invalid.

## Resolver service plan

The proto signature is `rpc GetDNSRecords(Domain) returns(stream DNSRecord)`.
We pass the printed domain string into `net.Resolver`'s typed lookup
methods (`LookupHost`, `LookupCNAME`, `LookupNS`, `LookupMX`, `LookupTXT`,
`LookupAddr`, `LookupSRV`) and stream a `DNSRecord` per result, populating
`type`, `class=Internet`, `text`/`raw`, and `ttl_seconds=0` (Go's stdlib
resolver hides TTLs).

If we need per-record TTLs later we can swap in `github.com/miekg/dns`,
but the standard library is enough for the v0 LET_IT_RIP target
(`localhost` + `accretional.com`).

## DNS resolver — fork strategy (decided 2026-04-29)

We're forking the stdlib `net` DNS path into `dns/` rather than wrapping
`net.Resolver` or pulling in `miekg/dns`. The decision rests on three
constraints:

1. **TTLs are mandatory** for `DNSRecord.ttl_seconds`. `net.Resolver`
   parses TTLs and discards them.
2. **proto-domain wants the whole DNS spec plus extensions** — long-tail
   record types (SOA/CAA/TLSA/SVCB/…), DNSSEC, eventually iterative
   resolution / AXFR / DoT / DoH / mDNS. miekg/dns covers most of this
   but it's a different upstream to track; staying parallel to stdlib
   keeps the behavioral story consistent with the rest of Go's
   ecosystem.
3. **Forking is mechanical** at the wire level. Upstream uses a few
   `internal/*` packages (`bytealg`, `stringslite`, `strconv`,
   `godebug`) that aren't importable, but each call site has a 1-line
   stdlib equivalent (`strings.IndexByte`, `strings.HasPrefix`, etc.).
   `// fork:` comments mark every change, so re-forking against a newer
   Go is a diff-and-replay job, not an exegesis.

The fork is staged in three layers, mirroring upstream's structure
(see `dns/COVERAGE.md` for the full breakdown):

- **Layer 1 — wire engine**: `newRequest`, UDP/TCP round-trips,
  `exchange`, `tryOneName`, header sanity, `resolverConfig`,
  `dnsConfig`, `nameList`, `/etc/hosts`. **Done** (~1361 lines).
- **Layer 2 — high-level Lookup* API**: `goLookupX` per record type,
  `Resolver.LookupX` public methods. **In progress** (~550 lines).
  Adds TTL exposure as a side effect of forking.
- **Layer 3 — extensions**: long-tail record types, direct-to-server
  queries, iterative lookups, AXFR/IXFR, EDNS0 options, DoT/DoH, mDNS,
  DNSSEC. Sequenced after Layer 2 lands.

`internal/resolver/resolver.go` will switch from `net.Resolver` to
`dns.Resolver` once Layer 2 is wired. The gRPC service stays the same
shape — only the underlying lookup path changes — so downstream callers
(cmd/client, tests) need no changes.

### Re-forking process (when Go is upgraded)

1. Update `dns/UPSTREAM_VERSION` to record the new `go version`.
2. Diff each forked file against `$GOROOT/src/net/<file>`.
3. For each upstream change: re-apply on top of our `// fork:` deltas.
4. Most changes are isolated — internal/* swaps don't drift across Go
   releases, the wire-level RFC-driven code rarely changes. Behavioral
   changes (EDNS handling, error wrapping, search-domain rules) are
   the ones to scrutinize.

## Open questions / TODO

- proto-ip is mid-rewrite; we may need to vendor a stable snapshot if its
  generated Go shifts under us. For now we use a `replace` directive
  pointing at the local checkout.
- The `dns_record.proto` `format` oneof is loose (bytes/text). For now
  the resolver emits `text` only. Typed per-record formats are a follow-up.
- URL parsing/printing is out of scope for the LET_IT_RIP target but
  url.proto needs to compile so we keep its grammar slot for later.
