# Progress log

Reverse-chronological. Newest entries on top.

## 2026-04-29 (evening — Layer 2 done, TTLs flowing)

**Layer 2 complete + wired in.** `internal/resolver/` now uses
`dns.Resolver` instead of `net.Resolver`; `DNSRecord.ttl_seconds` is
populated from the wire. LET_IT_RIP shows real TTLs for
accretional.com (A/AAAA=300, NS=83301, MX=231, TXT=300).

**New files**:
- `dns/records.go` (114 lines) — `Header`, `Record` interface, typed
  records (`ARecord`, `AAAARecord`, `CNAMERecord`, `NSRecord`,
  `MXRecord`, `TXTRecord`, `SRVRecord`, `PTRRecord`).
- `dns/golookup.go` (399 lines) — TTL-preserving `goLookupX`
  implementations adapted from upstream's bottom-of-`dnsclient_unix.go`.
  Sequential A+AAAA (vs upstream's parallel fanout — simpler, no
  package-level WaitGroup); always FilesDNS order for /etc/hosts
  precedence; no `hostLookupOrder` enum.
- `dns/lookup.go` (210 lines) — public `Resolver.LookupX` methods +
  generic `LookupRecords(ctx, name, qtype) []Record` for record
  types not yet typed. Drops upstream's `LookupPort` (not DNS) and
  `LookupHost`/`LookupIP`/`LookupNetIP` wrappers (callers can read
  IP off `*ARecord` / `*AAAARecord` directly).
- `dns/sort.go` (68 lines) — RFC 5321 / RFC 2782 sort helpers retyped
  to operate on `*MXRecord` / `*SRVRecord` instead of upstream's bare
  `*MX` / `*SRV`.
- `dns/lookup_test.go` (71 lines) — `TestLookupLocalhost` (hosts file
  smoke), `TestLookupAccretional` (live wire smoke + TTL > 0 check).

**Dropped** from `dns/dnsclient.go`: upstream-shaped `MX` / `NS` / `SRV`
struct types and their `byPref` / `byPriorityWeight` sort wrappers.
Layer 2 returns `*MXRecord` / `*NSRecord` / `*SRVRecord` everywhere
with sorting in `sort.go`, so the bare types were unused. Drop is
documented in `dnsclient.go` as a `// fork:` block.

**dns/ totals**: 2150 lines across 11 files (1979 source + 71 test +
~100 doc). Up from 1361 in the Layer-1-only state.

**LET_IT_RIP**: ✓ green. Both localhost and accretional.com paths
flow through `dns/`, TTLs appear in client output:

```
A     ttl=300    172.67.132.2
AAAA  ttl=300    2606:4700:3031::6815:46d
NS    ttl=83301  liberty.ns.cloudflare.com.
MX    ttl=231    1 smtp.google.com.
TXT   ttl=300    v=spf1 include:_spf.google.com ~all
```

**Next checkpoint** (Task #18): long-tail record types (SOA, CAA,
SSHFP, TLSA, NAPTR, SVCB/HTTPS, URI, LOC, HINFO, …). Pattern is the
same per type — define typed body in `records.go`, parse from
`dnsmessage.UnknownResource` (or the typed `XResource` if dnsmessage
supports it), add a switch case in `parseGenericAnswers`. Estimated
~500 lines.

After that, Task #19: direct-to-server queries, iterative resolution,
AXFR/IXFR, EDNS0 options, DoT/DoH, mDNS. Each is independently
landable.

DNSSEC (Task #20) deferred per user direction.

## 2026-04-29 (afternoon — pre-Layer-2 checkpoint)

**Decision**: commit to forking the stdlib `net` DNS path into `dns/`
rather than using `net.Resolver` or a third-party DNS library
(miekg/dns). Rationale: proto-domain's roadmap is the whole DNS spec
plus extensions; a faithful stdlib fork keeps us close to upstream
behavior while letting us expose TTLs, add the long-tail record types,
and eventually do DNSSEC. See `dns/COVERAGE.md` for the full audit.

**Status as of this commit**:
- `dns/` Layer 1 (wire engine) **done**: ~1361 lines across 6 files,
  faithful adaptation of upstream (Go 1.26.2). All `// fork:`-marked.
  Compiles. Not yet wired into `internal/resolver/`.
- `dns/COVERAGE.md` **done**: audit of upstream vs `dns/` vs missing
  from `net` itself. Sets the work plan.
- `dns/README.md`, `LICENSE_GO`, `UPSTREAM_VERSION` **done**: provenance.
- `internal/grammar/` and `internal/resolver/` **slimmed**: production
  files now contain only production code; test scaffolding (`All()`,
  `Resolve()`, `stream`, `collector`) lives in `_test.go` files.
  `go_resolver_impl.go` deleted (replaced by `dns/COVERAGE.md`).
- `internal/resolver/` still uses `net.Resolver` on the live path.
  TTLs are 0. LET_IT_RIP green.
- Picked up gluon commit `e121e84` (require ParseAST to consume
  whole input) — dropped our redundant `consumedAll` check.

**Next steps** (mapped to TaskList #15–#20):

1. **Layer 2 — `goLookup*` + `Lookup*` API** (~550 lines).
   - `dns/golookup.go`: fork the bottom half of upstream's
     `dnsclient_unix.go` (`goLookupHostOrder`, `goLookupIPCNAMEOrder`,
     `goLookupCNAME`, `goLookupPTR`, `goLookupSRV`, `goLookupMX`,
     `goLookupNS`, `goLookupTXT`). All TTL-preserving.
   - `dns/lookup.go`: fork the public `Resolver.LookupX` methods
     from upstream's `lookup.go` (Host, IPAddr, IP, NetIP, CNAME, NS,
     MX, TXT, SRV, Addr). Skip `LookupPort` (not DNS).
2. **TTL-aware Record API**. Add `Header` struct (Name/Type/Class/TTL)
   plus typed bodies per record type. Generic `LookupRecords(ctx,
   name, qtype) []Record` for the generic case. Existing
   `LookupX` methods stay net.Resolver-shaped for drop-in compat.
3. **Wire `dns/` into `internal/resolver/`**. Replace
   `net.Resolver.LookupX` calls with `dns.Resolver.LookupX`.
   Populate `DNSRecord.ttl_seconds` from each record's TTL. Verify
   LET_IT_RIP shows TTLs.
4. **Long-tail record types** (~500 lines): SOA, CAA, SSHFP, TLSA,
   NAPTR, SVCB/HTTPS, URI, LOC, HINFO, RP, AFSDB, KX. Pattern repeats
   per type; one task ticket each is overkill, batch them.
5. **Layer 3 features**: direct-to-server queries (~50 lines),
   iterative resolution (~200 lines), AXFR/IXFR (~150 lines), EDNS0
   options (DO/ECS/Cookies/EDE, ~150 lines), DoT/DoH (~230 lines),
   mDNS (~300 lines).
6. **DNSSEC** (deferred): RRSIG/DNSKEY/DS/NSEC/NSEC3 + crypto algos +
   trust chain validation. Several thousand lines. Punted from first
   pass per the user's direction.

**Out of scope intentionally**: cgo path, Windows, /etc/protocols and
/etc/services (`LookupPort`), `nettrace` debug hooks, the
`linkname`-based hall-of-shame helpers in upstream `dnsclient.go`.

## 2026-04-29 (end-of-day, v0 done)

## 2026-04-29 (end-of-day, v0 done)

- LET_IT_RIP.sh green end-to-end:
  - All unit + resolver tests pass.
  - Smoke: localhost resolves to 3 records (AAAA ::1, A 127.0.0.1, NS localhost.).
  - Smoke: accretional.com resolves to 10 records (4 IPs, 2 NS, 1 MX, 3 TXT).
  - Long fuzz: 10s per grammar (Domain/Hostname/TLD), no findings.
- Stable file inventory:
  - `proto/domainpb/{domain,dns_record,resolver,url}.proto` — moved from
    repo root, unified package `domain`, fixed cross-imports.
    Renamed enum collisions (`Unknown`→`RECORD_UNKNOWN`/`CLASS_UNKNOWN`,
    `HTTPS`→`SCHEME_HTTPS`, etc.). Added `fully_qualified` bool to
    Domain.
  - `internal/grammar/lang/{domain,hostname,tld,fqdn}.ebnf` — final
    grammars use character ranges (`"a" ... "z"`) rather than
    alternation-of-singletons. See impl note about the keyword
    boundary check for rationale.
  - `internal/grammar/{grammar,domain}.go` — Grammar struct caches
    each parsed `pb.GrammarDescriptor`; ParseDomain/ParseHostname/
    ParseTLD walk the AST + validate against RFC 1035 length/hyphen
    rules; PrintDomain canonicalizes back.
  - `internal/grammar/{grammar,fuzz}_test.go` — many positive +
    negative examples, plus 3 fuzz targets that assert determinism +
    print/parse round-trip.
  - `internal/resolver/resolver.go` + tests — net.Resolver-backed
    Service. `Resolve()` is the pure-Go entry; `GetDNSRecords()` is
    the gRPC streaming wrapper.
  - `cmd/server`, `cmd/client` — gRPC server + CLI smoke client.
  - `setup.sh build.sh test.sh LET_IT_RIP.sh` — idempotent pipeline.
- Notable findings while implementing:
  - gluon's `lexkit.matchTerminal` applies a keyword-boundary check
    that rejects single-letter terminals followed by another letter or
    digit. Single-quoted alternations of letters fail for almost every
    non-trivial input. Switched all letter productions to character
    ranges, which `matchRange` handles without the boundary check.
  - gluon v2's CST stage delegates to v1's parser internally, so v2
    inherits the same gotcha — the fix sits in the .ebnf file, not in
    a parser flag.
  - The standard library resolver does not surface TTLs; `ttl_seconds`
    in DNSRecord stays 0 for now. Switching to miekg/dns would fix it.

## 2026-04-29 (start of day)

- Read CLAUDE.md, all .proto files, gluon v1 + v2 README/source, proto-ip
  layout (used as scaffolding template).
- Decided on layout: protos under `proto/domainpb/`, grammars under
  `internal/grammar/lang/` (had to colocate with Go for `go:embed`),
  Go under `internal/`, binaries under `cmd/`, sibling scripts.
- Wrote initial `docs/impl-notes.md` capturing decisions.
