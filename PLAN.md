# AlOsint — Product Plan

**Document status:** Draft for review  
**Target release:** V1.0  
**Implementation language:** Goose with C interop  
**Last updated:** 2026-11-11

---

## 1. Product Summary

AlOsint is a command-line OSINT tool for analysts, security engineers, and incident responders. It consolidates five common public-source reconnaissance tasks into a single, predictable workflow with human-readable text output and a stable JSON contract suitable for automation.

V1.0 is deliberately narrow: it collects and normalizes information from **public, lawful sources** and never performs intrusive testing, exploitation, authentication attempts, or credential collection.

### 1.1 Product principles

1. **Passive and low-impact by default.** Only public data sources and ordinary HTTP requests. No port scanning, brute forcing, fuzzing, or exploitation.
2. **One target, one command.** A single invocation produces a complete, reproducible report.
3. **Scriptable first.** JSON output is a versioned contract, not an afterthought.
4. **Transparent provenance.** Every fact names the source that produced it and when it was observed.
5. **Consent before collection.** The tool confirms authorized use before the first scan and records that acknowledgment.
6. **Graceful degradation.** A failing module produces a partial report with explicit warnings, never a silent gap.

### 1.2 Goals for V1.0

- Give an analyst a complete public-footprint snapshot of a domain or IP in under two minutes.
- Make the same data consumable by scripts through deterministic JSON.
- Provide optional Tor transport for analysts who require it, without marketing it as anonymity.
- Ship a documented, testable foundation that V2.0 integrations can extend without redesign.

### 1.3 Non-goals for V1.0

- Vulnerability discovery, exploitation, or active service probing.
- Credential, breach, paste, or leak-site collection of any kind.
- Continuous monitoring, scheduling, or background agents.
- Persistence, historical comparison, or a database.
- A graphical interface.
- Guaranteed anonymity or evasion of attribution.

---

## 2. Target Users and Personas

| Persona | Context | Primary need |
|---|---|---|
| **Security analyst ("Ana")** | Incident triage, asset inventory | Fast domain footprint with defensible sourcing |
| **Penetration tester ("Priya")** | Pre-engagement reconnaissance with written scope | Consistent output she can attach to a report |
| **Bug bounty hunter ("Ben")** | Program-scoped recon | Quick subdomain and HTTP fingerprint overview |
| **Threat intel researcher ("Tomas")** | Enrichment of indicators | JSON that pipes into existing tooling |
| **Journalist / researcher ("Jo")** | Public-interest verification | Clear provenance and no covert collection |

### 2.1 Assumptions about users

- They operate on Linux, macOS, or Windows via a terminal.
- They understand DNS, HTTP, WHOIS/RDAP, and ASN concepts.
- They have a lawful basis and permission for the targets they query.
- They prefer composable CLI tools over dashboards.

---

## 3. V1.0 Scope

### 3.1 In scope

| Capability | Description | Data source |
|---|---|---|
| **DNS enumeration** | Resolve A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV records; follow CNAME chains; report TTLs | System or user-specified recursive resolver over DNS |
| **WHOIS / RDAP** | Registrar, creation/update/expiry dates, status codes, nameservers, registrant organization where publicly published; RDAP preferred, WHOIS fallback | IANA bootstrap, RDAP services, port 43 WHOIS |
| **Subdomain discovery** | Certificate Transparency log lookup and normalization of unique hostnames | crt.sh (public CT search) |
| **HTTP fingerprinting** | Status, redirect chain, headers, TLS certificate summary, detected server/framework/CDN/WAF hints, security header presence | Direct HTTP/HTTPS requests to discovered hosts |
| **IP geolocation / ASN** | Country, region, city, coordinates (coarse), ASN, organization, network prefix | Public RDAP/WHOIS for ASN; a configurable public geolocation source |
| **CLI text output** | Human-readable, colorized when attached to a TTY | Local |
| **JSON output** | Versioned, deterministic, schema-documented report | Local |
| **Optional Tor transport** | Route supported outbound requests through a local SOCKS5 proxy | Local Tor client |

### 3.2 Explicitly out of scope for V1.0

- Shodan, Censys, VirusTotal, or any API-keyed enrichment.
- SQLite or any persistent storage; no scan history, diffing, or resume.
- Web UI, desktop UI, or hosted service.
- Social media, people search, email enumeration, or username correlation.
- Breach data, stealer logs, combolists, paste sites, leak forums, or dark-web marketplaces.
- Subdomain brute forcing, DNS zone transfer attempts, or wildcard abuse.
- Port scanning, banner grabbing beyond the single fingerprint request, or vulnerability checks.
- Screenshots, headless browsers, or JavaScript execution.
- Distributed or multi-target scanning.
- Third-party plugin loading from untrusted paths (interface reserved, loading deferred).

### 3.3 Scope guardrails

- **No target lists.** V1.0 accepts exactly one target per invocation.
- **No crawling.** HTTP module fetches a bounded set of URLs (root plus redirects), never spidering.
- **No authentication.** The tool never submits credentials or session tokens.
- **No payloads.** Requests use ordinary GET/HEAD semantics with a truthful, configurable User-Agent.
- **No history.** Reports exist only in memory and in the user-specified output file.
- **No telemetry.** AlOsint never phones home, and never transmits results to the project.

---

## 4. Functional Specification by Module

### 4.1 DNS enumeration

**Behavior**

- Query the target domain for A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and SRV records.
- Use the system resolver by default; allow `--resolver` to select a specific recursive resolver.
- Follow CNAME chains up to a fixed depth (8) and report each hop.
- Preserve raw record data and add normalized fields (for example, parsed MX priority and exchange).
- Report NXDOMAIN, SERVFAIL, and timeouts distinctly.

**Acceptance criteria**

- All eight record types are attempted even when earlier types fail.
- A CNAME loop terminates with an explicit warning rather than hanging.
- Output is stable across runs for the same zone, modulo TTL and ordering rules.
- No queries are sent to authoritative servers directly; recursion is delegated to the configured resolver.

### 4.2 WHOIS / RDAP

**Behavior**

- Discover the correct RDAP endpoint through IANA bootstrap data.
- Prefer RDAP over WHOIS; fall back to WHOIS on port 43 when RDAP is unavailable or rate limited.
- Normalize registrar, key dates, status codes, nameservers, and public registrant organization.
- Preserve the raw response in a clearly separated field for auditability.
- Never attempt to bypass redaction or privacy services.

**Acceptance criteria**

- Works for gTLDs and the ccTLDs that publish RDAP or WHOIS.
- Missing or redacted fields are reported as `null` with a reason, not fabricated.
- Rate-limit responses are surfaced as warnings, not retried indefinitely.
- The tool identifies which protocol produced the result.

### 4.3 Subdomain discovery via crt.sh

**Behavior**

- Query crt.sh for certificates matching the apex domain, including wildcard certificates.
- Extract unique DNS names, normalize to lowercase, strip wildcards, and discard entries outside the target apex.
- Deduplicate and optionally resolve discovered names to confirm they are live.
- Record the certificate identifiers (CRT shard/ID) that produced each name.

**Acceptance criteria**

- Results are deduplicated and sorted deterministically.
- The module respects crt.sh rate limits and backs off on HTTP 429/503.
- If crt.sh is unreachable, the report contains a warning and the other modules still complete.
- No brute-force wordlist is used; discovery is CT-log only.

### 4.4 HTTP fingerprinting

**Behavior**

- Probe the apex and a bounded number of discovered hosts over HTTPS, then HTTP if HTTPS fails.
- Capture status code, final URL, redirect chain (max 10), response headers, and a TLS certificate summary.
- Detect server software, framework hints, CDN, and WAF signatures from headers and well-known response characteristics.
- Report presence or absence of common security headers.
- Send a single request per host; do not follow links or fetch assets.

**Acceptance criteria**

- Redirect loops terminate with a warning.
- Response bodies are not stored by default; only headers and metadata are retained.
- Header names are case-insensitive for matching but preserved as received.
- Fingerprints are labeled as **heuristic hints**, never as confirmed vulnerabilities.

### 4.5 IP geolocation and ASN

**Behavior**

- Resolve the target (or an IP literal) to one or more addresses.
- For each unique address, report ASN, organization, network prefix, and coarse geolocation.
- Use a configurable, publicly documented data source with clear attribution.
- Mark confidence and granularity when the provider supplies them.

**Acceptance criteria**

- Private, reserved, and loopback addresses are labeled and not sent to external providers.
- IPv4 and IPv6 are both supported.
- The provider and lookup timestamp are recorded for every result.
- Geolocation is described as approximate, never as a person's location.

---

## 5. User Stories

Each story includes acceptance criteria. IDs are stable for roadmap and test tracking.

### US-01 — First authorized scan
**As an analyst,** I want to scan a domain I am authorized to assess so that I get a complete footprint in one command.

- Given I have not run AlOsint before, when I start a scan, then I must acknowledge authorized use before any network request is made.
- Given a valid domain, when the scan completes, then DNS, WHOIS/RDAP, subdomains, HTTP, and IP sections are present.
- Given a module fails, then the remaining modules still run and the report lists a warning.

### US-02 — DNS records at a glance
**As an analyst,** I want DNS records grouped by type so that I can spot mail, delegation, and verification records quickly.

- Records are grouped and sorted by type, then by value.
- CNAME chains are shown as ordered hops.
- TTLs and record data are preserved.

### US-03 — Registration context
**As a penetration tester,** I want registrar and registration dates so that I can judge whether a domain is newly registered or well established.

- The report includes registrar, creation date, expiry date, and status codes.
- Redacted fields are explicitly marked rather than omitted silently.
- The protocol used (RDAP or WHOIS) is visible.

### US-04 — Discover forgotten subdomains
**As a bug bounty hunter,** I want certificate transparency results so that I can find hosts that are not linked from the main site.

- Unique in-scope hostnames are listed.
- Wildcard entries are normalized and clearly labeled.
- Results can be exported as JSON without post-processing.

### US-05 — Identify the edge stack
**As a security engineer,** I want HTTP and TLS fingerprints so that I can tell which CDN, server, and framework sits in front of a domain.

- The report lists server, CDN/WAF hints, TLS issuer, and certificate expiry.
- Redirect chains are shown in order.
- Security header presence is summarized.
- Findings are labeled heuristic, not definitive.

### US-06 — Enrich an IP indicator
**As a threat intel researcher,** I want ASN and coarse geolocation for an IP so that I can contextualize an indicator.

- The report includes ASN, organization, prefix, country, and city when available.
- Private and reserved ranges are flagged and not looked up externally.
- The provider is named.

### US-07 — Machine-readable output
**As an automation engineer,** I want JSON on stdout so that I can pipe AlOsint into my pipeline.

- `--json` emits exactly one JSON document to stdout and nothing else.
- Progress and diagnostics go to stderr.
- The document validates against the published schema for its `schema_version`.

### US-08 — Save a report
**As an analyst,** I want to write results to a file so that I can attach them to a ticket.

- `-o report.json` writes the same bytes that would have gone to stdout.
- The tool refuses to overwrite an existing file unless `--force` is supplied.
- File writes are atomic (temporary file plus rename).

### US-09 — Route through Tor
**As a privacy-conscious analyst,** I want an optional Tor transport so that my source address is not the one contacting public data sources.

- `--tor` routes supported HTTP(S) traffic through a local SOCKS5 proxy.
- If no proxy is reachable, the scan fails before any direct request is attempted.
- The report records that Tor was requested and whether it was actually used.
- The tool never claims that Tor provides anonymity.

### US-10 — Control which modules run
**As a power user,** I want to enable or disable modules so that I can avoid noisy or slow sources.

- `--plugins` accepts a comma-separated list of module names.
- `--plugins list` prints available modules and exits successfully.
- Unknown module names produce a usage error and a list of valid names.
- Dependencies between modules are resolved automatically or reported clearly.

### US-11 — Predictable failures
**As a script author,** I want stable exit codes so that my automation can branch correctly.

- Usage errors, no-result scans, network failures, authorization refusal, and upstream rate limits are distinguishable.
- Errors are reported on stderr in text mode and in the JSON `errors` array in JSON mode.
- Interrupting with Ctrl-C exits promptly and marks the report as partial.

### US-12 — Reproducible investigations
**As a reviewer,** I want to know when and from where each fact came so that I can audit a report.

- Every module result includes source, timestamp, and elapsed time.
- The report includes tool version, schema version, and the exact flags used.
- Raw upstream responses are separated from normalized fields.

---

## 6. CLI User Experience

### 6.1 Invocation model

```
alosint -d <target> [options]
alosint --plugins list
alosint --version
```

`-d` is the only required input for a scan. `--target` is an alias. The target may be a domain name or an IP literal; AlOsint infers the type unless `--type` is given.

### 6.2 Flags

| Flag | Argument | Default | Purpose |
|---|---|---|---|
| `-d`, `--domain`, `--target` | domain or IP | required | Scan target |
| `-t`, `--type` | `domain`, `ip`, or comma list | inferred | Force target interpretation |
| `-m`, `--modules` | comma list | all | Select modules (`dns`, `whois`, `subdomains`, `http`, `ip`) |
| `--plugins` | comma list or `list` | all built-ins | Alias for module selection; listed for forward compatibility |
| `--json` | none | off | Emit a single JSON document to stdout |
| `--jsonl` | none | off | Emit newline-delimited per-module events (advanced) |
| `--pretty` | none | off | Indent JSON output |
| `-o`, `--output` | path | stdout | Write report to a file |
| `--force` | none | off | Allow overwriting the output file |
| `--tor` | none | off | Route outbound HTTP(S) through SOCKS5 |
| `--socks5` | `host:port` | `127.0.0.1:9050` | SOCKS5 endpoint used by `--tor` |
| `--resolver` | `ip[:port]` | system | Recursive DNS resolver |
| `--timeout` | duration | `10s` | Per-request timeout |
| `--retries` | integer | `2` | Retries for idempotent GETs |
| `--rate-limit` | integer | `5` | Requests per second per upstream host |
| `--concurrency` | integer | `8` | Maximum in-flight requests |
| `--user-agent` | string | `AlOsint/1.0` | User-Agent for HTTP requests |
| `--no-color` | none | auto | Disable ANSI color |
| `--quiet` | none | off | Suppress progress; print only the report or summary |
| `--verbose` | none | off | Include request-level diagnostics on stderr |
| `--yes` | none | off | Non-interactive acceptance of the authorized-use notice |
| `--acknowledge-authorized-use` | none | off | Explicit, auditable acceptance flag for CI |
| `--version` | none | — | Print version and exit |
| `-h`, `--help` | none | — | Print help and exit |

### 6.3 Examples

Basic scan, human-readable:

```
alosint -d example.com
```

JSON for automation:

```
alosint -d example.com --json --pretty
```

Save JSON atomically:

```
alosint -d example.com --json -o reports/example.com.json
```

Tor transport, warning if the proxy is unavailable:

```
alosint -d example.com --tor
alosint -d example.com --tor --socks5 127.0.0.1:9150
```

Select modules through the plugins flag:

```
alosint -d example.com --plugins dns,subdomains
alosint -d example.com --plugins whosis,http   # usage error: unknown module, suggestions shown
```

List available modules:

```
alosint --plugins list
```

Enrich an IP:

```
alosint -d 203.0.113.10 --type ip
```

Non-interactive CI use:

```
alosint -d example.com --json --acknowledge-authorized-use --quiet
```

### 6.4 UX rules

- **stdout is the product.** Reports go to stdout. Progress, warnings, and diagnostics go to stderr.
- **`--quiet` changes volume, not content.** It suppresses progress but never removes report sections or warnings.
- **No prompts in JSON mode.** If authorization has not been acknowledged, JSON mode exits with code 5 and a clear message on stderr; it never blocks on a prompt.
- **Acknowledgment is persisted per user.** Acceptance is stored in the user configuration directory with a timestamp and tool version. `--yes` and `--acknowledge-authorized-use` bypass the prompt for automation.
- **Warnings are never hidden.** Even with `--quiet`, a one-line warning summary is printed to stderr when any module degrades.
- **Interrupts are clean.** SIGINT stops new work, waits briefly for in-flight requests, emits a partial report, and exits 130.
- **Colors are semantic and optional.** Green for observed, yellow for degraded, red for failed, dim for metadata. `NO_COLOR` is honored.
- **Tor failures are fatal before collection.** If `--tor` is set and the proxy cannot be reached, AlOsint performs no direct requests.
- **Module order is fixed.** DNS, WHOIS/RDAP, IP/ASN, subdomains, HTTP. The order never depends on flag order.

### 6.5 Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed successfully with at least one result |
| `1` | Unexpected internal failure |
| `2` | Usage error (bad flag, unknown module, invalid target) |
| `3` | Completed successfully but produced no findings |
| `4` | All selected modules failed due to network or upstream errors |
| `5` | Authorized-use acknowledgment missing or refused |
| `6` | Blocked by upstream rate limiting after retries |
| `130` | Interrupted by the user |

### 6.6 Text output structure

```
AlOsint 1.0.0 — example.com
Scanned 2026-11-11T14:02:11Z · 1.8s · Tor: no

DNS
  A        93.184.216.34            TTL 3600
  AAAA     2606:2800:220:1:248:1893:25c8:1946   TTL 3600
  MX       10 mail.example.com      TTL 3600
  NS       a.iana-servers.net       TTL 172800
  TXT      "v=spf1 -all"            TTL 3600
  CNAME    www.example.com → example.com

WHOIS / RDAP  (RDAP)
  Registrar      Example Registrar, Inc.
  Created        1995-08-14
  Expires        2027-08-13
  Status         clientTransferProhibited
  Nameservers    a.iana-servers.net, b.iana-servers.net

IP / ASN
  93.184.216.34
    ASN          AS15133
    Organization Edgecast Inc.
    Prefix       93.184.216.0/24
    Location     US · California · Los Angeles (approximate)
    Source       ExampleGeo (2026-11-11T14:02:12Z)

SUBDOMAINS  (crt.sh)  12 unique
  www.example.com
  mail.example.com
  dev.example.com
  ...

HTTP
  https://example.com  200 OK
    Server       ECS (dcb/7F84)
    CDN          Edgecast
    TLS issuer   DigiCert Inc
    TLS expires  2027-01-04
    Headers      HSTS ✓  CSP ✗  X-Frame-Options ✗

Warnings
  subdomains: crt.sh returned 503 once; retried successfully.
```

Rules:

- Section order is fixed; empty sections print `No results` rather than disappearing.
- Values are aligned only when writing to a TTY; piped text output uses single spaces.
- Long lists are truncated with an explicit `… and N more` line in text mode; JSON is never truncated without a `truncated` marker.
- Raw upstream payloads are not printed in text mode; they are available in JSON.

### 6.7 JSON output structure

The JSON document is the primary integration contract. It is deterministic, versioned, and additive-only within a major schema version.

```json
{
  "schema_version": "1.0",
  "tool": {
    "name": "alosint",
    "version": "1.0.0"
  },
  "scan": {
    "id": "018f4b1a-6c2e-7c31-9f4e-2b0a6f1d8a11",
    "target": "example.com",
    "target_type": "domain",
    "modules": ["dns", "whois", "ip", "subdomains", "http"],
    "started_at": "2026-11-11T14:02:11Z",
    "finished_at": "2026-11-11T14:02:13Z",
    "duration_ms": 1840,
    "tor": { "requested": true, "used": true, "endpoint": "127.0.0.1:9050" },
    "status": "partial",
    "flags": { "rate_limit": 5, "timeout": "10s", "resolver": "system" }
  },
  "results": {
    "dns": {
      "status": "ok",
      "source": "dns:system",
      "observed_at": "2026-11-11T14:02:11Z",
      "elapsed_ms": 210,
      "records": {
        "a": [{ "value": "93.184.216.34", "ttl": 3600 }],
        "aaaa": [{ "value": "2606:2800:220:1:248:1893:25c8:1946", "ttl": 3600 }],
        "mx": [{ "priority": 10, "exchange": "mail.example.com", "ttl": 3600 }],
        "ns": [{ "value": "a.iana-servers.net", "ttl": 172800 }],
        "txt": [{ "value": "v=spf1 -all", "ttl": 3600 }],
        "cname": [{ "from": "www.example.com", "to": "example.com", "ttl": 300 }],
        "soa": null,
        "caa": [],
        "srv": []
      },
      "cname_chains": [
        { "host": "www.example.com", "chain": ["www.example.com", "example.com"] }
      ]
    },
    "whois": {
      "status": "ok",
      "source": "rdap:iana-bootstrap",
      "protocol": "rdap",
      "observed_at": "2026-11-11T14:02:12Z",
      "elapsed_ms": 430,
      "registrar": "Example Registrar, Inc.",
      "created_at": "1995-08-14T04:00:00Z",
      "updated_at": "2026-08-01T12:00:00Z",
      "expires_at": "2027-08-13T04:00:00Z",
      "status": ["clientTransferProhibited"],
      "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
      "registrant_org": null,
      "redacted_fields": ["registrant_org"],
      "raw": "…"
    },
    "ip": {
      "status": "ok",
      "source": "rdap+geo:examplegeo",
      "observed_at": "2026-11-11T14:02:12Z",
      "elapsed_ms": 380,
      "addresses": [
        {
          "ip": "93.184.216.34",
          "version": 4,
          "asn": 15133,
          "organization": "Edgecast Inc.",
          "prefix": "93.184.216.0/24",
          "country": "US",
          "region": "California",
          "city": "Los Angeles",
          "coordinates": { "lat": 34.0522, "lon": -118.2437, "accuracy_km": 50 },
          "confidence": "medium",
          "private": false
        }
      ]
    },
    "subdomains": {
      "status": "ok",
      "source": "crt.sh",
      "observed_at": "2026-11-11T14:02:12Z",
      "elapsed_ms": 890,
      "count": 12,
      "truncated": false,
      "hostnames": [
        { "name": "dev.example.com", "wildcard": false, "certificate_id": 123456789 },
        { "name": "mail.example.com", "wildcard": false, "certificate_id": 123456790 },
        { "name": "www.example.com", "wildcard": false, "certificate_id": 123456791 }
      ]
    },
    "http": {
      "status": "ok",
      "source": "https",
      "observed_at": "2026-11-11T14:02:13Z",
      "elapsed_ms": 520,
      "hosts": [
        {
          "url": "https://example.com",
          "final_url": "https://example.com/",
          "status_code": 200,
          "redirects": [],
          "server": "ECS (dcb/7F84)",
          "cdn": "Edgecast",
          "framework": null,
          "waf": null,
          "tls": {
            "issuer": "DigiCert Inc",
            "subject": "example.com",
            "not_before": "2026-01-04T00:00:00Z",
            "not_after": "2027-01-04T23:59:59Z"
          },
          "security_headers": {
            "strict-transport-security": true,
            "content-security-policy": false,
            "x-frame-options": false,
            "x-content-type-options": false
          }
        }
      ]
    }
  },
  "errors": [],
  "warnings": [
    {
      "module": "subdomains",
      "code": "upstream_retry",
      "message": "crt.sh returned 503 once; retried successfully."
    }
  ],
  "meta": {
    "data_sources": ["dns:system", "rdap:iana-bootstrap", "crt.sh", "geo:examplegeo"],
    "partial": true
  }
}
```

### 6.8 JSON contract rules

1. **Top-level keys are fixed.** `schema_version`, `tool`, `scan`, `results`, `errors`, `warnings`, `meta`.
2. **Module objects are present only when selected**, but `results` always exists.
3. **Status values are closed sets:** `ok`, `partial`, `failed`, `skipped`.
4. **Timestamps are RFC 3339 in UTC.** No local time, no locale-dependent formatting.
5. **Absent data is `null` or `[]`**, never omitted, so consumers can rely on stable shapes.
6. **Ordering is deterministic:** hostnames, records, and addresses are sorted by a documented key.
7. **Every list has a count**, and truncation is explicit through `truncated`.
8. **Raw upstream payloads are strings** under a `raw` key and never mixed into normalized fields.
9. **Provenance is mandatory.** Each module identifies its source and observation time.
10. **Additive evolution only within 1.x.** Removing or renaming a key requires a major schema version.
11. **One document per invocation.** `--json` never emits logs before or after the document.
12. **`--jsonl` is an advanced, documented stream** of per-module events for long scans; it is not a substitute for the final document.

### 6.9 Configuration and environment

- Configuration file: `~/.config/alosint/config.toml` (XDG respected).
- Precedence: CLI flags, environment, config file, defaults.
- Environment variables use the `ALOSINT_` prefix (`ALOSINT_TOR`, `ALOSINT_RATE_LIMIT`).
- No secrets are required in V1.0. When V2.0 adds API keys, they must be read from environment or an OS keychain, never logged, and never written to reports.
- The authorized-use acknowledgment is stored separately from scan configuration and is not transmitted anywhere.

---

## 7. Safety, Privacy, and Compliance Controls in the Product

These are product requirements, not suggestions.

1. **Authorization gate.** A plain-language notice appears on first run: use is limited to systems you own or are authorized to assess. Acceptance is required before any network call.
2. **Non-interactive gate.** CI and JSON users must pass `--acknowledge-authorized-use`; missing acknowledgment is a hard failure with exit code 5.
3. **Rate limiting on by default.** Per-host request limits protect third parties and keep AlOsint a good citizen of public data sources.
4. **No intrusive techniques.** No port scans, no brute force, no zone transfers, no authentication, no payloads.
5. **Data minimization.** Only fields needed for the report are retained; response bodies are not stored.
6. **Tor transparency.** The report states whether Tor was requested and used. The help text states that Tor is not an anonymity guarantee.
7. **Provenance over inference.** Heuristic findings are labeled and never presented as confirmed facts.
8. **No leak-data pathway.** There is no module, flag, or plugin hook for breach data, credentials, or leaked personal data, and none will be added.
9. **Responsible disclosure guidance.** The documentation links to the legal and ethical guidance in `LEGAL.md` and encourages reporting discovered issues privately.
10. **Audit-friendly logs.** With `--verbose`, the tool logs request targets and status codes to stderr, but never response bodies or personal data.

---

## 8. Non-Functional Requirements

| Area | Requirement |
|---|---|
| **Performance** | Typical domain scan completes in under 15 seconds on a healthy network; hard ceiling of 120 seconds with defaults |
| **Reliability** | One failing module never aborts the scan; partial reports are first-class |
| **Portability** | Linux and macOS primary; Windows supported where the Goose toolchain and C dependencies allow |
| **Dependencies** | Minimal, pinned, license-audited; no telemetry or analytics libraries |
| **Security** | TLS verification on by default; no insecure skip-verify flag in V1.0; strict output encoding |
| **Determinism** | Same inputs and same upstream data produce byte-identical JSON apart from timestamps and IDs |
| **Accessibility** | Text output remains readable without color; no essential information conveyed by color alone |
| **Documentation** | Every flag, module, exit code, and schema field documented; examples tested in CI |
| **Observability** | Structured stderr diagnostics; no hidden network calls |
| **Licensing** | Project license compatible with all bundled C dependencies and data-source terms |

---

## 9. Risks and Open Questions

| Risk | Impact | Mitigation |
|---|---|---|
| crt.sh availability and rate limits | Subdomain module degrades | Backoff, cache-free retries, clear warnings, documented fallback none in V1 |
| WHOIS/RDAP inconsistency across registries | Incomplete registration data | Protocol fallback, explicit redaction markers, raw payload retention |
| Geolocation inaccuracy | Misleading conclusions | Coarse values, confidence labels, provider attribution, "approximate" wording |
| Tor blocked by public sources | Partial scans | Preflight probe, fatal-before-collection behavior, clear reporting |
| Users treating heuristics as facts | Bad decisions | Labeling, documentation, no vulnerability language |
| Goose/C toolchain maturity | Delivery risk | Early spike in M0, C boundary kept small and audited |
| Legal misuse of the tool | Harm and reputational risk | Strong gating, documentation, no leak-data features, rate limits |
| Output schema churn | Broken integrations | Versioned contract, additive-only 1.x, golden-file tests |

**Open questions for review**

1. Should V1.0 ship a small, documented offline fixture mode for demos and tests, or keep fixtures test-only?
2. Which public geolocation provider best balances accuracy, licensing, and rate limits?
3. Should `--jsonl` ship in V1.0 or slip to V1.1?
4. Is a per-user config file acceptable, or should V1.0 be flags-only for auditability?
5. What is the minimum supported Windows story for the first release?

---

## 10. Definition of Done for V1.0

- All five modules implemented and covered by unit and contract tests.
- Golden-file tests for text and JSON output pass on Linux and macOS.
- Schema published and validated in CI.
- Authorization gate tested interactively and non-interactively.
- Tor path tested against a local SOCKS5 proxy, including failure-before-collection.
- Rate limiting and backoff verified against mocked upstream 429/503 responses.
- Documentation complete: README, `PLAN.md`, `ROADMAP.md`, `LEGAL.md`, schema reference, man page.
- No known critical or high security findings in the C boundary.
- Release artifacts reproducible and checksummed.
