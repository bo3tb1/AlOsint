# AlOsint — Development Roadmap

**Document status:** Draft for review  
**Scope:** Project setup through V1.0 release, plus the V2.0 backlog  
**Last updated:** 2026-11-11

---

## 1. How to Read This Roadmap

Milestones are sequential and each has explicit exit criteria. Durations are indicative for a small team (two to three engineers) and assume part-time review capacity. They are planning aids, not commitments.

**Guiding rules**

1. Every milestone ends with a working, demonstrable increment.
2. No milestone starts before the prior milestone's exit criteria are met, except for documentation and legal work, which run in parallel.
3. Live-network tests are opt-in; CI uses recorded fixtures and mocks.
4. The JSON schema is frozen at the end of M1 and evolves additively thereafter.
5. Legal and ethical controls are built into the product, not bolted on at release.

**Milestone status legend:** `planned` · `in progress` · `done` · `deferred`

---

## 2. Milestone Overview

| ID | Milestone | Indicative duration | Depends on | Status |
|---|---|---|---|---|
| M0 | Foundation and feasibility | 1–2 weeks | — | planned |
| M1 | Core CLI, config, and output contract | 2–3 weeks | M0 | planned |
| M2 | DNS enumeration module | 2 weeks | M1 | planned |
| M3 | WHOIS / RDAP module | 2 weeks | M1 | planned |
| M4 | Subdomain discovery via crt.sh | 1–2 weeks | M1, M2 | planned |
| M5 | HTTP fingerprinting module | 2–3 weeks | M1, M2 | planned |
| M6 | IP geolocation and ASN module | 1–2 weeks | M1 | planned |
| M7 | Optional Tor transport | 1 week | M1, M5 | planned |
| M8 | Hardening, documentation, and V1.0 release | 2–3 weeks | M2–M7 | planned |
| V2.0 | Deferred integrations and platform features | TBD | V1.0 | deferred |

Total indicative effort to V1.0: **12–17 engineer-weeks**, excluding legal review and external security review.

---

## 3. M0 — Foundation and Feasibility

**Goal:** Prove the Goose/C toolchain and establish the repository, quality gates, and boundaries before feature work begins.

### Deliverables

- Repository scaffold: license, contribution guide, code of conduct, security policy, issue templates.
- Build system for Goose with a minimal, well-defined C interop boundary.
- Toolchain spike: argument parsing, HTTP client via C, JSON serialization, DNS resolution, SOCKS5 client.
- Decision record comparing native Goose libraries versus C libraries for each capability.
- CI pipeline: build, format, lint, unit tests, dependency license check.
- Threat model covering target data, upstream sources, Tor transport, and output handling.
- Initial `LEGAL.md` reviewed by counsel or a qualified reviewer.
- Skeleton CLI with `--help` and `--version` only.

### Exit criteria

- A hello-world binary builds reproducibly on Linux and macOS.
- CI is green on a clean checkout.
- The C boundary is documented, small, and covered by at least one boundary test.
- Toolchain risks are recorded; any blocker has a fallback plan.
- Threat model and legal draft approved by the maintainers.

### Key risks

- Goose ecosystem maturity and library availability.
- C dependency licensing and cross-platform build friction.
- Overly large C surface increasing memory-safety risk.

---

## 4. M1 — Core CLI, Configuration, and Output Contract

**Goal:** Deliver the shell of the product: parsing, configuration, orchestration, error model, and the frozen output contract.

### Deliverables

- Flag parser for `-d`, `--target`, `--type`, `--modules`, `--plugins`, `--json`, `--jsonl`, `--pretty`, `-o`, `--force`, `--tor`, `--socks5`, `--resolver`, `--timeout`, `--retries`, `--rate-limit`, `--concurrency`, `--user-agent`, `--no-color`, `--quiet`, `--verbose`, `--yes`, `--acknowledge-authorized-use`, `--version`, `--help`.
- Configuration loader with precedence: flags, environment, config file, defaults.
- Module registry and deterministic execution pipeline with per-module timeouts and partial-failure handling.
- Error taxonomy and exit codes 0, 1, 2, 3, 4, 5, 6, 130.
- Text renderer with TTY-aware color and stable section order.
- JSON renderer, schema document, and golden-file tests.
- Authorization gate with persistent per-user acknowledgment and non-interactive flag.
- Global rate limiter and retry policy with jittered exponential backoff.
- Structured stderr logging behind `--verbose`.

### Exit criteria

- `alosint --plugins list` and `--version` work without network access.
- A mock module proves the pipeline, text renderer, JSON renderer, exit codes, and partial reports end to end.
- JSON output validates against the published schema and is byte-stable apart from timestamps and IDs.
- Authorization gate cannot be bypassed in JSON mode without the explicit acknowledgment flag.
- Unit test coverage of the core is at least 80 percent by line, with critical paths at 100 percent.
- Schema is reviewed and frozen for 1.x additive evolution.

### Key risks

- Schema design that locks in awkward assumptions; mitigate with a review of real consumer needs.
- Flag surface creep; every flag must have a documented use case.
- Cross-platform TTY behavior.

---

## 5. M2 — DNS Enumeration Module

**Goal:** Complete, reliable DNS record collection with normalized output.

### Deliverables

- Queries for A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and SRV.
- CNAME chain following with a depth limit and loop detection.
- System resolver default plus `--resolver` override.
- Distinct handling for NXDOMAIN, SERVFAIL, timeout, and truncated responses.
- Normalized record models plus raw record preservation.
- Deterministic sorting and deduplication.
- Fixture-based tests, including malformed and hostile responses.
- Live-network integration tests behind an opt-in environment flag.

### Exit criteria

- All record types are covered by tests, including empty and error cases.
- CNAME loops terminate quickly with a warning.
- No direct queries to authoritative servers.
- Output matches the schema and golden files.
- Module degrades gracefully when the resolver is unreachable.

### Key risks

- Resolver differences across operating systems.
- TXT record parsing edge cases and multi-string records.
- Large zones producing oversized outputs; pagination or truncation rules must be explicit.

---

## 6. M3 — WHOIS / RDAP Module

**Goal:** Accurate registration data with clear provenance and redaction handling.

### Deliverables

- IANA RDAP bootstrap discovery with local fallback data.
- RDAP client with normalization of registrar, dates, status, nameservers, and public registrant organization.
- WHOIS (port 43) fallback with response parsing and referral handling.
- Explicit `null` plus reason for redacted or unavailable fields.
- Raw payload retention as a separate string field.
- Per-registry timeout and rate-limit behavior.
- Fixtures for gTLD and representative ccTLD responses.

### Exit criteria

- RDAP preferred; WHOIS used only on failure or unavailability.
- Redaction is never bypassed.
- Rate-limit responses surface as warnings or exit code 6, never infinite retries.
- Protocol and source are recorded in every result.
- Date parsing is timezone-correct and normalized to UTC.

### Key risks

- Registry-specific response shapes.
- WHOIS server deprecation and inconsistent port 43 behavior.
- Personal data appearing in public WHOIS; must be minimized in output and never enriched.

---

## 7. M4 — Subdomain Discovery via crt.sh

**Goal:** Reliable CT-log-based subdomain discovery without brute force.

### Deliverables

- crt.sh query client with pagination and deduplication.
- Wildcard normalization and apex scoping.
- Certificate provenance per hostname.
- Optional resolution of discovered names through the DNS module.
- Backoff for HTTP 429/503 and clear degradation warnings.
- Bounded output with `truncated` markers.
- Fixture tests for large, malformed, and empty responses.

### Exit criteria

- Only in-scope, deduplicated hostnames are reported.
- Wildcards are normalized and labeled.
- Upstream failure yields a warning and a partial report.
- No wordlist or brute-force path exists in the codebase.
- Output is deterministic across runs on the same fixture.

### Key risks

- crt.sh availability and rate limits.
- Very large result sets for popular domains.
- False positives from shared certificates; apex scoping must be strict.

---

## 8. M5 — HTTP Fingerprinting Module

**Goal:** Non-intrusive HTTP and TLS fingerprinting for the apex and discovered hosts.

### Deliverables

- HTTPS-first probing with HTTP fallback, one request per host, bounded redirect following.
- Status, final URL, redirect chain, headers, and TLS certificate summary.
- Heuristic detection of server, framework, CDN, and WAF.
- Security header presence summary.
- Host cap, concurrency cap, and per-host rate limiting.
- No response-body storage by default.
- Fixtures covering redirects, loops, TLS errors, and unusual headers.

### Exit criteria

- Redirect loops terminate with a warning.
- Findings are labeled heuristic in both text and JSON.
- No crawling, asset fetching, or authentication.
- TLS verification is enforced; no insecure override exists in V1.0.
- Degradation per host does not fail the module.

### Key risks

- Fingerprint false positives; require multiple signals or explicit confidence.
- Divergent behavior from CDNs and bot protection.
- Ethical concerns around request volume; caps are mandatory.

---

## 9. M6 — IP Geolocation and ASN

**Goal:** Contextualize IP addresses with ASN, prefix, and coarse location.

### Deliverables

- Address collection from DNS results and the target itself.
- ASN and prefix lookup through public RDAP/WHOIS.
- Coarse geolocation through a configurable, attributed public provider.
- Handling for private, reserved, loopback, and multicast addresses without external lookups.
- Confidence and accuracy fields where available.
- Provider abstraction to allow later substitution without schema changes.
- Fixtures for IPv4, IPv6, private ranges, and provider errors.

### Exit criteria

- Private and reserved addresses are labeled and never sent externally.
- IPv4 and IPv6 are both covered.
- Every result names its provider and observation time.
- Provider failure degrades to partial output.
- No precise-location claims; wording is reviewed for accuracy.

### Key risks

- Provider licensing and rate limits.
- Accuracy expectations from users.
- Privacy implications of geolocating individuals; documentation must stress approximation and lawful use.

---

## 10. M7 — Optional Tor Transport

**Goal:** Add optional SOCKS5 routing without overstating its guarantees.

### Deliverables

- SOCKS5 client integration for HTTP(S) requests.
- `--tor` and `--socks5` flags with sane defaults.
- Preflight reachability check: fail before any direct request if Tor is requested and unavailable.
- Report fields for Tor requested, used, and endpoint.
- DNS behavior documented: hostname resolution occurs through the proxy path where supported; otherwise the limitation is explicit.
- Tests against a local mock SOCKS5 server, including auth failure, timeout, and mid-scan drop.
- Help text and documentation stating that Tor is not an anonymity guarantee.

### Exit criteria

- With `--tor`, no direct egress occurs, verified by test.
- Proxy unavailability aborts before collection with a clear error.
- Mid-scan proxy failure yields a partial report and a warning.
- Tor usage is accurately recorded in text and JSON.
- No claims of anonymity, evasion, or attribution resistance anywhere in the product.

### Key risks

- Public sources blocking Tor exit nodes.
- DNS leak confusion; behavior must be documented precisely.
- Users misinterpreting Tor as a legal or ethical shield; documentation must be unambiguous.

---

## 11. M8 — Hardening, Documentation, and V1.0 Release

**Goal:** Turn the feature-complete build into a trustworthy release.

### Deliverables

- Full documentation: README, `PLAN.md`, `ROADMAP.md`, `LEGAL.md`, CLI reference, JSON schema reference, man page.
- Offline demo fixtures and a documented sample report.
- Performance pass against the 15-second typical and 120-second ceiling targets.
- Security review of the C boundary, fuzzing of parsers, and dependency audit.
- Accessibility and no-color review of text output.
- Packaging: static binaries where feasible, checksums, signed release notes.
- Release checklist and rollback plan.
- External legal review sign-off on `LEGAL.md` and the authorization gate wording.
- Beta period with a small group of authorized testers and a triage log.

### Exit criteria

- All V1.0 acceptance criteria in `PLAN.md` are met.
- No open critical or high severity security findings.
- Golden-file tests pass on Linux and macOS.
- Documentation examples are executed in CI and pass.
- Legal sign-off recorded.
- Release artifacts are reproducible and checksummed.
- Known limitations are published, including crt.sh dependence, geolocation accuracy, and Tor blocking.

### Key risks

- Late documentation drift; docs are updated per milestone, not at the end.
- Security review findings causing schedule slip; reserve buffer.
- Packaging complexity across platforms.

---

## 12. Cross-Cutting Workstreams

These run alongside every milestone.

| Workstream | Cadence | Owner |
|---|---|---|
| Documentation | Updated in every milestone PR | Maintainers |
| Legal and ethical review | M0, M3, M7, M8 | Maintainers plus reviewer |
| Security review | Continuous; formal at M5 and M8 | Security reviewer |
| Test fixtures and mocks | Every module milestone | Module owner |
| Dependency and license audit | Every milestone | Maintainers |
| Accessibility and UX review | M1, M5, M8 | Maintainers |
| Release engineering | M0 and M8 | Maintainers |

---

## 13. Quality Gates

A milestone is not complete unless all applicable gates pass.

1. **Build:** Clean build on supported platforms.
2. **Static checks:** Formatting, linting, and type checking pass.
3. **Tests:** Unit tests pass; new code has meaningful coverage; fixtures are deterministic.
4. **Contract:** JSON output validates against the schema; golden files updated intentionally.
5. **Security:** No new high or critical dependency findings; parsers fuzzed where applicable.
6. **Docs:** Every user-visible change is documented in the same change set.
7. **Ethics:** No feature enables intrusive scanning, leak-data collection, or evasion.
8. **Review:** At least one maintainer approval, plus a security review for boundary changes.

---

## 14. V2.0 — Deferred Scope

V2.0 is intentionally not scheduled until V1.0 is stable and its legal posture is proven in practice. The following items are deferred, with reasons.

| Deferred item | Why it is deferred | Prerequisites before reconsideration |
|---|---|---|
| **Shodan / Censys integrations** | Requires API keys, paid tiers, per-provider terms of service, quota handling, and careful disclosure of third-party data. Adds secret management and a new failure surface. | Key storage design, provider ToS review, quota and cost model, schema extension |
| **SQLite history** | Introduces persistent storage of potentially personal data, retention obligations, migration strategy, and encryption questions. V1.0's stateless design is a privacy feature. | Data retention policy, encryption at rest, migration plan, user controls for deletion and export |
| **Web UI** | Large surface area: authentication, authorization, session security, hosting model, and browser security. Would distract from the CLI contract and multiply the threat model. | Stable JSON API, authentication design, hosting and privacy review, accessibility plan |
| **Social media scraping** | High legal, ethical, and terms-of-service risk. Scraping personal data can violate platform terms and data protection law, and can enable harassment or doxxing. Requires a narrow, defensible use case and strong safeguards. | Dedicated legal review, platform terms analysis, strict purpose limitation, anti-abuse controls, possibly a decision not to build |
| **Breach and leak data** | Permanently prohibited, not merely deferred. See `LEGAL.md`. | Not applicable; will not be built |
| **External plugin loading** | Loading untrusted code undermines the security model and creates supply-chain risk. V1.0 exposes `--plugins` only for built-in module selection. | Sandboxing design, signing and provenance, permission model |
| **Subdomain brute forcing** | Intrusive and noisy; conflicts with the passive-by-default principle. | Not planned; would require explicit authorization design and is out of character for the product |
| **Port scanning and service probing** | Intrusive; outside the OSINT remit and increases legal exposure. | Not planned |
| **Distributed or multi-target scanning** | Amplifies impact and abuse potential; complicates rate limiting and authorization. | Not planned for the foreseeable roadmap |
| **Scheduling and monitoring** | Requires persistence, background execution, and alerting; depends on SQLite history. | V2.0 history plus a notification design |
| **Screenshots and headless browsing** | Heavy dependencies, resource use, and new privacy considerations; marginal value for V1.0 fingerprinting. | Resource budget, sandboxing, privacy review |

### 14.1 V2.0 sequencing (tentative)

If V2.0 is approved, the likely order is:

1. **API integrations (Shodan/Censys)** — highest user demand, bounded scope, additive to the existing schema.
2. **SQLite history** — enables repeat scans and comparison; requires the retention and encryption work above.
3. **Web UI** — only after the JSON API and history are stable.
4. **Social media** — last, and only with a specific lawful use case; may remain permanently out of scope.

### 14.2 What will not change

- Passive-by-default collection.
- No intrusive scanning and no exploitation.
- No breach, leak, or credential data.
- Versioned, additive JSON evolution.
- Authorization acknowledgment before collection.
- Honest reporting of provenance and uncertainty.

---

## 15. Release Checklist for V1.0

- [ ] All five modules pass acceptance criteria.
- [ ] Core and module tests pass on Linux and macOS.
- [ ] JSON schema published; golden files reviewed.
- [ ] Authorization gate tested interactively and in CI mode.
- [ ] Tor path tested, including failure-before-collection and mid-scan drop.
- [ ] Rate limiting and backoff verified with mocked 429/503.
- [ ] Documentation complete and examples executed in CI.
- [ ] `LEGAL.md` reviewed and signed off.
- [ ] Security review closed with no critical or high findings.
- [ ] Dependency licenses audited.
- [ ] Reproducible builds and checksums published.
- [ ] Known limitations documented.
- [ ] Changelog and migration notes written.
- [ ] Release tagged and artifacts attached.
- [ ] Post-release monitoring plan for upstream source changes.

---

## 16. Success Metrics

V1.0 is successful when:

- An authorized analyst can complete a full domain scan in one command and understand the result without reading the docs.
- JSON output integrates into at least two external workflows without schema changes.
- Partial failures are visible and never silent.
- No abuse reports attributable to default behavior (rate limiting and passive collection hold).
- Time to first scan for a new user is under five minutes, including the authorization notice.
- Documentation answers the top support questions without maintainer intervention.
