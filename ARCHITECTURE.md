# AlOsint — Architecture

> **Status:** Planning / Design. This document defines the architecture only.
> No implementation is described beyond ABI contracts and type layouts required
> to pin the design down.

AlOsint is a Linux OSINT collection tool. The orchestration core is written in
**Goose** (a fixed-capacity systems language: no heap allocator, no garbage
collector, storage is statically or stack-reserved with fixed capacities). All
I/O that requires a dynamic runtime — HTTP/HTTPS, SOCKS5, DNS, dynamic library
loading, byte-level JSON tokenizing — is delegated across a narrow **C interop
boundary**. OSINT data sources are shipped as **C `.so` plugins** loaded at
runtime.

The guiding invariant of the whole system:

> **Memory ownership never crosses the FFI boundary.** Goose owns every byte
> buffer. C fills buffers it is lent; C never allocates memory that Goose must
> later free, and Goose never frees memory C allocated. There is therefore no
> allocator contract to reconcile between the two sides.

---

## 0. Design Constraints (normative)

| Constraint | Consequence for the design |
|---|---|
| No heap in Goose | All storage is fixed-capacity: static arenas, slot pools, stack frames. Capacities are compile-time constants surfaced in `limits.goose`. |
| No GC | Lifetimes are explicit and lexical. "Freeing" means returning a slot to a pool, never calling an allocator. |
| Fixed-capacity storage | Every collection has a `capacity` and a `len`. Overflow is a first-class, non-fatal signal (`TRUNCATED`), never undefined behavior. |
| C interop for I/O | libcurl, dlopen, and the JSON tokenizer live behind thin C shims with a hand-audited ABI. |
| Dynamic `.so` plugins | Plugins conform to a frozen, versioned C ABI and receive all capabilities through a host-provided callback table. |
| Linux target | `dlopen`/`dlsym`/`dlclose`, ELF `.so`, POSIX. No cross-platform abstraction layer in v1. |

---

## 1. C Interop Layer (libcurl & DNS)

### 1.1 Boundary philosophy

Goose does not link against or call libcurl directly. It binds a **host C shim**
(`http_client`) with Goose `extern fn` declarations and calls its *flat,
allocation-free* C API. The shim is the only place in the system that touches
`CURL*` handles. This keeps the FFI surface small, auditable, and free of
callback-into-Goose reentrancy.

Every C entry point the core uses is declared once, Goose-side, as an `extern fn`
bound to the C symbol. The declaration is the whole contract Goose sees:

```goose
// Goose binding for a C symbol compiled from c/http_client.c (see §5).
extern fn alosint_http_perform(req: HttpReq&, body: Buf&, meta: HttpResp&) -> i32;
```

Goose's FFI admits only types with a defined C representation, and a signature
that uses an unsupported type is rejected at the declaration. The entire boundary
is therefore expressed with four argument kinds:

- **Scalars** — `i32`, `u32`, `u64`, `usize`; C enums are crossed as `i32`.
- **Borrowed const slices** — `const u8[:]`. A slice crosses to C as
  `{ const uint8_t *data; size_t len; }`, so it carries its own length. Used for
  every read-only byte window Goose lends (URLs, header blocks, request bodies,
  and the bytes handed to the JSON tokenizer). No NUL-termination or separate
  length argument is needed.
- **Borrowed mutable pointers** — `u8&`, a machine address into Goose-owned
  storage that C writes through (paired with an explicit capacity). A Goose
  reference is "a machine address that never dangles": because every shim call is
  synchronous, the lent storage trivially outlives the call.
- **Borrowed references to POD structs** — `HttpReq&`, `Buf&`, `HttpResp&`,
  `DnsRr[:]` … passed by `&` (or as a mutable slice) for the in/out descriptors
  whose layouts are frozen in the shared ABI (§1.4). C marks read-only ones
  `const`.

No pointer returned from C ever needs to outlive the call, and no pointer
passed into C is retained by C after the call returns.

### 1.2 Passing fixed-capacity buffers safely

A Goose response buffer is a plain reserved byte region. The bytes are static
Goose storage; a small `Buf` value is the mutable *view* Goose lends to C:

```goose
// Goose-side reserved storage (one slot of the ResponseBuffer pool, §3.2).
struct ResponseBuffer {
    bytes: [RESP_CAP]u8      // RESP_CAP is a compile-time constant
}

// The borrowed, fillable view passed across the FFI (mirrors alosint_buf_t).
struct Buf {
    bytes:    u8&            // mutable pointer into Goose-owned storage (&rb.bytes[0])
    len:      usize          // written by C: bytes actually stored
    cap:      usize          // read by C, never exceeded (== RESP_CAP)
    overflow: bool           // set by C on truncation
}
```

`Buf` is passed as `body: Buf&`, so C receives a single `alosint_buf_t*`. The
matching C view is a POD struct whose layout is **asserted to match** the Goose
`Buf` field-for-field (`static_assert(sizeof(...))` + explicit field offsets):

```c
typedef struct {
    uint8_t *bytes;     // the u8& — points into Goose-owned storage
    size_t   len;       // written by C
    size_t   cap;       // read by C, never exceeded
    uint8_t  overflow;  // set by C on truncation (Goose bool is one byte)
} alosint_buf_t;
```

Safety rules enforced at the shim:

1. **C writes at most `cap` bytes.** The libcurl write callback compares
   `len + incoming <= cap`. On overshoot it writes the prefix that fits, sets
   `overflow = 1`, and *keeps consuming* the stream so the transfer completes
   cleanly (returning the full byte count to libcurl) rather than erroring mid-transfer.
2. **C never reallocates `bytes`.** The pointer and `cap` are fixed for the
   lifetime of the call.
3. **Ownership stays in Goose.** After the call, Goose reads `len`/`overflow`
   from its own struct (C wrote through the borrowed pointer).
4. **No retained aliases.** The shim clears `CURLOPT_WRITEDATA` to a stack-local
   before return; the borrowed pointer is never stored in a `CURL*` that outlives the call.

This is the entire memory contract for HTTP: Goose lends a byte window, C fills
it bounded, Goose reads the result. `TRUNCATED` is reported upward and surfaced
to the user; it is never silent.

### 1.3 HTTP/HTTPS request flow across the FFI

A single blocking request is modeled as one C call. Goose binds it as:

```goose
// req is borrowed read-only; body/meta are borrowed and C-filled.
// Returns 0 on transport success (check meta for HTTP code),
// negative alosint_err_t on transport failure.
extern fn alosint_http_perform(req: HttpReq&, body: Buf&, meta: HttpResp&) -> i32;
```

which maps directly onto the C symbol the shim defines:

```c
int alosint_http_perform(const alosint_http_req_t *req,   // borrowed, const
                         alosint_buf_t           *body,   // borrowed, C fills
                         alosint_http_resp_t     *meta);   // borrowed, C fills
```

Inside the shim:

1. Acquire a pooled `CURL*` (reused handles; see 1.6).
2. Set `CURLOPT_URL`, method, headers (from the fixed header block in `req`),
   timeouts, `CURLOPT_WRITEFUNCTION`/`CURLOPT_WRITEDATA = body`.
3. Apply proxy options if `req->route == ROUTE_TOR` (see 1.5).
4. `curl_easy_perform`.
5. Write status code, final URL length, and content-type into `meta` (also a
   fixed buffer). Reset the handle (`curl_easy_reset`) and return it to the pool.

libcurl's own internal allocations are *its* business and never surface to
Goose; they are freed by libcurl on handle reset/cleanup.

### 1.4 Request descriptor (frozen POD)

The Goose descriptor carries its borrowed strings as `const u8[:]` slices, so no
field is NUL-terminated and the explicit `body_len` disappears — each slice
already carries its length. `method`/`route` cross as `i32` (the C enum values):

```goose
// C enum values, crossed as i32: Get=0 Post=1 Head=2 / Direct=0 Tor=1
struct HttpReq {
    url:                 const u8[:]   // borrowed slice from a Goose string arena
    method:              i32
    route:               i32
    headers:             const u8[:]   // borrowed CRLF-joined block (len 0 = none)
    body:                const u8[:]   // borrowed POST body (len 0 = none)
    timeout_ms:          u32
    connect_timeout_ms:  u32
    verify_tls:          bool          // true = verify peer+host (default)
}
```

Each `const u8[:]` field lowers to a `{ const uint8_t *data; size_t len; }` pair,
so the frozen C mirror is spelled with those pairs and its layout is
`static_assert`ed to match `HttpReq`:

```c
typedef enum { HTTP_GET = 0, HTTP_POST = 1, HTTP_HEAD = 2 } alosint_method_t;
typedef enum { ROUTE_DIRECT = 0, ROUTE_TOR = 1 } alosint_route_t;

typedef struct { const uint8_t *data; size_t len; } alosint_slice_t;  // == const u8[:]

typedef struct {
    alosint_slice_t  url;          // borrowed, from Goose arena
    int32_t          method;       // alosint_method_t
    int32_t          route;        // alosint_route_t
    alosint_slice_t  headers;      // borrowed CRLF-joined block (len 0 = none)
    alosint_slice_t  body;         // borrowed POST body (len 0 = none)
    uint32_t         timeout_ms;
    uint32_t         connect_timeout_ms;
    uint8_t          verify_tls;   // 1 = verify peer+host (default)
} alosint_http_req_t;
```

Strings are produced in a Goose string arena and passed as borrowed const
slices. Because the call is synchronous, borrow lifetimes are trivially valid
for the duration of `alosint_http_perform`.

### 1.5 Optional Tor routing (SOCKS5 on 127.0.0.1:9050)

Tor is a per-request routing flag, not a global mode, so a run can mix direct
and proxied sources (or force all-Tor via config).

When `req->route == ROUTE_TOR`, the shim sets:

```c
curl_easy_setopt(h, CURLOPT_PROXY, "socks5h://127.0.0.1:9050");
```

**`socks5h` (not `socks5`) is mandatory.** The trailing `h` makes libcurl send
the *hostname* to the Tor proxy for resolution, so DNS happens inside the Tor
network. Plain `socks5` resolves locally first and **leaks the target domain to
the local resolver** — a DNS deanonymization leak. This choice is a hard
invariant, asserted in the shim and covered by a leak test (see 1.7).

Configuration:

- Proxy host/port are config-overridable (`config.tor.endpoint`), defaulting to
  `127.0.0.1:9050`, but the `socks5h` scheme is forced regardless of override.
- `config.tor.mode = off | optional | force`. In `force`, any plugin request
  with `ROUTE_DIRECT` is rejected before the call (fail-closed), never silently
  downgraded.
- Optional bootstrap check: a one-time `GET https://check.torproject.org/api/ip`
  through the proxy to confirm exit routing before a `force`-mode run proceeds.

### 1.6 Connection reuse and concurrency

- A fixed pool of `CURL*` easy handles (`HTTP_HANDLE_POOL`, compile-time size)
  is pre-initialized at startup. Handles are leased per request and `reset`
  between uses so no option bleeds across requests.
- v1 concurrency model is **bounded worker threads driving blocking easy
  handles**, not `curl_multi`. Each worker owns one leased handle at a time; the
  pool size bounds in-flight requests. This keeps the FFI purely call/return and
  avoids exposing an event loop to Goose. (`curl_multi` is a documented future
  option behind the same `http_client` facade.)
- `curl_global_init`/`curl_global_cleanup` are called exactly once, at process
  start/stop, from the C side.

### 1.7 DNS, leaks, and the `dns` module

- **Proxied requests:** DNS is delegated to Tor via `socks5h`. No local
  resolution occurs. This is the default and preferred path for anonymity.
- **Direct requests:** libcurl uses the system resolver. An optional `dns` C
  module (compiled from `c/dns.c`, §5) can expose explicit lookups
  (A/AAAA/MX/TXT/NS) for OSINT plugins that enumerate records, filling a fixed
  `DnsRr` array (borrowed, C-filled, bounded by capacity — same ownership rules
  as §1.2). Goose binds it as:

  ```goose
  // name: borrowed read-only slice. out: a mutable slice Goose lends; C fills
  // it up to out.len (its capacity) and writes the count through `n`.
  // Returns 0, or negative alosint_err_t.
  extern fn alosint_dns_query(name: const u8[:], rr_type: i32,
                              out: DnsRr[:], n: usize&) -> i32;
  ```

  The mutable slice `DnsRr[:]` crosses as `{ alosint_dns_rr_t *data; size_t len; }`
  (its `len` is the capacity C must not exceed), and `n: usize&` is the borrowed
  out-count — no array memory is ever allocated or freed across the boundary.
- **Leak guard:** a test asserts that in `force` mode every outbound request
  carries a `socks5h` proxy and that no `dns` lookup fires. CI runs this against
  a local SOCKS stub.

---

## 2. Plugin System (OSINT Sources)

### 2.1 Overview

Each OSINT source (e.g. `whois`, `dns_enum`, `cert_transparency`, `breach_lookup`)
is a standalone C `.so` built against a shared `alosint_plugin.h` header. Plugins
are **pure data producers**: they receive a query, call back into the host for
all capabilities (networking, time, logging), and emit result records into
host-owned storage. Plugins do not open sockets, do not link libcurl, and do not
allocate buffers the host must free.

### 2.2 The plugin ABI (frozen contract)

`alosint_plugin.h` is the single source of truth, versioned by
`ALOSINT_ABI_VERSION`. Every `.so` exports exactly these symbols:

```c
/* ---- 1. ABI handshake -------------------------------------------------- */
// Must return ALOSINT_ABI_VERSION the plugin was compiled against.
uint32_t alosint_plugin_abi_version(void);

/* ---- 2. Static descriptor ---------------------------------------------- */
typedef struct {
    const char *id;            // stable machine id, e.g. "cert_transparency"
    const char *name;          // human label
    const char *version;       // plugin's own semver
    uint32_t    capabilities;  // bitmask: NET_HTTP | NET_DNS | NEEDS_KEY ...
    uint32_t    input_kinds;   // bitmask of accepted query kinds (domain/ip/email/...)
} alosint_plugin_info_t;

// Returns a pointer to static, immutable, plugin-owned storage. Never freed.
const alosint_plugin_info_t *alosint_plugin_info(void);

/* ---- 3. Lifecycle (optional) ------------------------------------------- */
int  alosint_plugin_init(const alosint_host_api_t *host);  // 0 = ok, <0 = fatal
void alosint_plugin_shutdown(void);

/* ---- 4. The work --------------------------------------------------------*/
int  alosint_plugin_run(const alosint_query_t   *query,   // borrowed, const
                        const alosint_host_api_t *host,    // borrowed vtable
                        alosint_sink_t           *sink);   // borrowed emitter
```

Contract rules:

- **Handshake first.** The loader calls `alosint_plugin_abi_version()` before
  anything else. A mismatch against `ALOSINT_ABI_VERSION` → the plugin is
  rejected and `dlclose`d. The ABI version bumps on any layout change to the
  structs below.
- **No global state leaks.** All per-call state is passed in; plugins should be
  reentrant-friendly. `init`/`shutdown` bracket the plugin's lifetime for things
  like reading an API key from the host config.
- **`run` returns a status code**, not data. Data leaves through `sink`
  (§2.4). Non-zero is a graded error (`alosint_err_t`): the orchestrator records
  it per-source and continues with other plugins.

### 2.3 The Host API (capability table)

Plugins receive capabilities only through a host-provided vtable. This is how a
`.so` performs networking without linking libcurl and without the ability to
reach outside its sandboxed surface:

```c
typedef struct alosint_host_api {
    uint32_t abi_version;

    // Networking — routes through the host's http_client, honoring Tor config.
    int (*http_get)(void *hctx,
                    const char *url,
                    const char *headers,     // or NULL
                    alosint_buf_t *out);      // host-owned buffer, host-bounded
    int (*http_post)(void *hctx,
                     const char *url, const char *headers,
                     const uint8_t *body, size_t body_len,
                     alosint_buf_t *out);
    int (*dns_lookup)(void *hctx, const char *name, int rr_type,
                      alosint_dns_rr_t *out, size_t out_cap, size_t *out_n);

    // Config / secrets — borrowed const, valid for the call only.
    const char *(*get_secret)(void *hctx, const char *key);

    // Observability.
    void (*log)(void *hctx, int level, const char *msg);
    uint64_t (*now_ms)(void *hctx);

    void *hctx;  // opaque host context passed back into every callback
} alosint_host_api_t;
```

Consequences:

- **The host enforces policy centrally.** Tor routing, rate limiting, timeouts,
  TLS verification, and allow/deny lists all live in `http_client`, so a
  plugin *cannot* bypass them. A plugin asking for `http_get` in `force`-Tor
  mode is proxied; it has no other way to reach the network.
- **The buffers are the host's.** `out` points at a slot the host leased from a
  fixed pool. The plugin writes response bytes into it (bounded by `cap`), reads
  them, and never frees them.

### 2.4 Returning dynamic JSON without a heap

The plugin does not return a JSON blob it allocated. Instead it **emits records
into a host-provided sink**, which writes into host-owned fixed storage. Two
emission styles are supported; both are heap-free:

**(a) Structured key/value emission (preferred).** The plugin, after parsing an
upstream API's JSON *in place* (§3.3) from a host buffer, emits normalized
fields:

```c
typedef struct alosint_sink {
    // Begin a result record; returns a record handle or <0 if the pool is full.
    int  (*begin)(void *sctx, const char *source_id);
    // Add a field to the open record. Values are copied into the host's
    // fixed string arena; both pointers are borrowed for the call only.
    int  (*field)(void *sctx, int rec, const char *key,
                  const char *val, size_t val_len);
    // Commit the record into the host record store.
    int  (*commit)(void *sctx, int rec);
    void *sctx;
} alosint_sink_t;
```

The sink copies each field's bytes into a Goose-owned **string arena** and
records offsets in a **record slot** (§3.2). When the arena or slot pool is
full, `begin`/`field` return `ALOSINT_FULL`; the plugin stops emitting and the
record store is marked `TRUNCATED`. No allocation occurs on either side.

**(b) Raw passthrough.** For sources whose payload the user may want verbatim,
the plugin copies raw response bytes into a host-leased `alosint_buf_t` and tags
the record `kind = RAW`. The renderer can emit or elide raw payloads by flag.

Either way, "dynamic JSON" is realized as *bounded structured records in fixed
host storage*, not as a dynamically sized value owned by the plugin. The plugin
is a producer that writes through host-controlled, capacity-checked sinks.

### 2.5 Loading, executing, unloading `.so` plugins

The `plugin_loader` (Goose) drives a thin C `plugin_host` shim that wraps
`dlopen`/`dlsym`/`dlclose` (Goose does not call libdl directly). Goose binds the
shim with `extern fn` declarations that trade only in slices, scalars, and
borrowed struct references — never a raw `void*`:

```goose
// Open a plugin by path; returns a registry index (>=0) or negative err.
// The raw void* from dlopen stays on the C side, keyed by this index.
extern fn alosint_dl_open(path: const u8[:]) -> i32;

// Run the handshake + info load for an opened plugin; C fills `info`.
extern fn alosint_dl_probe(idx: i32, info: PluginInfo&) -> i32;

// Close and release the slot.
extern fn alosint_dl_close(idx: i32) -> i32;
```

The Goose side holds only the `i32` index; the native handle never crosses the
boundary, so Goose cannot manipulate (or mistakenly free) a `void*`.

**Discovery & load**

1. Scan `config.plugins.dir` (default `./plugins`, overridable) for `*.so`.
   Paths are validated (no symlink escape outside the plugin dir).
2. For each: `dlopen(path, RTLD_NOW | RTLD_LOCAL)`.
   - `RTLD_NOW` forces eager symbol resolution → a plugin with missing symbols
     fails at load, not mid-run.
   - `RTLD_LOCAL` keeps plugin symbols out of the global namespace so two
     plugins can't collide or interpose on each other.
3. `dlsym` the required exports. Any missing export → reject + `dlclose`.
4. Call `alosint_plugin_abi_version()`; mismatch → reject + `dlclose`.
5. Read `alosint_plugin_info()`; register `id`, capabilities, accepted input
   kinds into a fixed **plugin registry slot pool** (`PLUGIN_SLOTS` capacity).
6. If present, call `alosint_plugin_init(host)`; non-zero → reject + `dlclose`.

The Goose side holds only an opaque handle (an index into the registry); the
raw `void*` from `dlopen` lives on the C side, referenced by that index. Goose
never manipulates native handles directly.

**Execute**

For a given query, the orchestrator selects plugins whose `input_kinds` match
the query kind and whose capabilities are permitted by config, then calls
`alosint_plugin_run(query, host, sink)` per plugin (dispatched across the worker
pool, §4.4). Each call is wrapped in the error-grading harness: a failing
plugin degrades its own source to an error record and never aborts the run.

**Unload**

At shutdown (or on explicit unload), for each registered plugin:
`alosint_plugin_shutdown()` → `dlclose(handle)` → release the registry slot.
Because no plugin memory is aliased by the host after a `run` returns (all data
was copied into host arenas), `dlclose` is safe: there are no dangling pointers
into the unloaded `.so`'s static data.

### 2.6 Plugin trust & isolation (v1 scope and limits)

`.so` plugins run **in-process with full native privileges** — `dlopen` of
untrusted native code is, by nature, not a security boundary. v1 therefore
treats plugins as *trusted code* and mitigates at the edges rather than
pretending to sandbox:

- Capability bitmask gating (a plugin without `NET_HTTP` is never handed a
  working `http_get`; the host returns `ALOSINT_DENIED`).
- Centralized network policy (Tor, rate limits, allow/deny host lists) the
  plugin cannot bypass because it has no direct socket access.
- Plugin directory path validation and an optional signature/manifest allowlist
  (`plugins.manifest`).
- Documented non-goal: v1 does not defend against a malicious `.so`. Untrusted
  sources are a future direction (out-of-process plugin workers behind the same
  Host API, communicating over a pipe) and the Host-API indirection is designed
  to make that migration possible without changing the plugin ABI.

---

## 3. Data Flow & Memory Management

### 3.1 End-to-end flow: CLI → plugin → terminal

```
  user: alosint run --target example.com --tor --sources dns_enum,crt_sh --json

  ┌───────┐   query    ┌──────────────┐  select  ┌────────────────┐
  │  cli  │──────────▶│ orchestrator │────────▶│ plugin_loader  │
  └───────┘  (parsed) └──────┬───────┘          └───────┬────────┘
     │ reserves                │ leases buffers/slots     │ dispatch run()
     │ record_store            │ from fixed pools         ▼
     │ & arenas         ┌──────▼────────┐          ┌──────────────┐
     └─────────────────▶│  host_api     │◀────────│  C .so plugin │
                        │  (Goose↔C)    │  http_*  └──────┬───────┘
                        └──────┬────────┘  callbacks      │ emits via sink
                               │ http_client (C/libcurl)  │
                               ▼                          ▼
                        network / Tor            record_store (slot pool)
                                                         │
                                                  ┌──────▼───────┐
                                                  │   output     │─▶ terminal
                                                  │  (renderer)  │   (table/json)
                                                  └──────────────┘
```

Step by step:

1. **`cli`** parses argv into a fixed `Command` struct (target, selected
   sources, flags). Invalid input → usage error, no allocation.
2. **`orchestrator`** builds a `Query` (kind inferred from target: domain / ip /
   email / username), validates requested sources against the registry, and
   reserves the run's storage: a `record_store` slot pool, a `string arena`, and
   leases from the `ResponseBuffer` pool. All capacities are fixed and known up
   front.
3. **`plugin_loader`** supplies the matching plugin set.
4. For each plugin (on a worker), **`host_api`** hands over `query`, the host
   vtable, and a `sink` bound to the shared `record_store`.
5. The plugin calls `host.http_get(...)`; **`host_api`** forwards to the C
   **`http_client`**, which performs the request (Tor-routed if flagged) into a
   leased `ResponseBuffer`.
6. The plugin tokenizes that buffer in place (§3.3), extracts fields, and
   `sink.field(...)`/`sink.commit(...)` them. The sink copies bytes into the
   string arena and fills record slots.
7. After all plugins finish (or time out), **`output`** walks the `record_store`
   and renders to the terminal as a table (default) or JSON (`--json`),
   streaming so render memory is also bounded.

At no point does any component call an allocator or a `free`; every buffer is a
lease from a pre-sized pool, returned when the run ends.

### 3.2 Fixed storage primitives

Three primitives carry all dynamic-looking data:

- **Arena (bump buffer).** A `[ARENA_CAP]u8` with a `head` offset. `push(bytes)`
  copies and returns an `(offset, len)` slice descriptor, or `FULL`. Reset in
  O(1) by zeroing `head` at end of run. Used for all variable-length strings
  (field values, URLs, raw payloads). No per-string free — the whole arena is
  reclaimed at once.

- **Slot pool.** A fixed array `[N]Record` plus a free-list (stack of free
  indices). `acquire()` pops a free index or returns `FULL`; `release(i)` pushes
  it back. Records reference strings by `(arena_offset, len)` slices, not owning
  pointers. Used for the plugin registry, the record store, and in-flight request
  bookkeeping.

- **ResponseBuffer pool.** A small fixed set of large `[RESP_CAP]u8` buffers
  (§1.2), leased to one in-flight HTTP call at a time. Pool size == max
  concurrent requests.

A `Record` is purely offsets/handles — no embedded pointers into C memory:

```
Record {
    source_id:  SliceRef   // (arena_offset, len)
    kind:       RecordKind  // FIELDS | RAW | ERROR
    fields:     [MAX_FIELDS]{ key: SliceRef, val: SliceRef }
    field_len:  u16
    status:     err_t
}
```

Because records hold only arena slices, they remain valid after the producing
plugin's `.so` is `dlclose`d — nothing points back into plugin memory.

### 3.3 JSON parsing with no GC

Upstream OSINT APIs return arbitrarily shaped JSON. We parse it **without
allocation** using a **non-allocating, in-place tokenizer** (jsmn-style) in the
C `json_parser` module:

- Input: the `ResponseBuffer` already filled by `http_client` (bytes live in
  Goose-owned storage).
- Output: a caller-provided fixed array `alosint_jtok_t[JSON_TOK_CAP]`, where
  each token is `{ type, start, end, size, parent }` — **offsets into the
  original buffer**, not copies.

```c
typedef enum { JT_OBJ, JT_ARR, JT_STR, JT_PRIM } alosint_jtok_type_t;
typedef struct {
    alosint_jtok_type_t type;
    int start;   // byte offset into the source buffer
    int end;     // one past the last byte
    int size;    // child count
    int parent;  // index of parent token, -1 for root
} alosint_jtok_t;

// Returns token count, or ALOSINT_JSON_FULL if JSON_TOK_CAP is exceeded,
// or a negative parse error. Never allocates.
int alosint_json_parse(const uint8_t *buf, size_t len,
                       alosint_jtok_t *toks, size_t tok_cap);
```

Goose binds it with the input bytes as a read-only slice and the token array as
a mutable slice it lends:

```goose
// buf: the filled ResponseBuffer bytes, read-only.
// toks: Goose-owned fixed token storage; toks.len is JSON_TOK_CAP.
extern fn alosint_json_parse(buf: const u8[:], toks: JTok[:]) -> i32;
```

The `const u8[:]` and `JTok[:]` slices each carry their own length, so the C
`len`/`tok_cap` arguments fold into the slices Goose passes.

- **Values are slices**, read directly from the source buffer by offset. A field
  value is only copied once — when the plugin hands it to `sink.field`, which
  arena-copies it into Goose storage that outlives the response buffer.
- **Capacity exceeded** (document deeper/larger than `JSON_TOK_CAP`) is a graceful
  `TRUNCATED` on that source, not a crash. Caps are sized from observed API
  payloads and configurable.
- Goose exposes a thin `json` wrapper over this C module: helpers like
  "find the token for path `data.0.name_value` under a parent" that walk the
  token array by index — no allocation, pure index arithmetic over the fixed
  token buffer.

This is the core answer to "dynamic JSON with no GC": we never build a dynamic
object graph. We tokenize in place into a fixed token array and copy only the
specific leaf values we keep, into a bump arena that is reset wholesale at the
end of the run.

### 3.4 Lifetimes & the end-of-run reset

The run is the allocation lifetime unit. At run end:

1. `output` has finished reading the `record_store`.
2. Release all leased `ResponseBuffer`s back to the pool.
3. Reset the string arena (`head = 0`) and the record slot pool (rebuild free
   list) in O(1).

No per-object teardown, no fragmentation, deterministic peak memory equal to the
sum of the fixed pool capacities declared in `limits.goose`.

### 3.5 Error model

A single `alosint_err_t` enum crosses the boundary (shared header). Codes are
graded:

- **Transport/plugin errors** (timeout, HTTP 5xx, DNS failure) → an `ERROR`
  record for that source; the run continues.
- **Capacity signals** (`FULL`, `TRUNCATED`, `JSON_FULL`) → partial results are
  kept and flagged; surfaced to the user as "results truncated (cap reached)".
- **Policy errors** (`DENIED` — e.g. direct request under `force`-Tor) →
  fail-closed for that request.
- **Fatal errors** (ABI mismatch at load, global curl init failure) → abort
  before any network activity.

Errors are data, carried in records and a run summary, never exceptions.

---

## 4. Module Boundaries

### 4.1 Goose modules (orchestration core)

| Module | Responsibility | Depends on |
|---|---|---|
| `cli` | Parse argv into a fixed `Command`; usage/help; flag validation. | `config` |
| `config` | Load/merge config file + flags + env; Tor mode, plugin dir, caps, secrets handles. | — |
| `orchestrator` | Build `Query`, select plugins, reserve run storage, dispatch runs, aggregate results, enforce timeouts. | `plugin_loader`, `host_api`, `record_store`, `output` |
| `plugin_loader` | Discover/register/unload plugins via the `plugin_host` C shim; ABI handshake; registry slot pool. | `plugin_host` (C) |
| `host_api` | Implement the `alosint_host_api_t` vtable Goose exposes to plugins; bridge `http_get`/`dns_lookup`/`get_secret`/`log` to C modules; enforce capability gating. | `http_client` (C), `dns` (C), `config` |
| `record_store` | Slot pool of `Record`s + string arena; implement the `alosint_sink_t` the plugins emit through. | `arena`, `slot_pool` |
| `json` | Thin Goose wrapper over `json_parser` (C): path lookups, typed value slicing over the token array. | `json_parser` (C) |
| `output` | Render the record store to terminal: table, JSON, NDJSON; streaming, bounded. | `record_store` |
| `arena` / `slot_pool` | Fixed-capacity storage primitives (§3.2). | — |
| `limits` | Central compile-time capacity constants (`RESP_CAP`, `PLUGIN_SLOTS`, `ARENA_CAP`, `JSON_TOK_CAP`, `HTTP_HANDLE_POOL`, …). | — |
| `errors` | Shared error enum/text mirroring `alosint_err_t`. | — |

### 4.2 C modules (interop + runtime services)

| Module | Responsibility | Links |
|---|---|---|
| `abi` (`alosint_plugin.h`, `alosint_ffi.h`) | The frozen, versioned contract: all POD structs, enums, vtable layouts, `static_assert`s on sizes/offsets. Shared by host and every plugin. | — |
| `http_client` | The only libcurl user: handle pool, request perform, bounded write callback, Tor/`socks5h` proxy, timeouts, TLS verify, rate limiting. | libcurl |
| `dns` | Optional explicit resolver (A/AAAA/MX/TXT/NS) filling fixed `alosint_dns_rr_t[]`; leak-aware (no local lookups under force-Tor). | libc resolver / libcurl |
| `json_parser` | Non-allocating in-place JSON tokenizer (§3.3). | — |
| `plugin_host` | `dlopen`/`dlsym`/`dlclose` wrapper; symbol resolution; handle table keyed by registry index. | libdl |
| `buffer` | Definitions + bounds helpers for `alosint_buf_t` and the write callback; the physical storage is Goose-owned. | — |

### 4.3 The three contract seams

1. **Goose ↔ host C shims** (`host_api` → `http_client`/`dns`/`json_parser`/
   `plugin_host`): flat, synchronous, borrow-only C functions bound with Goose
   `extern fn` declarations and reached through `const u8[:]` slices, `u8&`
   pointers, and borrowed struct references. The narrow, fully audited FFI
   surface.
2. **Host ↔ plugin** (`alosint_host_api_t` vtable + `alosint_plugin_*` exports):
   the versioned plugin ABI. Capabilities flow host→plugin; data flows
   plugin→host via `sink`.
3. **Run storage ↔ everything** (`record_store`, arena, buffer pools): the
   fixed-capacity substrate every component leases from and no one allocates.

Keeping these three seams explicit is what lets a no-heap/no-GC core cooperate
safely with libcurl and arbitrary C `.so` code.

### 4.4 Threading model

- A fixed worker pool (`WORKER_THREADS`, compile-time) runs blocking
  `alosint_plugin_run` calls concurrently; pool size ≤ `HTTP_HANDLE_POOL`.
- Each worker owns disjoint leased storage (its own `ResponseBuffer` and JSON
  token array); only the shared `record_store` sink is synchronized.
- The `sink` implementation is the single synchronization point: `begin`/
  `field`/`commit` take a short lock (or lock-free slot claim) so concurrent
  plugins append records safely into the shared pool. Nothing else is shared
  mutable state across threads.
- libcurl is used in the documented thread-safe way: one `CURL*` per thread at a
  time (no handle shared across threads), `curl_global_init` once before threads
  start.

---

## 5. Build & Repository Layout (planning)

```
alosint/
  alosint.goose     # Goose program entry point
  alosint.build     # Goose build sidecar: lists the C sources to compile in
  src/              # Goose core (cli, orchestrator, host_api, record_store, ...)
  c/
    abi/            # alosint_plugin.h, alosint_ffi.h  (shared contract)
    http_client.c   # libcurl wrapper
    json_parser.c   # in-place tokenizer
    plugin_host.c   # dlopen shim
    dns.c           # optional explicit resolver
  plugins/          # built .so OSINT sources (loaded at runtime)
    dns_enum/
    crt_sh/
    whois/
  config/           # default config, limits
  ARCHITECTURE.md
```

The core's C shims are compiled into the Goose program through the build
sidecar that sits beside `alosint.goose`. Goose reads `alosint.build` and
compiles each listed C source, so the program's `extern fn` declarations resolve
against those objects:

```
// alosint.build
c_sources = ["c/http_client.c", "c/json_parser.c", "c/plugin_host.c", "c/dns.c"];
```

- Each C module is reached only through the `extern fn` bindings shown in §1–§3;
  the Goose side never calls libcurl, libdl, or the resolver directly. libcurl
  and libdl are linked by the shim objects named in `c_sources`.
- Plugins are built separately as `.so`s against `abi/` headers only (no libcurl
  dependency in plugins) and are loaded at runtime via the `plugin_host` shim —
  they are not part of `c_sources`.
- ABI compatibility is enforced at compile time (`static_assert` in `abi/`, which
  also pins every slice/struct layout the `extern fn`s rely on) and at load time
  (`alosint_plugin_abi_version`).

---

## 6. Open Questions / Future Directions

- **Out-of-process plugins** for untrusted sources, reusing the same Host API
  over a pipe (addresses §2.6's non-goal without changing the plugin ABI).
- **`curl_multi` backend** behind the `http_client` facade for higher
  concurrency without more OS threads.
- **Capacity autotuning**: surface per-source `TRUNCATED` rates so `limits`
  constants can be tuned from real workloads.
- **Result persistence**: an append-only NDJSON exporter fed from the same
  streaming `output` path (still bounded, no in-memory accumulation).
- **Rate-limit policy per source**: config-driven token buckets in `http_client`
  keyed by source id.
