// modules/rdap.goose
//
// RDAP (modern WHOIS) module: a thin Goose wrapper over the C
// `alosint_rdap_lookup` shim in c/rdap.c (compiled in via alosint.build, which
// links libcurl). Fetches the raw RDAP JSON for a domain.
//
// Memory ownership never crosses the FFI boundary (ARCHITECTURE.md §1): Goose
// owns every byte buffer; C only writes into the window it is lent, bounded by
// the capacity Goose passes, and never allocates storage Goose must free.

// Bind the C symbol:
//     int alosint_rdap_lookup(const char *domain, char *json_out, int max_len);
// `domain` and `json_out` cross as plain byte pointers (u8&); `max_len` is a C
// int (i32). Returns 0 on success, -1 on transport error, -2 on HTTP error.
extern fn alosint_rdap_lookup(domain: u8&, json_out: u8&, max_len: i32) -> i32;

// Capacity of the response window lent to C, in bytes (64 KiB). RDAP records are
// typically a few KB; larger bodies are truncated by the C shim.
let RDAP_CAP: i32 = 65536;

// lookup fetches the RDAP JSON for `domain` and appends the raw body (without a
// trailing NUL) to the caller-owned builder `out_buf`.
// Returns true on success, false on any transport or HTTP failure.
fn lookup(domain: const u8[:], out_buf: u8[>..]&) -> bool {
    // The C side needs a NUL-terminated string. Copy the borrowed slice into a
    // Goose-owned builder and terminate it ourselves.
    var name: u8[>..] = [];
    for i: i32 in 0..domain.len {
        name.push(domain[i]);
    }
    name.push(0);

    // Lend C a fixed, Goose-owned window for the JSON response.
    var json: u8[>..] = [];
    for i: i32 in 0..RDAP_CAP {
        json.push(0);
    }

    let rc = alosint_rdap_lookup(name[0], json[0], RDAP_CAP);
    if rc != 0 {
        return false;
    }

    // Copy the NUL-terminated body into the caller's builder.
    for i: i32 in 0..json.len {
        if json[i] == 0 {
            break;
        }
        out_buf.push(json[i]);
    }
    true
}
