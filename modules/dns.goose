// modules/dns.goose
//
// DNS resolution module: a thin Goose wrapper over the C `alosint_dns_lookup`
// shim in c/dns.c (compiled in via alosint.build). IPv4 / A records only.
//
// Memory ownership never crosses the FFI boundary (ARCHITECTURE.md §1): Goose
// owns every byte buffer; C only writes into buffers it is lent, bounded by the
// capacity Goose passes, and never allocates storage Goose must later free.

namespace dns;

// Bind the C symbol:
//     int alosint_dns_lookup(const char *domain, char *ip_out, int max_len);
// `domain` and `ip_out` cross as plain byte pointers (u8&); `max_len` is a C
// int (i32). Returns 0 on success, a negative error code on failure.
extern fn alosint_dns_lookup(domain: u8&, ip_out: u8&, max_len: i32) -> i32;

// lookup resolves `domain` to its first IPv4 address and appends the dotted-quad
// text (without a trailing NUL) to the caller-owned builder `out_buf`.
// Returns true on success, false on any lookup or encoding failure.
fn lookup(domain: const u8[:], out_buf: u8[>..]&) -> bool {
    // getaddrinfo() needs a NUL-terminated C string. Copy the borrowed slice
    // into a Goose-owned builder and terminate it ourselves.
    var name: u8[>..] = [];
    for i: i64 in 0..domain.len {
        name.push(domain[i]);
    }
    name.push(0);

    // Lend C a fixed, Goose-owned window for the result. INET_ADDRSTRLEN is 16,
    // so 64 bytes is ample; C writes a NUL-terminated dotted quad into it.
    var ip: u8[>..] = [];
    for i: i64 in 0..64 {
        ip.push(0);
    }

    let rc = alosint_dns_lookup(name[0], ip[0], 64);
    if rc != 0 {
        return false;
    }

    // Copy the NUL-terminated result into the caller's builder.
    for i: i64 in 0..ip.len {
        if ip[i] == 0 {
            break;
        }
        out_buf.push(ip[i]);
    }
    true
}
