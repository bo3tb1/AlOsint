// modules/crtsh.goose
//
// Certificate Transparency subdomain discovery via crt.sh. A thin Goose
// wrapper over the C `alosint_crtsh_lookup` shim in c/crtsh.c.

namespace crtsh;

//     int alosint_crtsh_lookup(const char *domain, char *json_out, int max_len);
extern fn alosint_crtsh_lookup(domain: u8&, json_out: u8&, max_len: i32) -> i32;

let CRTSH_CAP: i32 = 262144;

// lookup fetches the raw crt.sh JSON for `domain` and appends it to `out_buf`.
// Returns true on success, false on any transport or HTTP failure.
fn lookup(domain: const u8[:], out_buf: u8[>..]&) -> bool {
    var name: u8[>..] = [];
    for i: i64 in 0..domain.len {
        name.push(domain[i]);
    }
    name.push(0);

    var json: u8[>..] = [];
    for i: i32 in 0..CRTSH_CAP {
        json.push(0);
    }

    let rc = alosint_crtsh_lookup(name[0], json[0], CRTSH_CAP);
    if rc != 0 {
        return false;
    }

    for i: i64 in 0..json.len {
        if json[i] == 0 {
            break;
        }
        out_buf.push(json[i]);
    }
    true
}

//     int alosint_crtsh_extract_unique(const char *json_str, const char *domain,
//                                      char *out_buf, int max_len);
extern fn alosint_crtsh_extract_unique(json_str: u8&, domain: u8&, out_buf: u8&, max_len: i32) -> i32;

let SUMMARY_CAP: i32 = 65536;

fn summary(json: const u8[:], domain: const u8[:], out_buf: u8[>..]&) -> i32 {
    var src: u8[>..] = [];
    for i: i64 in 0..json.len {
        src.push(json[i]);
    }
    src.push(0);

    var name: u8[>..] = [];
    for i: i64 in 0..domain.len {
        name.push(domain[i]);
    }
    name.push(0);

    var buf: u8[>..] = [];
    for i: i32 in 0..SUMMARY_CAP {
        buf.push(0);
    }

    let rc = alosint_crtsh_extract_unique(src[0], name[0], buf[0], SUMMARY_CAP);
    for i: i64 in 0..buf.len {
        if buf[i] == 0 {
            break;
        }
        out_buf.push(buf[i]);
    }
    rc
}
