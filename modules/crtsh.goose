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
