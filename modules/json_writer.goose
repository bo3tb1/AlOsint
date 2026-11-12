// modules/json_writer.goose
//
// JSON string escaping via the C `alosint_json_escape` helper in
// c/json_writer.c. The C side writes only into the bounded window it is lent.

namespace json_writer;

//     int alosint_json_escape(const char *in, char *out, int max_len);
extern fn alosint_json_escape(input: u8&, out: u8&, max_len: i32) -> i32;

// escape appends the JSON-escaped form of `s` (without surrounding quotes) to
// `out_buf` and returns the number of bytes written, or a negative value on
// failure.
fn escape(s: const u8[:], out_buf: u8[>..]&) -> i32 {
    var src: u8[>..] = [];
    for i: i64 in 0..s.len {
        src.push(s[i]);
    }
    src.push(0);

    let cap = (s.len * 4 + 1) as i32;
    var buf: u8[>..] = [];
    for i: i32 in 0..cap {
        buf.push(0);
    }

    let rc = alosint_json_escape(src[0], buf[0], cap);
    if rc < 0 {
        return rc;
    }

    for i: i64 in 0..buf.len {
        if buf[i] == 0 {
            break;
        }
        out_buf.push(buf[i]);
    }
    rc
}
