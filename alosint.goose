import os;
import modules.crtsh;
import modules.dns;
import modules.json_writer;
import modules.rdap;

extern fn alosint_set_tor(enabled: i32);
extern fn alosint_get_tor() -> i32;
extern fn alosint_write_file(path: u8&, data: u8&, len: i32) -> i32;

var SINK: u8[>..] = [];

let HELP = """
    AlOsint 1.0.0 - passive OSINT for authorized targets

    Usage:
      alosint -d <domain> [--rdap] [--subdomains] [--subdomains-raw] [--json] [--tor] [--output <file>] [--quiet]
      alosint --email <email> [--json] [--tor] [--output <file>] [--quiet]
      alosint --ip <ip> [--json] [--tor] [--output <file>] [--quiet]
      alosint -h | --help

    Options:
      -d, --domain <domain>  Target domain to investigate
          --email <email>    Search Certificate Transparency for an email address
          --ip <ip>          Retrieve RDAP network summary for an IP address
          --rdap             Retrieve RDAP registration summary
          --subdomains       Print unique subdomains discovered via crt.sh
          --subdomains-raw   Print raw crt.sh JSON
          --json             Emit one unified JSON object
          --tor              Route HTTP(S) through a local SOCKS5 proxy at 127.0.0.1:9050 (DNS is not proxied).
      -o, --output <file>    Write output to a file instead of stdout
      -q, --quiet            Suppress human-readable output
      -h, --help             Print this help and exit

    Legal:
      Use AlOsint only on systems you own or are explicitly authorized to
      assess. Unauthorized scanning may be unlawful. Tor is a transport
      option: it is not anonymity and it does not grant authorization.
      See LEGAL.md for the full notice.
    """;

struct Config {
    json: bool,
    tor: bool,
    rdap: bool,
    subdomains: bool,
    subdomains_raw: bool,
    quiet: bool,
    email_mode: bool,
    ip_mode: bool,
    target: u8[],
    output: u8[>..],
}

fn emit(cfg: Config&, msg: const u8[:]) {
    if cfg.output.len == 0 {
        print(msg);
    } else {
        SINK.append(msg);
        SINK.push('\n');
    }
}

fn write_output(cfg: Config&) {
    if cfg.output.len == 0 {
        return;
    }
    var path: u8[>..] = [];
    for i: i64 in 0..cfg.output.len {
        path.push(cfg.output[i]);
    }
    path.push(0);
    SINK.push(0);
    let rc = alosint_write_file(path[0], SINK[0], (SINK.len - 1) as i32);
    if rc != 0 {
        write_stderr(str("alosint: could not write output file: ", cfg.output, "\n"));
        exit(1);
    }
}

fn usage_error(msg: const u8[:]) {
    write_stderr(str("alosint: ", msg, "\n"));
    write_stderr("try 'alosint --help' for usage\n");
    exit(2);
}

fn parse_args() -> Config {
    let argv = args();
    var domain: u8[>..] = [];
    var email: u8[>..] = [];
    var ip: u8[>..] = [];
    var output: u8[>..] = [];
    var json = false;
    var tor = false;
    var rdap = false;
    var subdomains = false;
    var subdomains_raw = false;
    var quiet = false;
    var i = 1;
    while i < argv.len {
        let a = argv[i];
        if a == "-h" || a == "--help" {
            print(HELP);
            exit(0);
        } else if a == "-d" || a == "--domain" {
            if i + 1 >= argv.len || (argv[i + 1].len > 0 && argv[i + 1][0] == '-') {
                usage_error(str("missing value for ", a));
            }
            if domain.len > 0 {
                usage_error("domain specified more than once");
            }
            i++;
            if argv[i].len == 0 { usage_error("domain must not be empty"); }
            domain.append(argv[i]);
        } else if a == "--email" {
            if i + 1 >= argv.len || (argv[i + 1].len > 0 && argv[i + 1][0] == '-') {
                usage_error(str("missing value for ", a));
            }
            if email.len > 0 {
                usage_error("email specified more than once");
            }
            i++;
            if argv[i].len == 0 { usage_error("email must not be empty"); }
            email.append(argv[i]);
        } else if a == "--ip" {
            if i + 1 >= argv.len || (argv[i + 1].len > 0 && argv[i + 1][0] == '-') {
                usage_error(str("missing value for ", a));
            }
            if ip.len > 0 {
                usage_error("ip specified more than once");
            }
            i++;
            if argv[i].len == 0 { usage_error("ip must not be empty"); }
            ip.append(argv[i]);
        } else if a == "--output" || a == "-o" {
            if i + 1 >= argv.len || (argv[i + 1].len > 0 && argv[i + 1][0] == '-') {
                usage_error(str("missing value for ", a));
            }
            if output.len > 0 {
                usage_error("output specified more than once");
            }
            i++;
            if argv[i].len == 0 { usage_error("output path must not be empty"); }
            var j: i64 = 0;
            while j < argv[i].len {
                if argv[i][j] == 0 {
                    usage_error("output path must not contain NUL");
                }
                j++;
            }
            output.append(argv[i]);
        } else if a == "--quiet" || a == "-q" {
            quiet = true;
        } else if a == "--json" {
            json = true;
        } else if a == "--tor" {
            tor = true;
        } else if a == "--rdap" {
            rdap = true;
        } else if a == "--subdomains" {
            subdomains = true;
        } else if a == "--subdomains-raw" {
            subdomains_raw = true;
        } else {
            usage_error(str("unknown option: ", a));
        }
        i++;
    }
    if domain.len > 0 && email.len > 0 {
        usage_error("-d/--domain and --email are mutually exclusive");
    }
    if ip.len > 0 && domain.len > 0 {
        usage_error("--ip and -d/--domain are mutually exclusive");
    }
    if ip.len > 0 && email.len > 0 {
        usage_error("--ip and --email are mutually exclusive");
    }
    if domain.len == 0 && email.len == 0 && ip.len == 0 {
        usage_error("missing required -d/--domain, --email, or --ip");
    }
    if ip.len > 0 {
        return Config { json: json, tor: tor, rdap: rdap, subdomains: subdomains, subdomains_raw: subdomains_raw, quiet: quiet, email_mode: false, ip_mode: true, target: copy(ip), output: copy(output) };
    }
    if email.len > 0 {
        return Config { json: json, tor: tor, rdap: rdap, subdomains: subdomains, subdomains_raw: subdomains_raw, quiet: quiet, email_mode: true, ip_mode: false, target: copy(email), output: copy(output) };
    }
    return Config { json: json, tor: tor, rdap: rdap, subdomains: subdomains, subdomains_raw: subdomains_raw, quiet: quiet, email_mode: false, ip_mode: false, target: copy(domain), output: copy(output) };
}

fn find_from(s: const u8[:], start: i64, needle: const u8[:]) -> i64 {
    if needle.len == 0 {
        return start;
    }
    var i = start;
    while i + needle.len <= s.len {
        var j: i64 = 0;
        var same = true;
        while j < needle.len {
            if s[i + j] != needle[j] {
                same = false;
                break;
            }
            j++;
        }
        if same {
            return i;
        }
        i++;
    }
    -1
}

fn main() {
    let cfg = parse_args();
    if cfg.tor {
        alosint_set_tor(1);
    }

    if cfg.email_mode {
        var email_raw: u8[>..] = [];
        let email_ok = crtsh::lookup_email(cfg.target, email_raw);
        var email_names: u8[>..] = [];
        var email_count: i32 = 0;
        if email_ok {
            email_count = crtsh::summary_emails(email_raw, email_names);
            if email_count < 0 {
                email_count = 0;
            }
        }

        if cfg.json {
            var out: u8[>..] = [];
            out.append("{\"email\":\"");
            json_writer::escape(cfg.target, out);
            out.append("\",\"entries\":");
            if !email_ok {
                out.append("null,\"entries_error\":\"lookup failed\"");
            } else if email_count > 0 {
                out.push('[');
                var start: i64 = 0;
                var first = true;
                var i: i64 = 0;
                while i <= email_names.len {
                    if i == email_names.len || email_names[i] == '\n' {
                        if i > start {
                            if !first {
                                out.push(',');
                            }
                            first = false;
                            out.push('"');
                            json_writer::escape(email_names[start..i], out);
                            out.push('"');
                        }
                        start = i + 1;
                    }
                    i++;
                }
                out.push(']');
            } else {
                out.append("[]");
            }
            out.push('}');
            emit(cfg, out);
        } else if !cfg.quiet {
            if !email_ok {
                emit(cfg, str(cfg.target, " email lookup failed"));
            } else {
                emit(cfg, str(cfg.target, " found in Certificate Transparency:"));
                emit(cfg, str("Unique entries (", email_count, "):"));
                var start: i64 = 0;
                var i: i64 = 0;
                while i <= email_names.len {
                    if i == email_names.len || email_names[i] == '\n' {
                        if i > start {
                            emit(cfg, str("  - ", email_names[start..i]));
                        }
                        start = i + 1;
                    }
                    i++;
                }
            }
        }
        write_output(cfg);
        if !email_ok {
            exit(1);
        }
        return;
    }

    if cfg.ip_mode {
        var ip_rdap: u8[>..] = [];
        let ip_ok = rdap::lookup_ip(cfg.target, ip_rdap);
        var ip_summary: u8[>..] = [];
        if ip_ok {
            rdap::format_ip_summary(ip_rdap, ip_summary);
        }

        if cfg.json {
            var out: u8[>..] = [];
            out.append("{\"ip\":\"");
            json_writer::escape(cfg.target, out);
            out.append("\",\"rdap\":");
            if ip_ok {
                let network_prefix = "Network: ";
                let range_sep = " | Range: ";
                let country_sep = " | Country: ";
                let type_sep = " | Type: ";
                let n_start = find_from(ip_summary, 0, network_prefix);
                let r_sep = find_from(ip_summary, 0, range_sep);
                let c_sep = find_from(ip_summary, 0, country_sep);
                let t_sep = find_from(ip_summary, 0, type_sep);
                if n_start >= 0
                    && r_sep >= n_start + network_prefix.len
                    && c_sep >= r_sep + range_sep.len
                    && t_sep >= c_sep + country_sep.len
                    && ip_summary.len >= t_sep + type_sep.len {
                    let n_begin = n_start + network_prefix.len;
                    let r_begin = r_sep + range_sep.len;
                    let c_begin = c_sep + country_sep.len;
                    let t_begin = t_sep + type_sep.len;
                    out.append("{\"network\":\"");
                    json_writer::escape(ip_summary[n_begin..r_sep], out);
                    out.append("\",\"range\":\"");
                    json_writer::escape(ip_summary[r_begin..c_sep], out);
                    out.append("\",\"country\":\"");
                    json_writer::escape(ip_summary[c_begin..t_sep], out);
                    out.append("\",\"type\":\"");
                    json_writer::escape(ip_summary[t_begin..ip_summary.len], out);
                    out.append("\"}");
                } else {
                    out.append("{\"network\":\"");
                    json_writer::escape(ip_summary, out);
                    out.append("\",\"range\":\"Unknown\",\"country\":\"Unknown\",\"type\":\"Unknown\"}");
                }
            } else {
                out.append("null,\"rdap_error\":\"lookup failed\"");
            }
            out.push('}');
            emit(cfg, out);
        } else if !cfg.quiet {
            if ip_ok {
                emit(cfg, str(cfg.target, " RDAP Summary: ", ip_summary));
            } else {
                emit(cfg, str(cfg.target, " RDAP lookup failed"));
            }
        }
        write_output(cfg);
        if !ip_ok {
            exit(1);
        }
        return;
    }

    var ip: u8[>..] = [];
    var dns_ok = dns::lookup(cfg.target, ip);

    var rdap_data: u8[>..] = [];
    var rdap_ok = false;
    var rdap_summary: u8[>..] = [];
    if cfg.rdap {
        rdap_ok = rdap::lookup(cfg.target, rdap_data);
        if rdap_ok {
            rdap::format_summary(rdap_data, rdap_summary);
        }
    }

    var crtsh_raw: u8[>..] = [];
    var crtsh_ok = false;
    var sub_names: u8[>..] = [];
    var sub_count: i32 = 0;
    if cfg.subdomains || cfg.subdomains_raw {
        crtsh_ok = crtsh::lookup(cfg.target, crtsh_raw);
        if crtsh_ok && cfg.subdomains {
            sub_count = crtsh::summary(crtsh_raw, cfg.target, sub_names);
        }
    }

    var lookup_failed = false;
    if cfg.rdap && !rdap_ok {
        lookup_failed = true;
    }
    if (cfg.subdomains || cfg.subdomains_raw) && !crtsh_ok {
        lookup_failed = true;
    }

    if !cfg.json && !cfg.quiet {
        if dns_ok {
            emit(cfg, str(cfg.target, " resolves to: ", ip));
        } else {
            emit(cfg, str(cfg.target, " could not be resolved"));
        }

        if cfg.rdap {
            if rdap_ok {
                emit(cfg, str("RDAP Summary for ", cfg.target, ": ", rdap_summary));
            } else {
                emit(cfg, str("RDAP Data for ", cfg.target, " could not be retrieved"));
            }
        }

        if cfg.subdomains {
            if !crtsh_ok {
                emit(cfg, str(cfg.target, " subdomain lookup failed"));
            } else if sub_count > 0 {
                emit(cfg, str("\nUnique subdomains (", sub_count, "):\n"));
                emit(cfg, sub_names);
            } else {
                emit(cfg, "No subdomains found.");
            }
        }

        if cfg.subdomains_raw {
            if crtsh_ok {
                emit(cfg, crtsh_raw);
            } else if !cfg.subdomains {
                emit(cfg, str(cfg.target, " subdomain lookup failed"));
            }
        }
    }

    if cfg.json {
        var out: u8[>..] = [];
        out.append("{\"domain\":\"");
        json_writer::escape(cfg.target, out);
        out.append("\",\"ip\":");
        if dns_ok {
            out.push('"');
            json_writer::escape(ip, out);
            out.push('"');
        } else {
            out.append("null");
        }

        out.append(",\"rdap\":");
        if cfg.rdap {
            if rdap_ok {
                let sep = find_from(rdap_summary, 0, " | ");
                let reg_prefix = "Registrar: ";
                let date_prefix = "Registered: ";
                var matched = false;
                if sep >= 0 && find_from(rdap_summary, 0, reg_prefix) == 0 {
                    if find_from(rdap_summary, sep + 3, date_prefix) == sep + 3 {
                        matched = true;
                    }
                }
                if matched {
                    out.append("{\"registrar\":\"");
                    json_writer::escape(rdap_summary[reg_prefix.len..sep], out);
                    out.append("\",\"registered\":\"");
                    let date_start = sep + 3 + date_prefix.len;
                    json_writer::escape(rdap_summary[date_start..rdap_summary.len], out);
                    out.append("\"}");
                } else {
                    out.push('"');
                    json_writer::escape(rdap_summary, out);
                    out.push('"');
                }
            } else {
                out.append("null,\"rdap_error\":\"lookup failed\"");
            }
        } else {
            out.append("null");
        }

        if cfg.subdomains {
            out.append(",\"subdomains\":");
            if !crtsh_ok {
                out.append("null,\"subdomains_error\":\"lookup failed\"");
            } else if sub_count > 0 {
                out.push('[');
                var start: i64 = 0;
                var first = true;
                var i: i64 = 0;
                while i <= sub_names.len {
                    if i == sub_names.len || sub_names[i] == '\n' {
                        if i > start {
                            if !first {
                                out.push(',');
                            }
                            first = false;
                            out.push('"');
                            json_writer::escape(sub_names[start..i], out);
                            out.push('"');
                        }
                        start = i + 1;
                    }
                    i++;
                }
                out.push(']');
            } else {
                out.append("[]");
            }
        }

        if cfg.subdomains_raw {
            out.append(",\"subdomains_raw\":");
            if crtsh_ok {
                out.append(crtsh_raw);
            } else {
                out.append("null");
                if !cfg.subdomains {
                    out.append(",\"subdomains_error\":\"lookup failed\"");
                }
            }
        }

        out.push('}');
        emit(cfg, out);
    }
    write_output(cfg);
    if lookup_failed {
        exit(1);
    }
}
