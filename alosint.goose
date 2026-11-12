import os;
import modules.crtsh;
import modules.dns;
import modules.json_writer;
import modules.rdap;

let HELP = """
    AlOsint 1.0.0 - passive OSINT for authorized targets

    Usage:
      alosint -d <domain> [--rdap] [--subdomains] [--subdomains-raw] [--json] [--tor]
      alosint -h | --help

    Options:
      -d, --domain <domain>  Target domain to investigate (required)
          --rdap             Retrieve RDAP registration summary
          --subdomains       Print unique subdomains discovered via crt.sh
          --subdomains-raw   Print raw crt.sh JSON
          --json             Emit one unified JSON object
          --tor              Route HTTP(S) through a local SOCKS5 proxy
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
    domain: u8[>..],
}

fn usage_error(msg: const u8[:]) {
    write_stderr(str("alosint: ", msg, "\n"));
    write_stderr("try 'alosint --help' for usage\n");
    exit(2);
}

fn parse_args() -> Config {
    let argv = args();
    var domain: u8[>..] = [];
    var json = false;
    var tor = false;
    var rdap = false;
    var subdomains = false;
    var subdomains_raw = false;
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
    if domain.len == 0 { usage_error("missing required -d/--domain"); }
    return Config { json: json, tor: tor, rdap: rdap, subdomains: subdomains, subdomains_raw: subdomains_raw, domain: domain };
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

    var ip: u8[>..] = [];
    let dns_ok = dns::lookup(cfg.domain, ip);
    if !cfg.json {
        if dns_ok {
            print(cfg.domain, " resolves to: ", ip);
        } else {
            print(cfg.domain, " could not be resolved");
        }
    }

    var rdap_summary: u8[>..] = [];
    var rdap_ok = false;
    if cfg.rdap {
        var rdap_data: u8[>..] = [];
        if rdap::lookup(cfg.domain, rdap_data) {
            rdap::format_summary(rdap_data, rdap_summary);
            rdap_ok = true;
            if !cfg.json {
                print("RDAP Summary for ", cfg.domain, ": ", rdap_summary);
            }
        } else if !cfg.json {
            print("RDAP Data for ", cfg.domain, " could not be retrieved");
        }
    }

    var crtsh_raw: u8[>..] = [];
    var names: u8[>..] = [];
    var name_count: i32 = 0;
    if cfg.subdomains || cfg.subdomains_raw {
        if crtsh::lookup(cfg.domain, crtsh_raw) {
            if cfg.subdomains || cfg.json {
                name_count = crtsh::summary(crtsh_raw, cfg.domain, names);
            }
            if !cfg.json {
                if cfg.subdomains {
                    if name_count > 0 {
                        print("\nUnique subdomains (", name_count, "):\n");
                        print(names);
                    } else {
                        print("No subdomains found.");
                    }
                }
                if cfg.subdomains_raw {
                    print(crtsh_raw);
                }
            }
        } else if !cfg.json {
            print(cfg.domain, " subdomain lookup failed");
        }
    }

    if cfg.json {
        var out: u8[>..] = [];
        out.append("{\"domain\":\"");
        json_writer::escape(cfg.domain, out);
        out.append("\",\"ip\":");
        if dns_ok {
            out.push('"');
            json_writer::escape(ip, out);
            out.push('"');
        } else {
            out.append("null");
        }

        out.append(",\"rdap\":");
        if rdap_ok {
            let sep = find_from(rdap_summary, 0, " | Registered: ");
            let prefix = "Registrar: ";
            var reg_start: i64 = 0;
            if find_from(rdap_summary, 0, prefix) == 0 {
                reg_start = prefix.len;
            }
            let reg_end = if sep >= 0 { sep } else { rdap_summary.len };
            let date_start = if sep >= 0 { sep + " | Registered: ".len } else { rdap_summary.len };

            out.append("{\"registrar\":\"");
            if reg_start <= reg_end {
                json_writer::escape(rdap_summary[reg_start..reg_end], out);
            }
            out.append("\",\"registered\":\"");
            if date_start <= rdap_summary.len {
                json_writer::escape(rdap_summary[date_start..rdap_summary.len], out);
            }
            out.append("\"}");
        } else {
            out.append("null");
        }

        out.append(",\"subdomains\":");
        if name_count > 0 {
            out.push('[');
            var start: i64 = 0;
            var first = true;
            var i: i64 = 0;
            while i <= names.len {
                if i == names.len || names[i] == '\n' {
                    if i > start {
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        out.push('"');
                        json_writer::escape(names[start..i], out);
                        out.push('"');
                    }
                    start = i + 1;
                }
                i++;
            }
            out.push(']');
        } else {
            out.append("null");
        }
        out.push('}');
        print(out);
    }
}
