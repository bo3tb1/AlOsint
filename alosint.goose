import os;
import modules.crtsh;
import modules.dns;
import modules.rdap;

let HELP = """
    AlOsint 1.0.0 - passive OSINT for authorized targets

    Usage:
      alosint -d <domain> [--rdap] [--subdomains] [--json] [--tor]
      alosint -h | --help

    Options:
      -d, --domain <domain>  Target domain to investigate (required)
          --rdap             Retrieve RDAP registration summary
          --subdomains       Discover subdomains via Certificate Transparency (crt.sh)
          --json             Emit JSON output (reserved for a later step)
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
        } else {
            usage_error(str("unknown option: ", a));
        }
        i++;
    }
    if domain.len == 0 { usage_error("missing required -d/--domain"); }
    return Config { json: json, tor: tor, rdap: rdap, subdomains: subdomains, domain: domain };
}

fn main() {
    let cfg = parse_args();
    var ip: u8[>..] = [];
    if dns::lookup(cfg.domain, ip) {
        if cfg.json {
            print("{\"domain\":\"", cfg.domain, "\",\"ip\":\"", ip, "\"}");
        } else {
            print(cfg.domain, " resolves to: ", ip);
        }
    } else {
        print(cfg.domain, " could not be resolved");
    }
    if cfg.rdap {
        var rdap_data: u8[>..] = [];
        if rdap::lookup(cfg.domain, rdap_data) {
            var summary: u8[>..] = [];
            rdap::format_summary(rdap_data, summary);
            print("RDAP Summary for ", cfg.domain, ": ", summary);
        } else {
            print("RDAP Data for ", cfg.domain, " could not be retrieved");
        }
    }
    if cfg.subdomains {
        var crtsh_data: u8[>..] = [];
        if crtsh::lookup(cfg.domain, crtsh_data) {
            print(crtsh_data);
        } else {
            print(cfg.domain, " subdomain lookup failed");
        }
    }
}
