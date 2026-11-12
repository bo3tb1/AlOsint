# AlOsint

Lightweight OSINT tool for domain and IP intelligence.

AlOsint is a command-line tool that gathers public information about domains, subdomains, email addresses, and IP networks. It performs DNS lookups, queries RDAP registration records, searches Certificate Transparency logs through crt.sh, and can optionally route HTTP requests through a local Tor SOCKS5 proxy. Results can be printed for humans or emitted as JSON for scripts.

## Features

- DNS A-record lookup
- RDAP domain registration summaries
- RDAP IP network summaries
- Subdomain discovery via crt.sh
- Email search via crt.sh
- Unified JSON output
- Tor support through a local SOCKS5 proxy
- File output, quiet mode, verbose diagnostics, and version reporting

## Installation

### Prerequisites

- Goose compiler
- `gcc` (or another supported C compiler)
- `libcurl` development headers

On Debian/Ubuntu, the native dependencies can be installed with:

```sh
sudo apt install gcc libcurl4-openssl-dev
```

### Build and install with make

From the repository root:

```sh
make
sudo make install
```

`make` builds `./alosint`, and `sudo make install` copies it to `/usr/local/bin/alosint`. Use `make test` to run the Goose compiler check, and `make clean` to remove the binary and object files.

If `goose` is not in your `PATH`, pass its location explicitly:

```sh
make GOOSE=/path/to/goose
```

### Fallback installer (without make)

If `make` is unavailable, use the included installer. It checks for `goose` and `gcc`, builds the binary, and installs it to `/usr/local/bin` when permitted (using `sudo` if needed). Otherwise, it installs to `$HOME/.local/bin`:

```sh
./install.sh
```

If AlOsint is installed under `$HOME/.local/bin`, ensure that directory is in your `PATH`.

## Usage

### DNS lookup

```sh
./alosint -d example.com
```

### RDAP domain lookup

```sh
./alosint -d example.com --rdap
```

### Subdomain discovery

```sh
./alosint -d example.com --subdomains
```

### JSON output

```sh
./alosint -d example.com --json
```

### Email search

```sh
./alosint --email user@example.com
```

### IP lookup

```sh
./alosint --ip 8.8.8.8
```

### Additional options

```sh
./alosint --version              # print the version
./alosint -d example.com --verbose
./alosint -d example.com --tor
./alosint -d example.com --json --output results.json
./alosint -d example.com --quiet
```

- `--json` emits a single JSON object.
- `--verbose` writes `[verbose]` diagnostics to stderr without changing stdout.
- `--quiet` suppresses human-readable output.
- `--output <file>` writes results to a file instead of stdout.
- `--tor` routes HTTP(S) requests through a SOCKS5 proxy at `127.0.0.1:9050`.
- `--version` prints `alosint <version>` and exits.

Run `./alosint --help` for the full option list.

## Legal Disclaimer

AlOsint is intended for educational purposes and authorized security testing only. Use it only on systems and data you own or are explicitly authorized to assess. Unauthorized scanning, data collection, or privacy violations may be unlawful. See [LEGAL.md](LEGAL.md) for the full disclaimer.

## License

AlOsint is released under the [MIT License](LICENSE).
