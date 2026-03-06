# CLAUDE.md

## Project Purpose

This repository contains tooling to parse, summarize, and visualize FreeBSD `pf.conf` firewall rule files. The goal is to make complex PF configurations human-readable at a glance — showing rule intent, table membership, NAT mappings, and per-interface policy.

**Status:** Implemented. The `pf_analyzer/` package provides a working CLI. See the `pf_analyzer/` directory and `README.md` for usage.

## Documentation

### Web References

- [FreeBSD Handbook — Firewalls](https://docs.freebsd.org/en/books/handbook/firewalls/)
- [FreeBSD Foundation — An Introduction to Packet Filter (PF)](https://freebsdfoundation.org/resource/an-introduction-to-packet-filter-pf/)

### Local Man Pages

Full FreeBSD man pages are stored in `./freebsd_man_pages/`, with each file gzipped (`.gz`).

Key PF-related pages:

| Page | Path |
|------|------|
| `pf.conf(5)` | `freebsd_man_pages/man5/pf.conf.5.gz` |
| `pf.os(5)` | `freebsd_man_pages/man5/pf.os.5.gz` |
| `pfctl(8)` | `freebsd_man_pages/man8/pfctl.8.gz` |
| `pflogd(8)` | `freebsd_man_pages/man8/pflogd.8.gz` |
| `pfilctl(8)` | `freebsd_man_pages/man8/pfilctl.8.gz` |
| `pflowctl(8)` | `freebsd_man_pages/man8/pflowctl.8.gz` |

To read a man page locally:

```sh
zcat freebsd_man_pages/man5/pf.conf.5.gz | man -l -
# or simply:
zcat freebsd_man_pages/man8/pfctl.8.gz | less
```

## PF Validation Commands (FreeBSD)

```sh
# Syntax-check a config file without loading it
pfctl -n -f /etc/pf.conf

# Load rules (requires root)
pfctl -f /etc/pf.conf

# Show currently loaded rules
pfctl -sr

# Show NAT rules
pfctl -sn

# Show tables
pfctl -sT

# Show table contents
pfctl -t <tablename> -T show

# Enable/disable PF
pfctl -e   # enable
pfctl -d   # disable
```

## pf.conf Architecture

The example `pf.conf` follows the standard PF rule ordering:

1. **Macros** — named variables for interfaces, networks, and IP addresses (e.g., `ext_if`, `jail_net`, `dns_servers`)
2. **Tables** — dynamic IP sets: `<jails>`, `<tarpit>`, `<quickblock>`
3. **Options** — global settings (`set skip`, `set block-policy`, etc.)
4. **Scrub** — packet normalization rules
5. **NAT / RDR** — network address translation and port redirection for jails
6. **Anchors** — sub-ruleset hooks (e.g., for `pf-osfp`, per-jail anchors)
7. **Block defaults** — default-deny stances applied early
8. **Per-interface pass rules** — stateful pass rules organized by interface/zone (loopback, external, jail network)
9. **ICMP rules** — explicit pass rules for required ICMP types

## pf_analyzer Package

The `pf_analyzer/` package is a pure-Python (stdlib only, 3.10+) implementation.

### Running

```sh
python3 -m pf_analyzer topology pf.conf
python3 -m pf_analyzer rules   pf.conf [--interface ext] [--action pass|block] [--expanded]
python3 -m pf_analyzer tables  pf.conf [--name tablename]
python3 -m pf_analyzer nat     pf.conf
python3 -m pf_analyzer trace   pf.conf --src IP --dst IP --proto tcp|udp|icmp \
                                [--sport PORT] [--dport PORT] [--iface IFACE] [--dir in|out]
```

### Module layout

| Module | Responsibility |
|--------|---------------|
| `lexer.py` | Strip comments, join continuations, tokenize (handles `->`, `><`, `<>`, `<table>`, `($iface)`) |
| `parser.py` | Two-pass: collect macros, then parse rules; `TokenStream` for safe token consumption |
| `model.py` | All dataclasses (`FilterRule`, `NatRule`, `RdrRule`, `Table`, …) + enums |
| `matcher.py` | `ip_in_network`, `ip_in_table`, `port_matches`, `address_matches` via stdlib `ipaddress` |
| `tracer.py` | PF packet-evaluation semantics: RDR → filter (quick=stop, non-quick=last-wins) → NAT |
| `topology.py` | Zone/interface discovery by macro-naming conventions; ASCII box-drawing output |
| `formatter.py` | `make_table()`, `format_filter_rule()`, rule/table summaries |
| `cli.py` | `argparse` CLI, five subcommands |

### Parser notes

- **Macro expansion**: two-pass; macros must be defined before use (PF rule)
- **`->`** tokenized as a single token (critical for NAT/RDR redirect targets)
- **Brace lists** `{ a, b }` in address/port positions are stored as multi-value specs, not expanded into separate rules (exception: multi-proto `proto { tcp udp }` expands into separate `FilterRule` objects)
- **Unspecified packet fields** in `trace` (e.g., no `--icmp-type`) are treated as wildcards that match any rule filter

### Development Notes

- All tooling treats `pf.conf` as read-only input; never modify the source config
- Rule ordering is semantically significant in PF — the parser preserves insertion order
- `($iface)` and `($iface:0)` NAT targets are stored symbolically; actual IP is runtime-dependent
- File-backed tables (`persist file "/etc/tarpit"`) have no inline addresses; the tracer notes this
