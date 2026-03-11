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
python3 pfa.py topology pf.conf.sample
python3 pfa.py rules    pf.conf.sample [--interface ext] [--action pass|block] [--expanded]
python3 pfa.py tables   pf.conf.sample [--name tablename]
python3 pfa.py nat      pf.conf.sample
python3 pfa.py trace    pf.conf.sample --src IP --dst IP --proto tcp|udp|icmp \
                        [--sport PORT] [--dport PORT] [--iface IFACE] [--dir in|out] \
                        [--suggest-fix]
python3 pfa.py pcap     pf.conf.sample pf_blocked.pcap [--verbose]
python3 pfa.py pcap     pf.conf.sample robin_broken_ipv6_tunnel.pcap [--verbose]
python3 pfa.py analyze  pf_blocked.pcap [--top N] [--scan-threshold N] \
                        [--sweep-threshold N] [--flood-pps N]
```

`pfa.py` is the recommended entry point; `python3 -m pf_analyzer` also works.

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
| `pcap.py` | Multi-DLT pcap parser; `PflogPacket` + `GenericPacket` dataclasses; `read_pflog_pcap()` + `read_pcap()`; stdlib `struct` only |
| `analyze.py` | Aggregate stats (`AnalysisReport`) + anomaly detectors (`Anomaly`); `analyze_packets()`, `format_report()` |
| `cli.py` | `argparse` CLI, seven subcommands (topology/rules/tables/nat/trace/pcap/analyze) |

### pcap.py — multi-DLT support

`read_pcap(path) -> (list[GenericPacket], link_type)` accepts any of:

| DLT | Value | Parsing strategy |
|-----|-------|-----------------|
| DLT_NULL / DLT_LOOP | 0 / 12 | 4-byte host-order AF field → IPv4/IPv6 |
| DLT_EN10MB | 1 | 14-byte Ethernet header; strips 802.1Q VLAN tags |
| DLT_RAW / DLT_IPV4 | 101 / 228 | First nibble selects IPv4 or IPv6 |
| DLT_PFLOG | 117 | pflog frame → all PFLOG fields + IP |

`GenericPacket` fields: `pkt_num`, `ts_sec/usec`, `pkt_len`, `cap_len`, `ip_version`, `src_ip`, `dst_ip`, `proto_num/name`, `sport`, `dport`, `tcp_flags` (raw byte, TCP only), PFLOG-only: `pflog_action/name`, `ifname`, `direction`, `rule_num`. `parse_error` is set on decode failure.

`read_pflog_pcap()` is retained for backward compatibility (returns `list[PflogPacket]`).

### PFLOG pcap format notes

- Global pcap header: 24 bytes, magic `0xa1b2c3d4` (LE) or `0xd4c3b2a1` (BE), link type 117
- Per-packet record: 16-byte pcap header + pflog frame
- PFLOG frame layout: `[0]` hdr_len, `[1]` af, `[2]` action, `[3]` reason, `[4:20]` ifname, `[20:36]` ruleset, `[36:40]` rulenr (big-endian), `[60]` direction
- **IP payload alignment**: IP header starts at `(hdr_len + 3) & ~3` (next 4-byte boundary), not at `hdr_len` directly — FreeBSD pflog pads to 4-byte alignment
- `af` values: 2=IPv4, 28/30=IPv6 (FreeBSD/macOS), 10=IPv6 (Linux)
- Action values: 0=pass, 1=block, 2=scrub, 4=nat, 6=binat, 8=rdr

### analyze.py — anomaly detectors

All detectors are pure functions `(packets: list[GenericPacket], threshold) -> list[Anomaly]`:

| Detector | Category | Default threshold |
|----------|----------|------------------|
| `detect_port_scans` | `PORT_SCAN` | ≥10 distinct dst ports per src→dst pair |
| `detect_syn_scans` | `SYN_SCAN` | ≥5 SYN-only (SYN=1,ACK=0) ports per src→dst |
| `detect_host_sweeps` | `HOST_SWEEP` | ≥5 distinct dst hosts per src+dport |
| `detect_floods` | `FLOOD` | ≥100 pps in any 1-second bucket per src |
| `detect_suspicious_ports` | `SUSP_PORT` | any traffic on `SUSPICIOUS_PORTS` dict |
| `detect_icmp_anomalies` | `ICMP_FLOOD` / `ICMP_SWEEP` | ≥20 pps or ≥5 distinct hosts |
| `detect_unencrypted_sensitive` | `CLEARTEXT` | any traffic on Telnet/FTP/POP3/IMAP/TFTP/Syslog |

TCP flags byte bits: FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20

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
- pcap verdict mismatches vs pflog action are expected when config differs from the one used during capture
