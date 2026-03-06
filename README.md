Purpose of this project is to create an easy summary and visualization for pf.conf PF rules on FreeBSD.

An example `pf.conf` is included along with a full offline copy of the FreeBSD man pages under `./freebsd_man_pages/`.

## pf_analyzer

A pure-Python (stdlib only, 3.10+) tool that parses any `pf.conf` and provides:

- **Topology view** — ASCII network diagram showing interfaces, zones, subnets, NAT/RDR mappings
- **Rule listing** — filterable table of filter rules with full macro expansion
- **Table inspection** — inline addresses and file-backed table definitions
- **NAT/RDR summary** — all translation rules in one place
- **Packet tracer** — simulate PF rule evaluation for a specific packet, rule by rule

### Usage

```sh
# Network topology diagram
python3 -m pf_analyzer topology pf.conf

# All filter rules (expanded after macro substitution)
python3 -m pf_analyzer rules pf.conf

# Filter rules for a specific interface (macro name or interface name)
python3 -m pf_analyzer rules pf.conf --interface ext
python3 -m pf_analyzer rules pf.conf --interface ue1

# Only block rules, with raw expanded text
python3 -m pf_analyzer rules pf.conf --action block --expanded

# Table definitions and their addresses
python3 -m pf_analyzer tables pf.conf
python3 -m pf_analyzer tables pf.conf --name quickblock

# NAT and RDR mappings
python3 -m pf_analyzer nat pf.conf

# Trace a packet through the ruleset
python3 -m pf_analyzer trace pf.conf \
    --src 1.2.3.4 --dst 5.6.7.8 \
    --proto tcp --dport 80 \
    --iface ue1 --dir in
```

### Trace examples

```sh
# TCP port 80 inbound on external interface (expect: PASS, line 175)
python3 -m pf_analyzer trace pf.conf \
    --src 1.2.3.4 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in

# Source IP in <quickblock> table (expect: BLOCK quick, line 98)
python3 -m pf_analyzer trace pf.conf \
    --src 168.95.245.1 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in

# Bot-net DNS to gateway (expect: PASS quick, line 133)
python3 -m pf_analyzer trace pf.conf \
    --src 192.168.10.5 --dst 192.168.10.1 --proto tcp --dport 53 --iface wlan0 --dir in

# Inbound ICMP (expect: PASS quick on icmp-type {3,4,11}, line 188)
python3 -m pf_analyzer trace pf.conf \
    --src 1.2.3.4 --dst 5.6.7.8 --proto icmp --iface ue1 --dir in
```

### Trace subcommand options

| Flag | Required | Description |
|------|----------|-------------|
| `--src IP` | yes | Source IP address |
| `--dst IP` | yes | Destination IP address |
| `--proto` | yes | Protocol: `tcp`, `udp`, `icmp`, `icmp6` |
| `--dport N` | — | Destination port |
| `--sport N` | — | Source port |
| `--iface NAME` | — | Interface name (e.g. `ue1`) |
| `--dir in\|out` | — | Packet direction (default: `in`) |
| `--icmp-type N` | — | ICMP type number (omit to wildcard-match) |

### Known limitations

- `($ext)` / `($ext:0)` NAT targets: actual IP is runtime-dependent; shown symbolically
- `file "/etc/tarpit"` table contents: unknown at analysis time; flagged in output
- `rdr-anchor "rdr/*"`: dynamically-loaded sub-rulesets are not analyzed
- Hostname macros are not DNS-resolved in offline mode

---

Documentation links for PF on FreeBSD:

- [FreeBSD Handbook — Firewalls](https://docs.freebsd.org/en/books/handbook/firewalls/)
- [FreeBSD Foundation — An Introduction to Packet Filter (PF)](https://freebsdfoundation.org/resource/an-introduction-to-packet-filter-pf/)

Full copy of FreeBSD Manual Pages, with each file compressed with gz, is stored in `./freebsd_man_pages/`.
