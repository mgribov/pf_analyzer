Purpose of this project is to create an easy summary and visualization for FreeBSD PF firewall rules.

An example `pf.conf.sample` is included along with a sample packet capture `pf_blocked.pcap` and a full offline copy of the FreeBSD man pages under `./freebsd_man_pages/`.

## pf_analyzer

A pure-Python (stdlib only, 3.10+) tool that parses any `pf.conf` and provides:

- **Topology view** — ASCII network diagram showing interfaces, zones, subnets, NAT/RDR mappings
- **Rule listing** — filterable table of filter rules with full macro expansion
- **Table inspection** — inline addresses and file-backed table definitions
- **NAT/RDR summary** — all translation rules in one place
- **Packet tracer** — simulate PF rule evaluation for a specific packet, rule by rule
- **PCAP analysis** — read a PFLOG capture, trace every packet through the ruleset, and generate rule suggestions

### Usage

```sh
# Network topology diagram
python3 pfa.py topology pf.conf.sample

# All filter rules (expanded after macro substitution)
python3 pfa.py rules pf.conf.sample

# Filter rules for a specific interface (macro name or interface name)
python3 pfa.py rules pf.conf.sample --interface ext
python3 pfa.py rules pf.conf.sample --interface ue1

# Only block rules, with raw expanded text
python3 pfa.py rules pf.conf.sample --action block --expanded

# Table definitions and their addresses
python3 pfa.py tables pf.conf.sample
python3 pfa.py tables pf.conf.sample --name quickblock

# NAT and RDR mappings
python3 pfa.py nat pf.conf.sample

# Trace a packet through the ruleset
python3 pfa.py trace pf.conf.sample \
    --src 1.2.3.4 --dst 5.6.7.8 \
    --proto tcp --dport 80 \
    --iface ue1 --dir in

# Analyze a PFLOG pcap capture
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap --verbose
```

The `pfa.py` wrapper is the recommended entry point. The package can also be invoked directly:

```sh
python3 -m pf_analyzer <subcommand> ...
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `topology` | ASCII network topology diagram |
| `rules` | Filterable table of filter rules |
| `tables` | Table definitions and their addresses |
| `nat` | NAT and RDR translation rules |
| `trace` | Simulate PF rule evaluation for a single packet |
| `pcap` | Trace all packets in a PFLOG pcap capture |

Run `python3 pfa.py help <subcommand>` for full options and examples.

### Trace examples

```sh
# TCP port 80 inbound on external interface (expect: PASS, line 175)
python3 pfa.py trace pf.conf.sample \
    --src 1.2.3.4 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in

# Source IP in <quickblock> table (expect: BLOCK quick, line 98)
python3 pfa.py trace pf.conf.sample \
    --src 168.95.245.1 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in

# Bot-net DNS to gateway (expect: PASS quick, line 133)
python3 pfa.py trace pf.conf.sample \
    --src 192.168.10.5 --dst 192.168.10.1 --proto tcp --dport 53 --iface wlan0 --dir in

# Inbound ICMP (expect: PASS quick on icmp-type {3,4,11}, line 188)
python3 pfa.py trace pf.conf.sample \
    --src 1.2.3.4 --dst 5.6.7.8 --proto icmp --iface ue1 --dir in

# Suggest the rule needed to flip the verdict
python3 pfa.py trace pf.conf.sample \
    --src 168.95.245.1 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in \
    --suggest-fix
```

### Trace subcommand options

| Flag | Required | Description |
|------|----------|-------------|
| `--src IP` | yes | Source IP address |
| `--dst IP` | yes | Destination IP address |
| `--proto` | yes | Protocol: `tcp`, `udp`, `icmp`, `icmp6`, `gre`, `esp` |
| `--dport N` | — | Destination port |
| `--sport N` | — | Source port |
| `--iface NAME` | — | Interface name (e.g. `ue1`) |
| `--dir in\|out` | — | Packet direction (default: `in`) |
| `--icmp-type N` | — | ICMP type number (omit to wildcard-match) |
| `--suggest-fix` | — | Print a minimal rule to achieve the opposite verdict |

### PCAP subcommand

Reads a PFLOG-format capture file (link type 117, as produced by `pflogd` on FreeBSD) and traces each packet through the loaded ruleset.

```sh
# Summary: one block per packet with verdict and rule suggestions
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap

# Verbose: full rule-by-rule trace per packet
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap --verbose

# Count verdicts across all captured packets
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap | grep Verdict
```

Output format per packet:

```
Pkt N: IPv4/TCP 1.2.3.4:1234 -> 5.6.7.8:443 on re1 [in] (pflog: BLOCK, rule 0)
  Verdict : BLOCK (line 26: block log on re1)
  To ALLOW: pass in quick on re1 inet proto tcp from 1.2.3.4/32 port 1234 to 5.6.7.8/32 port 443 flags S/SA modulate state
  To BLOCK: block in quick on re1 inet proto tcp from 1.2.3.4/32 port 1234 to 5.6.7.8/32 port 443
  (To PASS: insert before line 26)
---
```

To capture PFLOG traffic on a live FreeBSD system:

```sh
# Add 'log' to a filter rule in pf.conf, e.g.:
block in log quick on $ext_if

# Capture with tcpdump (pflog0 is the pflogd interface):
tcpdump -i pflog0 -w /tmp/blocked.pcap
```

**Note on verdict mismatches:** The `pcap` subcommand traces packets against the config file you supply, which may differ from the config active when the capture was taken. A packet recorded as BLOCK in the capture may show PASS against a different config — this is expected and useful for auditing rule changes.

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
