Purpose of this project is to create an easy summary and visualization for FreeBSD PF firewall rules.

An example `pf.conf.sample` is included along with sample packet captures (`pf_blocked.pcap`, `pf_blocked-big.pcap`, `robin_broken_ipv6_tunnel.pcap`) and a full offline copy of the FreeBSD man pages under `./freebsd_man_pages/`.

## pf_analyzer

A pure-Python (stdlib only, 3.10+) tool that parses any `pf.conf` and provides:

- **Topology view** — ASCII network diagram showing interfaces, zones, subnets, NAT/RDR mappings
- **Rule listing** — filterable table of filter rules with full macro expansion
- **Table inspection** — inline addresses and file-backed table definitions
- **NAT/RDR summary** — all translation rules in one place
- **Packet tracer** — simulate PF rule evaluation for a specific packet, rule by rule
- **PCAP trace** — read any tcpdump PCAP (Ethernet, PFLOG, raw IP, loopback), trace every packet through the ruleset, and generate rule suggestions
- **PCAP analyze** — aggregate stats (top IPs, ports, conversations) and anomaly detection (port scans, floods, suspicious ports, cleartext protocols) on any capture — no `pf.conf` needed

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

# Trace packets from any pcap against a ruleset
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap
python3 pfa.py pcap pf.conf.sample robin_broken_ipv6_tunnel.pcap --verbose

# Aggregate analysis and anomaly detection (no pf.conf required)
python3 pfa.py analyze pf_blocked.pcap
python3 pfa.py analyze pf_blocked-big.pcap --top 5
```

The `pfa.py` wrapper is the recommended entry point. The package can also be invoked directly:

```sh
python3 -m pf_analyzer <subcommand> ...
```

### Subcommands

| Subcommand | pf.conf? | Description |
|------------|----------|-------------|
| `topology` | required | ASCII network topology diagram |
| `rules`    | required | Filterable table of filter rules |
| `tables`   | required | Table definitions and their addresses |
| `nat`      | required | NAT and RDR translation rules |
| `trace`    | required | Simulate PF rule evaluation for a single packet |
| `pcap`     | required | Trace all packets in a pcap capture against the ruleset |
| `analyze`  | **none** | Aggregate stats + anomaly detection on any pcap |

Run `python3 pfa.py help <subcommand>` for full options and examples.

### Trace examples

```sh
# TCP port 80 inbound on external interface
python3 pfa.py trace pf.conf.sample \
    --src 1.2.3.4 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in

# Source IP in <quickblock> table
python3 pfa.py trace pf.conf.sample \
    --src 168.95.245.1 --dst 5.6.7.8 --proto tcp --dport 80 --iface ue1 --dir in

# Bot-net DNS to gateway
python3 pfa.py trace pf.conf.sample \
    --src 192.168.10.5 --dst 192.168.10.1 --proto tcp --dport 53 --iface wlan0 --dir in

# Inbound ICMP
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

Reads any supported tcpdump PCAP and traces each packet through the loaded ruleset.

**Supported link types:**

| DLT | Value | Description |
|-----|-------|-------------|
| DLT_NULL | 0 | BSD loopback |
| DLT_EN10MB | 1 | Ethernet (handles 802.1Q VLAN tags) |
| DLT_LOOP | 12 | BSD loopback |
| DLT_RAW | 101 | Raw IP (IPv4 or IPv6) |
| DLT_PFLOG | 117 | FreeBSD pflog — also shows pflog action, interface, direction |
| DLT_IPV4 | 228 | Raw IPv4 |

```sh
# Summary: one block per packet with verdict and rule suggestions
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap

# Verbose: full rule-by-rule trace per packet
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap --verbose

# Works with any link type — Ethernet, raw IP, etc.
python3 pfa.py pcap pf.conf.sample robin_broken_ipv6_tunnel.pcap

# Count verdicts across all captured packets
python3 pfa.py pcap pf.conf.sample pf_blocked.pcap | grep Verdict
```

Output format per packet (PFLOG capture):

```
Pkt N: IPv4/TCP 1.2.3.4:1234 -> 5.6.7.8:443 on re1 [in] (pflog: BLOCK, rule 0)
  Verdict : BLOCK (line 26: block log on re1)
  To ALLOW: pass in quick on re1 inet proto tcp from 1.2.3.4/32 port 1234 to 5.6.7.8/32 port 443 flags S/SA modulate state
  To BLOCK: block in quick on re1 inet proto tcp from 1.2.3.4/32 port 1234 to 5.6.7.8/32 port 443
  (To PASS: insert before line 26)
---
```

For non-PFLOG captures the `on <iface> [dir]` and `(pflog: ...)` fields are omitted; interface and direction default to `in` for rule suggestions.

To capture PFLOG traffic on a live FreeBSD system:

```sh
# Add 'log' to a filter rule in pf.conf, e.g.:
block in log quick on $ext_if

# Capture with tcpdump (pflog0 is the pflogd interface):
tcpdump -i pflog0 -w /tmp/blocked.pcap
```

**Note on verdict mismatches:** The `pcap` subcommand traces packets against the config file you supply, which may differ from the config active when the capture was taken. A packet recorded as BLOCK in the capture may show PASS against a different config — this is expected and useful for auditing rule changes.

### Analyze subcommand

Reads any supported PCAP and produces an aggregate statistics report with anomaly detection. Does **not** require a `pf.conf`.

```sh
# Full report
python3 pfa.py analyze pf_blocked.pcap

# Show only top 5 entries per table
python3 pfa.py analyze pf_blocked-big.pcap --top 5

# Lower thresholds for stealthy-scan detection
python3 pfa.py analyze capture.pcap --scan-threshold 5 --sweep-threshold 3

# Detect lower-volume floods
python3 pfa.py analyze capture.pcap --flood-pps 20
```

Report sections:
- **Capture metadata** — file, link type, duration, packet count, IP version split, packet size stats
- **Protocol breakdown** — packet count per protocol
- **Top source / destination IPs**
- **Top destination ports** — with well-known service names
- **Top conversations** — (src → dst on port)
- **PFLOG actions / interfaces / directions** — shown only for PFLOG captures
- **Anomalies** — sorted HIGH → MED → LOW

Anomaly detectors:

| Category | Severity | Triggers when |
|----------|----------|---------------|
| `PORT_SCAN` | HIGH | 1 src → ≥N distinct ports on same dst host |
| `SYN_SCAN` | HIGH | SYN-only packets to ≥N ports per src→dst |
| `HOST_SWEEP` | MED | 1 src → same port on ≥N distinct hosts |
| `FLOOD` | HIGH | Any src sends > `--flood-pps` pkts in one second |
| `SUSP_PORT` | HIGH | Traffic on known-bad ports (Metasploit, Back Orifice, IRC C2, …) |
| `ICMP_FLOOD` | MED | ICMP rate > 20 pps from a single source |
| `ICMP_SWEEP` | MED | ICMP to ≥5 distinct hosts from one source |
| `CLEARTEXT` | MED | Traffic on Telnet(23), FTP(21), POP3(110), IMAP(143), TFTP(69), Syslog(514) |

Analyze subcommand options:

| Flag | Default | Description |
|------|---------|-------------|
| `--top N` | 10 | Entries to show per table |
| `--scan-threshold N` | 10 | Distinct ports to flag as port scan |
| `--sweep-threshold N` | 5 | Distinct hosts to flag as host sweep |
| `--flood-pps N` | 100 | Packets/sec threshold for flood detection |

### Known limitations

- `($ext)` / `($ext:0)` NAT targets: actual IP is runtime-dependent; shown symbolically
- `file "/etc/tarpit"` table contents: unknown at analysis time; flagged in output
- `rdr-anchor "rdr/*"`: dynamically-loaded sub-rulesets are not analyzed
- Hostname macros are not DNS-resolved in offline mode
- IPv6 extension headers beyond the first are not parsed by the PCAP decoder

---

Documentation links for PF on FreeBSD:

- [FreeBSD Handbook — Firewalls](https://docs.freebsd.org/en/books/handbook/firewalls/)
- [FreeBSD Foundation — An Introduction to Packet Filter (PF)](https://freebsdfoundation.org/resource/an-introduction-to-packet-filter-pf/)

Full copy of FreeBSD Manual Pages, with each file compressed with gz, is stored in `./freebsd_man_pages/`.
