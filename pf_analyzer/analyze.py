"""Aggregate statistics and anomaly detection for any pcap capture."""

from __future__ import annotations

import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .pcap import GenericPacket, LINKTYPE_NAMES


# ---------------------------------------------------------------------------
# Port dictionaries
# ---------------------------------------------------------------------------

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP/sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 1433: "MSSQL", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
    51820: "WireGuard",
}

SUSPICIOUS_PORTS: dict[int, str] = {
    1080:  "SOCKS proxy",
    1337:  "elite / backdoor",
    4444:  "Metasploit default",
    4899:  "Radmin",
    5554:  "Sasser worm",
    5555:  "ADB / Android miner",
    6666:  "IRC",
    6667:  "IRC / botnet C2",
    6668:  "IRC",
    6669:  "IRC",
    8888:  "cryptominer alt",
    9090:  "C2 framework",
    9999:  "C2 / backdoor",
    12345: "NetBus",
    27374: "Sub7",
    31337: "Back Orifice",
    33434: "traceroute start",
    3333:  "cryptominer",
    65535: "port-scan artifact",
}

_CLEARTEXT_PORTS: dict[int, str] = {
    21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP",
    514: "Syslog (UDP)", 69: "TFTP",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    severity:    str   # "HIGH", "MED", "LOW"
    category:    str   # "PORT_SCAN", "SYN_SCAN", "HOST_SWEEP", etc.
    description: str   # human-readable sentence
    evidence:    str   # concise supporting data


@dataclass
class AnalysisReport:
    pcap_path:       str
    link_type:       int
    total_packets:   int
    parse_errors:    int
    duration_secs:   float
    first_ts:        float
    last_ts:         float
    ipv4_count:      int
    ipv6_count:      int
    proto_counts:    Counter
    src_ip_counts:   Counter
    dst_ip_counts:   Counter
    dst_port_counts: Counter
    src_port_counts: Counter
    conversations:   Counter       # (src_ip, dst_ip, proto_name, dport) → count
    pkt_sizes:       list[int]     # for avg/min/max computation
    # PFLOG-specific (populated only when is_pflog)
    is_pflog:         bool
    action_counts:    Counter
    interface_counts: Counter
    direction_counts: Counter
    # Anomalies (sorted HIGH→MED→LOW)
    anomalies:       list[Anomaly]


# ---------------------------------------------------------------------------
# Anomaly detectors
# ---------------------------------------------------------------------------

def detect_port_scans(packets: list[GenericPacket],
                      threshold: int = 10) -> list[Anomaly]:
    """1 source → N distinct dst ports on the same host."""
    port_map: dict[tuple[str, str], set[int]] = defaultdict(set)
    for p in packets:
        if p.dport is not None:
            port_map[(p.src_ip, p.dst_ip)].add(p.dport)

    anomalies = []
    for (src, dst), ports in port_map.items():
        if len(ports) >= threshold:
            sample = ", ".join(str(x) for x in sorted(ports)[:12])
            if len(ports) > 12:
                sample += "…"
            anomalies.append(Anomaly(
                severity="HIGH",
                category="PORT_SCAN",
                description=f"{src} probed {len(ports)} distinct ports on {dst}",
                evidence=f"ports: {sample}",
            ))
    return anomalies


def detect_host_sweeps(packets: list[GenericPacket],
                       threshold: int = 5) -> list[Anomaly]:
    """1 source → same port on N distinct destination hosts."""
    sweep_map: dict[tuple[str, int], set[str]] = defaultdict(set)
    for p in packets:
        if p.dport is not None:
            sweep_map[(p.src_ip, p.dport)].add(p.dst_ip)

    anomalies = []
    for (src, port), hosts in sweep_map.items():
        if len(hosts) >= threshold:
            svc = WELL_KNOWN_PORTS.get(port, "")
            svc_str = f" ({svc})" if svc else ""
            sample = ", ".join(sorted(hosts)[:6])
            if len(hosts) > 6:
                sample += "…"
            anomalies.append(Anomaly(
                severity="MED",
                category="HOST_SWEEP",
                description=f"{src} swept {len(hosts)} hosts on port {port}{svc_str}",
                evidence=f"hosts: {sample}",
            ))
    return anomalies


def detect_floods(packets: list[GenericPacket],
                  flood_pps: int = 100) -> list[Anomaly]:
    """Any source sending > flood_pps packets in a 1-second bucket."""
    buckets: dict[tuple[str, int], int] = defaultdict(int)
    for p in packets:
        buckets[(p.src_ip, p.ts_sec)] += 1

    seen: set[str] = set()
    anomalies = []
    for (src, sec), count in sorted(buckets.items(), key=lambda x: -x[1]):
        if count >= flood_pps and src not in seen:
            seen.add(src)
            anomalies.append(Anomaly(
                severity="HIGH",
                category="FLOOD",
                description=f"{src} sent {count} pps peak (threshold: {flood_pps})",
                evidence=f"worst second: {sec}",
            ))
    return anomalies


def detect_suspicious_ports(packets: list[GenericPacket]) -> list[Anomaly]:
    """Traffic to/from known suspicious ports."""
    seen: set[int] = set()
    anomalies = []
    for p in packets:
        for port in (p.sport, p.dport):
            if port is not None and port in SUSPICIOUS_PORTS and port not in seen:
                seen.add(port)
                desc = SUSPICIOUS_PORTS[port]
                anomalies.append(Anomaly(
                    severity="HIGH",
                    category="SUSP_PORT",
                    description=f"Traffic on port {port} ({desc})",
                    evidence=f"e.g. {p.src_ip} → {p.dst_ip}:{port}",
                ))
    return anomalies


def detect_icmp_anomalies(packets: list[GenericPacket],
                          flood_threshold: int = 20,
                          sweep_threshold: int = 5) -> list[Anomaly]:
    """ICMP flood (high pps) and ICMP ping sweep (many dest IPs)."""
    icmp = [p for p in packets if p.proto_name in ("icmp", "icmp6")]
    anomalies = []

    # Flood: bucket by (src, second)
    buckets: dict[tuple[str, int], int] = defaultdict(int)
    for p in icmp:
        buckets[(p.src_ip, p.ts_sec)] += 1
    seen: set[str] = set()
    for (src, sec), count in sorted(buckets.items(), key=lambda x: -x[1]):
        if count >= flood_threshold and src not in seen:
            seen.add(src)
            anomalies.append(Anomaly(
                severity="MED",
                category="ICMP_FLOOD",
                description=f"{src} sent {count} ICMP pps (threshold: {flood_threshold})",
                evidence=f"worst second: {sec}",
            ))

    # Sweep: 1 src → many distinct dst IPs
    dst_map: dict[str, set[str]] = defaultdict(set)
    for p in icmp:
        dst_map[p.src_ip].add(p.dst_ip)
    for src, dsts in dst_map.items():
        if len(dsts) >= sweep_threshold:
            sample = ", ".join(sorted(dsts)[:6])
            if len(dsts) > 6:
                sample += "…"
            anomalies.append(Anomaly(
                severity="MED",
                category="ICMP_SWEEP",
                description=f"{src} sent ICMP to {len(dsts)} distinct hosts",
                evidence=f"hosts: {sample}",
            ))
    return anomalies


def detect_syn_scans(packets: list[GenericPacket],
                     threshold: int = 5) -> list[Anomaly]:
    """SYN-only packets (SYN=1, ACK=0) to many ports per src→dst pair."""
    # TCP flags: SYN=0x02, ACK=0x10
    syn_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    for p in packets:
        if (p.tcp_flags is not None and p.dport is not None
                and (p.tcp_flags & 0x12) == 0x02):
            syn_ports[(p.src_ip, p.dst_ip)].add(p.dport)

    anomalies = []
    for (src, dst), ports in syn_ports.items():
        if len(ports) >= threshold:
            sample = ", ".join(str(x) for x in sorted(ports)[:12])
            if len(ports) > 12:
                sample += "…"
            anomalies.append(Anomaly(
                severity="HIGH",
                category="SYN_SCAN",
                description=f"{src} sent SYN-only to {len(ports)} ports on {dst}",
                evidence=f"ports: {sample}",
            ))
    return anomalies


def detect_unencrypted_sensitive(packets: list[GenericPacket]) -> list[Anomaly]:
    """Traffic to cleartext-protocol ports (Telnet, FTP, POP3, IMAP, TFTP)."""
    seen: set[int] = set()
    anomalies = []
    for p in packets:
        for port in (p.sport, p.dport):
            if port is not None and port in _CLEARTEXT_PORTS and port not in seen:
                seen.add(port)
                proto_label = _CLEARTEXT_PORTS[port]
                anomalies.append(Anomaly(
                    severity="MED",
                    category="CLEARTEXT",
                    description=f"Unencrypted {proto_label} traffic on port {port}",
                    evidence=f"e.g. {p.src_ip} → {p.dst_ip}:{port}",
                ))
    return anomalies


# ---------------------------------------------------------------------------
# Main aggregation entry point
# ---------------------------------------------------------------------------

_SEV_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2}


def analyze_packets(
    packets: list[GenericPacket],
    pcap_path: str = "",
    link_type: int = 0,
    top_n: int = 10,
    scan_threshold: int = 10,
    sweep_threshold: int = 5,
    flood_pps: int = 100,
) -> AnalysisReport:
    """Aggregate statistics and run anomaly detectors over *packets*."""
    good = [p for p in packets if not p.parse_error and p.src_ip]
    errors = sum(1 for p in packets if p.parse_error)

    if good:
        first_ts = min(p.ts_sec + p.ts_usec / 1e6 for p in good)
        last_ts  = max(p.ts_sec + p.ts_usec / 1e6 for p in good)
    else:
        first_ts = last_ts = 0.0

    duration = last_ts - first_ts

    proto_counts    = Counter(p.proto_name for p in good)
    src_ip_counts   = Counter(p.src_ip for p in good)
    dst_ip_counts   = Counter(p.dst_ip for p in good)
    dst_port_counts = Counter(p.dport for p in good if p.dport is not None)
    src_port_counts = Counter(p.sport for p in good if p.sport is not None)
    conversations   = Counter(
        (p.src_ip, p.dst_ip, p.proto_name, p.dport)
        for p in good if p.dport is not None
    )
    pkt_sizes = [p.pkt_len for p in good]

    ipv4_count = sum(1 for p in good if p.ip_version == 4)
    ipv6_count = sum(1 for p in good if p.ip_version == 6)

    is_pflog = any(p.pflog_action is not None for p in packets)
    if is_pflog:
        action_counts    = Counter(p.pflog_action_name for p in good if p.pflog_action_name)
        interface_counts = Counter(p.ifname for p in good if p.ifname)
        direction_counts = Counter(p.direction for p in good if p.direction)
    else:
        action_counts = interface_counts = direction_counts = Counter()

    anomalies: list[Anomaly] = []
    anomalies.extend(detect_port_scans(good, scan_threshold))
    anomalies.extend(detect_syn_scans(good, sweep_threshold))
    anomalies.extend(detect_host_sweeps(good, sweep_threshold))
    anomalies.extend(detect_floods(good, flood_pps))
    anomalies.extend(detect_suspicious_ports(good))
    anomalies.extend(detect_icmp_anomalies(good))
    anomalies.extend(detect_unencrypted_sensitive(good))
    anomalies.sort(key=lambda a: _SEV_ORDER.get(a.severity, 9))

    return AnalysisReport(
        pcap_path=pcap_path,
        link_type=link_type,
        total_packets=len(packets),
        parse_errors=errors,
        duration_secs=duration,
        first_ts=first_ts,
        last_ts=last_ts,
        ipv4_count=ipv4_count,
        ipv6_count=ipv6_count,
        proto_counts=proto_counts,
        src_ip_counts=src_ip_counts,
        dst_ip_counts=dst_ip_counts,
        dst_port_counts=dst_port_counts,
        src_port_counts=src_port_counts,
        conversations=conversations,
        pkt_sizes=pkt_sizes,
        is_pflog=is_pflog,
        action_counts=action_counts,
        interface_counts=interface_counts,
        direction_counts=direction_counts,
        anomalies=anomalies,
    )


# ---------------------------------------------------------------------------
# Report formatter
# ---------------------------------------------------------------------------

def _fmt_ts(ts: float) -> str:
    dt = datetime.datetime.utcfromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _pct(count: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{count / total * 100:.1f}%"


def format_report(report: AnalysisReport, top_n: int = 10) -> str:
    """Render a human-readable text report from an AnalysisReport."""
    # Import here to avoid circular imports
    from .formatter import make_table

    lines: list[str] = []

    # ── Header box ──────────────────────────────────────────────────────────
    title  = "PCAP ANALYSIS REPORT"
    width  = 62
    inner  = width - 2
    lines.append("╔" + "═" * inner + "╗")
    lines.append("║" + title.center(inner) + "║")
    lines.append("╚" + "═" * inner + "╝")
    lines.append("")

    # ── File / capture info ──────────────────────────────────────────────────
    link_label = LINKTYPE_NAMES.get(report.link_type, f"link type {report.link_type}")
    lines.append(f"File       : {report.pcap_path}  ({link_label})")

    if report.duration_secs > 0 and report.first_ts > 0:
        t1 = _fmt_ts(report.first_ts)
        t2 = _fmt_ts(report.last_ts)
        lines.append(f"Duration   : {report.duration_secs:.1f} s  ({t1} → {t2})")

    decoded = report.total_packets - report.parse_errors
    lines.append(
        f"Packets    : {report.total_packets:,} total  "
        f"({decoded:,} decoded, {report.parse_errors:,} errors)"
    )
    lines.append(f"IP versions: IPv4: {report.ipv4_count:,}  IPv6: {report.ipv6_count:,}")

    if report.pkt_sizes:
        avg_sz = sum(report.pkt_sizes) / len(report.pkt_sizes)
        lines.append(
            f"Pkt size   : min={min(report.pkt_sizes)}  "
            f"avg={avg_sz:.0f}  max={max(report.pkt_sizes)} bytes"
        )
    lines.append("")

    total = report.total_packets or 1

    # ── Protocol breakdown ───────────────────────────────────────────────────
    if report.proto_counts:
        lines.append("PROTOCOL BREAKDOWN")
        rows = [
            [proto, f"{cnt:,}", _pct(cnt, total)]
            for proto, cnt in report.proto_counts.most_common()
        ]
        lines.append(make_table(["Protocol", "Count", "%"], rows))
        lines.append("")

    # ── Top source IPs ───────────────────────────────────────────────────────
    if report.src_ip_counts:
        lines.append(f"TOP SOURCE IPs  (top {top_n})")
        rows = [
            [ip, f"{cnt:,}", _pct(cnt, total)]
            for ip, cnt in report.src_ip_counts.most_common(top_n)
        ]
        lines.append(make_table(["Source IP", "Pkts", "%"], rows))
        lines.append("")

    # ── Top destination IPs ──────────────────────────────────────────────────
    if report.dst_ip_counts:
        lines.append(f"TOP DESTINATION IPs  (top {top_n})")
        rows = [
            [ip, f"{cnt:,}", _pct(cnt, total)]
            for ip, cnt in report.dst_ip_counts.most_common(top_n)
        ]
        lines.append(make_table(["Destination IP", "Pkts", "%"], rows))
        lines.append("")

    # ── Top destination ports ────────────────────────────────────────────────
    if report.dst_port_counts:
        lines.append(f"TOP DESTINATION PORTS  (top {top_n})")
        rows = [
            [str(port), WELL_KNOWN_PORTS.get(port, ""), f"{cnt:,}", _pct(cnt, total)]
            for port, cnt in report.dst_port_counts.most_common(top_n)
        ]
        lines.append(make_table(["Port", "Service", "Pkts", "%"], rows))
        lines.append("")

    # ── Top conversations ────────────────────────────────────────────────────
    if report.conversations:
        lines.append(f"TOP CONVERSATIONS  (top {top_n})")
        rows = []
        for (src, dst, proto, dport), cnt in report.conversations.most_common(top_n):
            svc = WELL_KNOWN_PORTS.get(dport, "") if dport is not None else ""
            rows.append([src, dst, proto, str(dport) if dport is not None else "*",
                         svc, f"{cnt:,}"])
        lines.append(make_table(
            ["Source", "Destination", "Proto", "Port", "Service", "Pkts"], rows
        ))
        lines.append("")

    # ── PFLOG-specific ───────────────────────────────────────────────────────
    if report.is_pflog:
        if report.action_counts:
            lines.append("PFLOG ACTIONS")
            rows = [
                [action, f"{cnt:,}", _pct(cnt, total)]
                for action, cnt in report.action_counts.most_common()
            ]
            lines.append(make_table(["Action", "Count", "%"], rows))
            lines.append("")

        if report.interface_counts:
            lines.append("PFLOG INTERFACES")
            rows = [
                [iface, f"{cnt:,}", _pct(cnt, total)]
                for iface, cnt in report.interface_counts.most_common()
            ]
            lines.append(make_table(["Interface", "Count", "%"], rows))
            lines.append("")

        if report.direction_counts:
            lines.append("PFLOG DIRECTIONS")
            rows = [
                [direction, f"{cnt:,}", _pct(cnt, total)]
                for direction, cnt in report.direction_counts.most_common()
            ]
            lines.append(make_table(["Direction", "Count", "%"], rows))
            lines.append("")

    # ── Anomalies ────────────────────────────────────────────────────────────
    if report.anomalies:
        lines.append(f"ANOMALIES DETECTED  ({len(report.anomalies)} found)")
        rows = [
            [a.severity, a.category, a.description, a.evidence]
            for a in report.anomalies
        ]
        lines.append(make_table(["Sev", "Category", "Description", "Evidence"], rows))
    else:
        lines.append("ANOMALIES: none detected")

    return "\n".join(lines)
