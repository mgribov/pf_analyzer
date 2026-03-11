"""CLI entry point — 5 subcommands."""

from __future__ import annotations

import argparse
import sys

from .errors import PfAnalyzerError, TraceError
from .formatter import (
    format_filter_rule, format_nat_rule, format_rdr_rule,
    make_table, rules_summary, tables_summary,
)
from .model import Action, AddressFamily, Direction, ParsedConfig
from .parser import parse_file
from .topology import render_topology
from .tracer import TracePacket, format_trace, suggest_counter_rule, trace
from .pcap import read_pflog_pcap, read_pcap


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pf_analyzer",
        description="Parse, visualize, and trace FreeBSD pf.conf files.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # --- topology ---
    p_topo = sub.add_parser("topology", help="Render ASCII network topology.")
    p_topo.add_argument("config", help="Path to pf.conf")

    # --- rules ---
    p_rules = sub.add_parser("rules", help="List filter rules.")
    p_rules.add_argument("config", help="Path to pf.conf")
    p_rules.add_argument("--interface", "-i", metavar="IFACE",
                         help="Filter by interface macro or name")
    p_rules.add_argument("--action", "-a", choices=["pass", "block"],
                         help="Filter by action")
    p_rules.add_argument("--expanded", action="store_true",
                         help="Show expanded (post-macro) rule text")

    # --- tables ---
    p_tables = sub.add_parser("tables", help="List table definitions.")
    p_tables.add_argument("config", help="Path to pf.conf")
    p_tables.add_argument("--name", "-n", metavar="NAME",
                          help="Show only this table")

    # --- nat ---
    p_nat = sub.add_parser("nat", help="Show NAT/RDR mappings.")
    p_nat.add_argument("config", help="Path to pf.conf")

    # --- pcap ---
    p_pcap = sub.add_parser("pcap", help="Trace packets from a PFLOG pcap file.")
    p_pcap.add_argument("config", help="Path to pf.conf")
    p_pcap.add_argument("pcap", help="Path to PFLOG .pcap file (link type 117)")
    p_pcap.add_argument("--verbose", "-v", action="store_true",
                        help="Print full trace output for each packet")

    # --- trace ---
    p_trace = sub.add_parser("trace", help="Simulate packet processing.")
    p_trace.add_argument("config", help="Path to pf.conf")
    p_trace.add_argument("--src", required=True, metavar="IP",
                         help="Source IP address")
    p_trace.add_argument("--dst", required=True, metavar="IP",
                         help="Destination IP address")
    p_trace.add_argument("--proto", required=True,
                         choices=["tcp", "udp", "icmp", "icmp6", "gre", "esp"],
                         help="Protocol")
    p_trace.add_argument("--sport", type=int, metavar="PORT",
                         help="Source port")
    p_trace.add_argument("--dport", type=int, metavar="PORT",
                         help="Destination port")
    p_trace.add_argument("--iface", metavar="IFACE",
                         help="Incoming/outgoing interface name")
    p_trace.add_argument("--dir", choices=["in", "out"], default="in",
                         dest="direction", help="Packet direction (default: in)")
    p_trace.add_argument("--icmp-type", type=int, metavar="N",
                         help="ICMP type number")
    p_trace.add_argument("--suggest-fix", action="store_true",
                         help="Suggest a rule to achieve the opposite verdict")

    # --- analyze ---
    p_analyze = sub.add_parser(
        "analyze",
        help="Aggregate stats and anomaly detection on any pcap (no pf.conf required).",
    )
    p_analyze.add_argument("pcap", help="Path to any pcap file (Ethernet, PFLOG, raw, etc.)")
    p_analyze.add_argument("--top", type=int, default=10, metavar="N",
                           help="Number of top entries to show (default: 10)")
    p_analyze.add_argument("--scan-threshold", type=int, default=10, metavar="N",
                           dest="scan_threshold",
                           help="Distinct ports to flag as port scan (default: 10)")
    p_analyze.add_argument("--sweep-threshold", type=int, default=5, metavar="N",
                           dest="sweep_threshold",
                           help="Distinct hosts to flag as host sweep (default: 5)")
    p_analyze.add_argument("--flood-pps", type=int, default=100, metavar="N",
                           dest="flood_pps",
                           help="Packets/sec threshold for flood detection (default: 100)")

    args = parser.parse_args(argv)

    # analyze does not require a pf.conf — dispatch before config parsing
    if args.command == "analyze":
        cmd_analyze(args)
        return

    try:
        config = parse_file(args.config)
    except FileNotFoundError:
        print(f"Error: file not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    except PfAnalyzerError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.command == "topology":
        cmd_topology(config)
    elif args.command == "rules":
        cmd_rules(config, args)
    elif args.command == "tables":
        cmd_tables(config, args)
    elif args.command == "nat":
        cmd_nat(config)
    elif args.command == "trace":
        cmd_trace(config, args)
    elif args.command == "pcap":
        cmd_pcap(config, args)


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def cmd_topology(config: ParsedConfig) -> None:
    print(render_topology(config))
    print()
    print(rules_summary(config))


def cmd_rules(config: ParsedConfig, args: argparse.Namespace) -> None:
    rules = config.filter_rules

    # Resolve interface filter: match either macro name or expanded value
    iface_filter: str | None = None
    if args.interface:
        # Try to resolve macro name → interface
        macro = config.get_macro(args.interface)
        if macro:
            iface_filter = macro.expanded_value
        else:
            iface_filter = args.interface

    if iface_filter:
        rules = [r for r in rules if r.interface == iface_filter]
    if args.action:
        target_action = Action.PASS if args.action == "pass" else Action.BLOCK
        rules = [r for r in rules if r.action == target_action]

    if not rules:
        print("No matching rules.")
        return

    headers = ["#", "Line", "Action", "Dir", "Quick", "Iface", "AF",
               "Proto", "Src", "Dst", "Ports", "Rule"]
    rows: list[list[str]] = []
    for idx, r in enumerate(rules, start=1):
        src_str = str(r.src)
        dst_str = str(r.dst)
        port_str = ""
        if r.dst_port:
            port_str = f"dst:{r.dst_port.raw}"
        if r.src_port:
            port_str = (f"src:{r.src_port.raw} " + port_str).strip()

        rule_text = r.raw_text if args.expanded else format_filter_rule(r)

        rows.append([
            str(idx),
            str(r.line_num),
            r.action.value,
            r.direction.value,
            "Q" if r.quick else "",
            r.interface or "*",
            r.address_family.value,
            r.proto or "*",
            src_str,
            dst_str,
            port_str,
            rule_text,
        ])

    print(make_table(headers, rows))
    print(f"\nShowing {len(rules)} of {len(config.filter_rules)} total rules.")


def cmd_tables(config: ParsedConfig, args: argparse.Namespace) -> None:
    tables = config.tables
    if args.name:
        tables = [t for t in tables if t.name == args.name]

    if not tables:
        print("No matching tables.")
        return

    for t in tables:
        flags_str = " ".join(t.flags) or "(none)"
        print(f"Table: <{t.name}>")
        print(f"  Flags   : {flags_str}")
        print(f"  Line    : {t.line_num}")
        if t.addrs:
            print(f"  Addresses ({len(t.addrs)}):")
            for a in t.addrs:
                print(f"    {a}")
        else:
            print("  Addresses: (none inline)")
        if t.file_paths:
            print("  Files:")
            for fp in t.file_paths:
                print(f"    {fp}  (offline: contents unknown)")
        print()


def cmd_nat(config: ParsedConfig) -> None:
    if not config.nat_rules and not config.rdr_rules:
        print("No NAT or RDR rules found.")
        return

    if config.nat_rules:
        print("NAT Rules:")
        print("-" * 60)
        headers = ["Line", "Iface", "AF", "Src", "Dst", "Redirect"]
        rows: list[list[str]] = []
        for n in config.nat_rules:
            rows.append([
                str(n.line_num),
                n.interface or "*",
                n.address_family.value,
                str(n.src),
                str(n.dst),
                str(n.redirect_to),
            ])
        print(make_table(headers, rows))
        print()

    if config.rdr_rules:
        print("RDR Rules:")
        print("-" * 60)
        headers = ["Line", "Iface", "AF", "Proto", "Src", "Dst", "Redirect"]
        rows = []
        for r in config.rdr_rules:
            rows.append([
                str(r.line_num),
                r.interface or "*",
                r.address_family.value,
                "/".join(r.proto) if r.proto else "*",
                str(r.src),
                str(r.dst),
                str(r.redirect_to),
            ])
        print(make_table(headers, rows))
        print()

    if config.anchors:
        print("Anchors:")
        for a in config.anchors:
            print(f"  [{a.line_num:>4}] {a.anchor_type} {a.name}")


def cmd_pcap(config: ParsedConfig, args: argparse.Namespace) -> None:
    try:
        packets, _link_type = read_pcap(args.pcap)
    except (ValueError, OSError) as exc:
        print(f"Error reading pcap: {exc}", file=sys.stderr)
        sys.exit(1)

    good = []
    for pkt in packets:
        if pkt.parse_error:
            print(f"  [warning] pkt {pkt.pkt_num}: {pkt.parse_error}, skipping",
                  file=sys.stderr)
        else:
            good.append(pkt)

    if not good:
        print("No decodable packets found in pcap file.")
        return

    for pkt in good:
        # Header line — show IP version + transport proto + ports
        ip_ver = f"IPv{pkt.ip_version}"
        proto_label = f"{ip_ver}/{pkt.proto_name.upper()}"
        sport_str = f":{pkt.sport}" if pkt.sport is not None else ""
        dport_str = f":{pkt.dport}" if pkt.dport is not None else ""

        # Location info (only PFLOG packets carry ifname/direction)
        loc_parts: list[str] = []
        if pkt.ifname:
            loc_parts.append(f"on {pkt.ifname}")
        if pkt.direction:
            loc_parts.append(f"[{pkt.direction}]")
        loc_str = (" " + " ".join(loc_parts)) if loc_parts else ""

        # PFLOG verdict annotation
        if pkt.pflog_action_name is not None:
            pflog_str = f" (pflog: {pkt.pflog_action_name.upper()}, rule {pkt.rule_num})"
        else:
            pflog_str = ""

        print(
            f"Pkt {pkt.pkt_num}: {proto_label} "
            f"{pkt.src_ip}{sport_str} -> {pkt.dst_ip}{dport_str}"
            f"{loc_str}{pflog_str}"
        )

        # Build TracePacket — pass the real proto name; matcher handles unknowns correctly
        trace_pkt = TracePacket(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            proto=pkt.proto_name,
            src_port=pkt.sport,
            dst_port=pkt.dport,
            interface=pkt.ifname,
            direction=pkt.direction or "in",
        )

        result = trace(trace_pkt, config)

        verdict_word = result.final_action.value.upper()
        if result.final_rule:
            print(f"  Verdict : {verdict_word} (line {result.final_rule.line_num}: {result.final_rule.raw_text})")
        else:
            print(f"  Verdict : {verdict_word} (default policy)")

        if args.verbose:
            for line in format_trace(result).splitlines():
                print(f"    {line}")

        # Rule suggestions
        _print_pcap_suggestions(pkt, result)

        print("---")


def _print_pcap_suggestions(pkt, result) -> None:
    """Print To ALLOW and To BLOCK rule suggestions for a pcap packet."""
    import ipaddress

    try:
        src_obj = ipaddress.ip_address(pkt.src_ip)
        af = "inet" if src_obj.version == 4 else "inet6"
        src_prefix = "/32" if src_obj.version == 4 else "/128"
    except ValueError:
        af = "inet"
        src_prefix = "/32"

    try:
        dst_obj = ipaddress.ip_address(pkt.dst_ip)
        dst_prefix = "/32" if dst_obj.version == 4 else "/128"
    except ValueError:
        dst_prefix = "/32"

    proto = pkt.proto_name
    direction = pkt.direction or "in"

    def _build_rule(action: str) -> str:
        parts = [action, direction, "quick"]
        if pkt.ifname:
            parts += ["on", pkt.ifname]
        parts += [af, "proto", proto,
                  "from", f"{pkt.src_ip}{src_prefix}"]
        if pkt.sport is not None:
            parts += ["port", str(pkt.sport)]
        parts += ["to", f"{pkt.dst_ip}{dst_prefix}"]
        if pkt.dport is not None:
            parts += ["port", str(pkt.dport)]
        if action == "pass":
            if proto == "tcp":
                parts.append("flags S/SA modulate state")
            else:
                parts.append("keep state")
        return " ".join(parts)

    current_action = result.final_action.value  # "pass" or "block"
    opposite_action = "block" if current_action == "pass" else "pass"

    print(f"  To ALLOW: {_build_rule('pass')}")
    print(f"  To BLOCK: {_build_rule('block')}")

    # Insertion hint for the counter-rule (opposite of current verdict)
    if result.final_rule is not None:
        insert_line = result.final_rule.line_num
        print(f"  (To {opposite_action.upper()}: insert before line {insert_line})")


def cmd_analyze(args: argparse.Namespace) -> None:
    from .analyze import analyze_packets, format_report

    try:
        packets, link_type = read_pcap(args.pcap)
    except (ValueError, OSError) as exc:
        print(f"Error reading pcap: {exc}", file=sys.stderr)
        sys.exit(1)

    if not packets:
        print("No packets found in pcap file.")
        return

    report = analyze_packets(
        packets,
        pcap_path=args.pcap,
        link_type=link_type,
        top_n=args.top,
        scan_threshold=args.scan_threshold,
        sweep_threshold=args.sweep_threshold,
        flood_pps=args.flood_pps,
    )
    print(format_report(report, top_n=args.top))


def cmd_trace(config: ParsedConfig, args: argparse.Namespace) -> None:
    packet = TracePacket(
        src_ip=args.src,
        dst_ip=args.dst,
        proto=args.proto,
        src_port=args.sport,
        dst_port=args.dport,
        interface=args.iface,
        direction=args.direction,
        icmp_type=args.icmp_type,
    )

    result = trace(packet, config)
    print(format_trace(result))
    if args.suggest_fix:
        print(suggest_counter_rule(result))
