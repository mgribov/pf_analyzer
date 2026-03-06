#!/usr/bin/env python3
"""
pfa.py — CLI wrapper for pf_analyzer.

Delegates all execution to the pf_analyzer package; adds comprehensive
per-subcommand help and a 'help' meta-subcommand.

Usage:
    pfa.py <subcommand> <config> [options]
    pfa.py help [subcommand]
"""

from __future__ import annotations

import os
import sys
import textwrap

# ---------------------------------------------------------------------------
# Help text — one entry per subcommand plus an overview
# ---------------------------------------------------------------------------

_OVERVIEW = """\
pfa.py — FreeBSD pf.conf parser, visualizer, and packet tracer
===============================================================

USAGE
    pfa.py <subcommand> <config.conf> [options]
    pfa.py help [subcommand]

SUBCOMMANDS
    topology    Render an ASCII network topology diagram
    rules       List filter rules as a filterable table
    tables      Show table definitions and their addresses
    nat         Show NAT and RDR translation rules
    trace       Simulate PF rule evaluation for a specific packet

QUICK START
    pfa.py topology  pf.conf
    pfa.py rules     pf.conf --interface ext
    pfa.py nat       pf.conf
    pfa.py tables    pf.conf --name quickblock
    pfa.py trace     pf.conf --src 1.2.3.4 --dst 5.6.7.8 \\
                              --proto tcp --dport 80 --iface ue1 --dir in

Run 'pfa.py help <subcommand>' for full options and examples.
"""

_HELP: dict[str, str] = {}

# ---------------------------------------------------------------------------

_HELP["topology"] = """\
SUBCOMMAND: topology
====================

USAGE
    pfa.py topology <config>

DESCRIPTION
    Renders an ASCII network topology diagram that shows:

      - All interfaces referenced in the ruleset, grouped into zones
        discovered from macro naming conventions (e.g. ext → INTERNET,
        int → JAIL ZONE, bot → BOT NET, tun → TUNNEL/VPN)
      - Child interfaces inferred from macro names (e.g. int_jail_nextcloud
        is drawn as a child of the 'int' zone)
      - Subnets associated with each zone via *_net macros
      - NAT and RDR translation targets shown inside the firewall block
      - Blocking policy summary: block-policy, table list, default-deny ifaces

    The diagram is purely informational and read-only; pf.conf is never
    modified.

ARGUMENTS
    config      Path to a pf.conf file (required)

OPTIONS
    (none beyond config)

OUTPUT SECTIONS
    1. ASCII box diagram with zones and interfaces
    2. Blocking policy summary (tables, default-deny stances)
    3. Rule count totals (pass / block)

EXAMPLES
    # Show topology for the bundled example config
    pfa.py topology pf.conf

    # Show topology for the live system config (read-only)
    pfa.py topology /etc/pf.conf

    # Pipe through less for large configs
    pfa.py topology /etc/pf.conf | less
"""

# ---------------------------------------------------------------------------

_HELP["rules"] = """\
SUBCOMMAND: rules
=================

USAGE
    pfa.py rules <config> [--interface IFACE] [--action pass|block]
                          [--expanded]

DESCRIPTION
    Prints all filter rules (pass/block) as a tabular summary after full
    macro expansion.  Each row shows: sequential index, source line number,
    action, direction, quick flag, interface, address family, protocol,
    source address, destination address, port constraints, and a formatted
    rule string.

    By default the Rule column shows a normalized rule text built from the
    parsed model.  With --expanded it shows the raw text as it appeared
    after macro substitution (i.e. exactly what PF would evaluate).

ARGUMENTS
    config          Path to a pf.conf file (required)

OPTIONS
    --interface, -i IFACE
        Show only rules whose interface matches IFACE.  Accepts either the
        macro name (e.g. 'ext') or the expanded interface name (e.g. 'ue1').
        Rules with no interface constraint (all interfaces) are hidden when
        this filter is active.

    --action, -a pass|block
        Show only pass rules or only block rules.

    --expanded
        Show the raw expanded rule text instead of the normalized form.
        Useful for diffing against pfctl -sr output.

EXAMPLES
    # All rules — full table
    pfa.py rules pf.conf

    # Rules for the external interface (by macro name)
    pfa.py rules pf.conf --interface ext

    # Same, using the actual interface name
    pfa.py rules pf.conf --interface ue1

    # Only pass rules on the bot-net wifi interface
    pfa.py rules pf.conf --interface bot --action pass

    # Only block rules, raw expanded text
    pfa.py rules pf.conf --action block --expanded

    # Rules for the jail-zone bridge
    pfa.py rules pf.conf --interface int

    # Pipe through grep to find rules touching a specific port
    pfa.py rules pf.conf --interface ext --expanded | grep 'port 443'
"""

# ---------------------------------------------------------------------------

_HELP["tables"] = """\
SUBCOMMAND: tables
==================

USAGE
    pfa.py tables <config> [--name NAME]

DESCRIPTION
    Displays all table definitions found in the config.  For each table:

      - Name, flags (persist / const / counters), and source line number
      - All inline addresses (CIDRs or single IPs)
      - File paths referenced with the 'file' keyword (contents are not
        available in offline mode; this is noted in the output)

    Tables are used by PF to group addresses for efficient membership
    testing in filter, NAT, and RDR rules.  Common uses include blocklists
    (<quickblock>, <tarpit>) and dynamic jail address sets (<jails>).

ARGUMENTS
    config          Path to a pf.conf file (required)

OPTIONS
    --name, -n NAME
        Show only the table named NAME (without angle brackets).

EXAMPLES
    # List all tables with their addresses
    pfa.py tables pf.conf

    # Show only the quickblock table
    pfa.py tables pf.conf --name quickblock

    # Show the jails table (populated dynamically at runtime by Bastille)
    pfa.py tables pf.conf --name jails

    # Show the tarpit table (file-backed; contents unknown offline)
    pfa.py tables pf.conf --name tarpit

NOTES
    Tables declared with 'persist file "/path/to/file"' have no inline
    addresses — their contents are loaded from disk at PF load time.  The
    tracer treats file-backed tables as empty (0 inline addresses), so a
    packet from a file-backed blocked address will appear to pass that
    table check during offline tracing.
"""

# ---------------------------------------------------------------------------

_HELP["nat"] = """\
SUBCOMMAND: nat
===============

USAGE
    pfa.py nat <config>

DESCRIPTION
    Displays all NAT, RDR (redirect), and anchor rules found in the config.

    NAT (Network Address Translation)
        Rewrites source addresses on outbound traffic.  Typically used to
        masquerade internal hosts behind the external interface IP.
        Syntax: nat on <iface> from <src> to <dst> -> <target>

    RDR (Redirect)
        Rewrites destination address/port on inbound traffic.  Used to
        forward incoming connections to internal hosts.
        Syntax: rdr on <iface> proto <p> from <src> to <dst> -> <target>

    Anchors
        Named sub-ruleset attachment points.  rdr-anchor rules delegate
        to dynamically-loaded rulesets (e.g. per-jail redirect rules
        managed by Bastille's 'rdr/*' anchor).

    Output is grouped: NAT rules table, then RDR rules table, then anchors.

ARGUMENTS
    config          Path to a pf.conf file (required)

OPTIONS
    (none beyond config)

COLUMNS (NAT table)
    Line      Source line in pf.conf
    Iface     Interface the rule applies on
    AF        Address family: inet / inet6 / any
    Src       Source address filter (what traffic is NATted)
    Dst       Destination address filter
    Redirect  Translation target — ($iface) means the runtime IP of that
              interface; ($iface:0) means its first assigned address

COLUMNS (RDR table)
    Line      Source line in pf.conf
    Iface     Interface the rule applies on
    AF        Address family
    Proto     Matched protocol(s)
    Src       Source address filter
    Dst       Destination address matched (before redirect)
    Redirect  New destination address after redirect

EXAMPLES
    # Show all NAT, RDR, and anchor rules
    pfa.py nat pf.conf

    # Use with the live system config
    pfa.py nat /etc/pf.conf
"""

# ---------------------------------------------------------------------------

_HELP["trace"] = """\
SUBCOMMAND: trace
=================

USAGE
    pfa.py trace <config>
                 --src IP --dst IP --proto PROTO
                 [--sport PORT] [--dport PORT]
                 [--iface IFACE] [--dir in|out]
                 [--icmp-type N]

DESCRIPTION
    Simulates PF processing a single packet through the loaded ruleset and
    shows the result of every rule evaluation, step by step.

    Evaluation order follows PF semantics:
      1. RDR rules (inbound) — may rewrite destination before filter
      2. Filter rules (pass/block) — evaluated in order:
           - 'quick' rules: first match terminates evaluation immediately
           - non-quick rules: last match wins (later rules override earlier)
      3. NAT rules (outbound, applied after a PASS verdict)

    The final VERDICT line shows PASS or BLOCK, the winning rule, its line
    number, and state tracking mode (keep / modulate / synproxy state).

    Unspecified packet fields (omitting --sport, --dport, --icmp-type) act
    as wildcards and match any rule that filters on those fields.

ARGUMENTS
    config          Path to a pf.conf file (required)

REQUIRED OPTIONS
    --src IP        Source IP address of the simulated packet
    --dst IP        Destination IP address of the simulated packet
    --proto PROTO   Protocol: tcp, udp, icmp, icmp6, gre, esp

OPTIONAL OPTIONS
    --sport PORT    Source port number (omit to wildcard-match)
    --dport PORT    Destination port number (omit to wildcard-match)
    --iface IFACE   Interface name the packet arrives/leaves on (e.g. ue1).
                    Omit to match rules on all interfaces.
    --dir in|out    Packet direction relative to the firewall (default: in)
    --icmp-type N   ICMP type number (e.g. 8 for echo request, 3 for
                    unreachable).  Omit to wildcard-match all ICMP rules.

ICMP TYPE REFERENCE
    0   Echo Reply          8   Echo Request
    3   Destination Unreach 11  Time Exceeded
    4   Source Quench       30  Traceroute
    5   Redirect            13  Timestamp Request

EXAMPLES
    # Inbound TCP port 80 on external interface
    # Expected: PASS (line 175 — pass in quick on ue1 inet proto tcp ... port 80)
    pfa.py trace pf.conf \\
        --src 1.2.3.4 --dst 5.6.7.8 \\
        --proto tcp --dport 80 \\
        --iface ue1 --dir in

    # Source IP listed in <quickblock> table
    # Expected: BLOCK quick (line 98 — block quick on ue1 from <quickblock>)
    pfa.py trace pf.conf \\
        --src 168.95.245.1 --dst 5.6.7.8 \\
        --proto tcp --dport 80 \\
        --iface ue1 --dir in

    # Bot-net client querying its local DNS gateway on port 53
    # Expected: PASS quick (line 133 — pass in quick on wlan0 ... proto tcp ... port 53)
    pfa.py trace pf.conf \\
        --src 192.168.10.5 --dst 192.168.10.1 \\
        --proto tcp --dport 53 \\
        --iface wlan0 --dir in

    # Bot-net client trying to reach an arbitrary external host (not DNS)
    # Expected: BLOCK (falls through to default-deny on wlan0)
    pfa.py trace pf.conf \\
        --src 192.168.10.5 --dst 8.8.8.8 \\
        --proto tcp --dport 443 \\
        --iface wlan0 --dir in

    # Inbound ICMP (wildcard type — matches icmp-type {3,4,11} rule)
    # Expected: PASS quick (line 188)
    pfa.py trace pf.conf \\
        --src 1.2.3.4 --dst 5.6.7.8 \\
        --proto icmp \\
        --iface ue1 --dir in

    # Inbound ICMP echo request (type 8) — NOT in {3,4,11} rule
    # Expected: BLOCK (default-deny on ue1, no pass rule matches type 8 inbound)
    pfa.py trace pf.conf \\
        --src 1.2.3.4 --dst 5.6.7.8 \\
        --proto icmp --icmp-type 8 \\
        --iface ue1 --dir in

    # Outbound TCP from any source on ext — should be allowed
    # Expected: PASS quick (line 181 — pass out quick on ue1 inet proto tcp)
    pfa.py trace pf.conf \\
        --src 192.168.0.10 --dst 93.184.216.34 \\
        --proto tcp --dport 443 \\
        --iface ue1 --dir out

    # IPv6 tunnel packet from robin1 tunnelbroker
    # Expected: PASS quick (line 127)
    pfa.py trace pf.conf \\
        --src 2001:db8::1 --dst 2001:db8::2 \\
        --proto tcp --dport 22 \\
        --iface ue1 --dir in

    # WireGuard UDP port 51000 inbound
    # Expected: PASS quick (line 173)
    pfa.py trace pf.conf \\
        --src 203.0.113.7 --dst 5.6.7.8 \\
        --proto udp --dport 51000 \\
        --iface ue1 --dir in

    # Jail outbound HTTP — passes through jail-zone interface
    # Expected: PASS quick (line 165 — pass in quick on re0 ... from jail nets ... port 80)
    pfa.py trace pf.conf \\
        --src 192.168.4.10 --dst 203.0.113.1 \\
        --proto tcp --dport 80 \\
        --iface re0 --dir in

NOTES
    - Table membership for file-backed tables (e.g. <tarpit>) cannot be
      determined offline; those tables are treated as empty during tracing.
    - Interface self-references like ($ext) or ($ext:0) cannot be resolved
      to a specific IP offline; they are treated as matching any address.
    - For non-quick rules the trace shows all evaluations; the final verdict
      reflects the last matching rule, not the first.
"""

# ---------------------------------------------------------------------------
# Help display
# ---------------------------------------------------------------------------

def _print_help(cmd: str | None) -> None:
    if cmd is None:
        print(_OVERVIEW)
        print("Run 'pfa.py help <subcommand>' for details on a specific command.")
    elif cmd in _HELP:
        print(_HELP[cmd])
    else:
        print(f"Unknown subcommand: {cmd!r}", file=sys.stderr)
        print(f"Available: {', '.join(_HELP)}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]

    # No arguments — show overview
    if not args:
        _print_help(None)
        sys.exit(0)

    first = args[0].lower()

    # Global help flags
    if first in ("-h", "--help"):
        _print_help(None)
        sys.exit(0)

    # 'help' meta-subcommand
    if first == "help":
        cmd = args[1].lower() if len(args) > 1 else None
        _print_help(cmd)
        sys.exit(0)

    # Per-subcommand help shortcut: pfa.py topology --help
    if first in _HELP and len(args) >= 2 and args[1] in ("-h", "--help"):
        _print_help(first)
        sys.exit(0)

    # Delegate to pf_analyzer.cli for actual execution
    try:
        from pf_analyzer.cli import main as pfa_main
    except ImportError as exc:
        print(
            f"Error: could not import pf_analyzer package.\n"
            f"Make sure this script is run from the repository root.\n"
            f"Details: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    pfa_main(args)


if __name__ == "__main__":
    main()
