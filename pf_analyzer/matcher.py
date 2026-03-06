"""IP/port/protocol matching primitives."""

from __future__ import annotations

import ipaddress
from typing import Optional

from .model import (
    Action, AddressFamily, AddressSpec, Direction, FilterRule,
    ParsedConfig, PortSpec, RdrRule, Table,
)

# ICMP type name → number map (common subset)
ICMP_TYPES: dict[str, int] = {
    "echorep":   0,
    "unreach":   3,
    "squench":   4,
    "redir":     5,
    "echoreq":   8,
    "routeradv": 9,
    "routersol": 10,
    "timex":     11,
    "paramprob": 12,
    "timereq":   13,
    "timerep":   14,
    "inforeq":   15,
    "inforep":   16,
    "maskreq":   17,
    "maskrep":   18,
    # numeric aliases
    "0": 0, "3": 3, "4": 4, "5": 5, "8": 8,
    "9": 9, "10": 10, "11": 11, "12": 12,
    "13": 13, "14": 14, "30": 30,
}


def icmp_name_to_num(name: str) -> int | None:
    if name in ICMP_TYPES:
        return ICMP_TYPES[name]
    try:
        return int(name)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# IP matching
# ---------------------------------------------------------------------------

def ip_in_network(ip_str: str, network_str: str) -> bool:
    """Return True if ip_str falls within network_str (bare IP treated as /32)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if '/' in network_str:
            net = ipaddress.ip_network(network_str, strict=False)
        else:
            net = ipaddress.ip_network(network_str + '/32', strict=False)
        return ip in net
    except ValueError:
        return False


def ip_in_table(ip_str: str, table: Table) -> bool:
    """Return True if ip_str is in any of table.addrs."""
    for addr in table.addrs:
        if ip_in_network(ip_str, addr):
            return True
    return False


# ---------------------------------------------------------------------------
# Port matching
# ---------------------------------------------------------------------------

def port_matches(port: int | None, spec: PortSpec | None) -> bool:
    """Return True if port matches the port spec. None spec = any port."""
    if spec is None:
        return True
    if port is None:
        # Unspecified packet port — match anything (wildcard)
        return True
    for item in spec.specs:
        op = item[0]
        if op == '=':
            val = item[1]
            if isinstance(val, int):
                if port == val:
                    return True
            else:
                # named port we couldn't resolve — skip
                pass
        elif op == '>':
            if port > item[1]:
                return True
        elif op == '<':
            if port < item[1]:
                return True
        elif op == '>=':
            if port >= item[1]:
                return True
        elif op == '<=':
            if port <= item[1]:
                return True
        elif op == '><':
            low, high = item[1], item[2]
            if low < port < high:
                return True
        elif op == '<>':
            low, high = item[1], item[2]
            if low <= port <= high:
                return True
    return False


# ---------------------------------------------------------------------------
# Protocol matching
# ---------------------------------------------------------------------------

def proto_matches(pkt_proto: str | None, rule_proto: str | None) -> bool:
    """Return True if packet proto matches rule proto. None rule = any."""
    if rule_proto is None:
        return True
    if pkt_proto is None:
        return True  # unspecified packet matches any rule
    return pkt_proto.lower() == rule_proto.lower()


# ---------------------------------------------------------------------------
# Address matching
# ---------------------------------------------------------------------------

def address_matches(
    ip: str | None,
    spec: AddressSpec,
    config: ParsedConfig,
    iface_ips: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """
    Return (matched: bool, reason: str).

    iface_ips maps interface name → IP for resolving ($iface) self-refs.
    """
    if spec.is_any:
        result = True
        reason = "any"
    elif spec.table_name is not None:
        table = config.get_table(spec.table_name)
        if table is None:
            result = False
            reason = f"table <{spec.table_name}> not found"
        elif ip is None:
            result = True
            reason = f"unspecified IP (wildcard match) in <{spec.table_name}>"
        else:
            result = ip_in_table(ip, table)
            reason = f"{'in' if result else 'not in'} table <{spec.table_name}>"
    elif spec.interface_self is not None:
        # ($iface) — we don't know the actual IP at analysis time
        # Treat as "any" for tracing unless caller provides iface_ips
        if iface_ips and spec.interface_self in iface_ips:
            iface_ip = iface_ips[spec.interface_self]
            if ip is None:
                result = True
            else:
                result = ip_in_network(ip, iface_ip)
            reason = f"({'in' if result else 'not in'}) ({spec.interface_self}) = {iface_ip}"
        else:
            # Symbolic match — unknown at analysis time
            result = True
            reason = f"({spec.interface_self}) — runtime IP unknown, assumed match"
    elif spec.addrs:
        if ip is None:
            result = True
            reason = "unspecified IP (wildcard)"
        else:
            result = any(ip_in_network(ip, a) for a in spec.addrs)
            reason = f"{'in' if result else 'not in'} {', '.join(spec.addrs)}"
    else:
        result = True
        reason = "any (empty spec)"

    if spec.negated:
        result = not result
        reason = f"NOT ({reason})"

    return result, reason


# ---------------------------------------------------------------------------
# Interface matching
# ---------------------------------------------------------------------------

def interface_matches(pkt_iface: str | None, rule_iface: str | None) -> bool:
    """None rule_iface = all interfaces."""
    if rule_iface is None:
        return True
    if pkt_iface is None:
        return True
    return pkt_iface == rule_iface


# ---------------------------------------------------------------------------
# Direction matching
# ---------------------------------------------------------------------------

def direction_matches(pkt_dir: str | None, rule_dir: Direction) -> bool:
    if rule_dir == Direction.ANY:
        return True
    if pkt_dir is None:
        return True
    return pkt_dir.lower() == rule_dir.value


# ---------------------------------------------------------------------------
# Address-family matching
# ---------------------------------------------------------------------------

def af_matches(ip: str | None, rule_af: AddressFamily) -> bool:
    if rule_af == AddressFamily.ANY:
        return True
    if ip is None:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if rule_af == AddressFamily.INET:
            return addr.version == 4
        if rule_af == AddressFamily.INET6:
            return addr.version == 6
    except ValueError:
        pass
    return True


# ---------------------------------------------------------------------------
# ICMP type matching
# ---------------------------------------------------------------------------

def icmp_type_matches(pkt_icmp_type: int | None, rule_icmp_types: list[str]) -> bool:
    """Return True if packet icmp type matches rule icmp-type list."""
    if not rule_icmp_types:
        return True
    if pkt_icmp_type is None:
        return True  # unspecified → wildcard
    for name_or_num in rule_icmp_types:
        n = icmp_name_to_num(name_or_num)
        if n is not None and n == pkt_icmp_type:
            return True
    return False
