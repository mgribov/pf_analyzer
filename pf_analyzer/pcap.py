"""PFLOG pcap parser — reads link-type 117 captures (stdlib only)."""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LINKTYPE_PFLOG = 117

PCAP_GLOBAL_MAGIC_LE = 0xa1b2c3d4
PCAP_GLOBAL_MAGIC_BE = 0xd4c3b2a1

# pflog address families
_AF_INET  = 2
_AF_INET6_BSD = 28   # FreeBSD AF_INET6
_AF_INET6_LNX = 10   # Linux AF_INET6 (seen in some captures)
_AF_INET6_OSX = 30   # macOS AF_INET6

# pflog actions
_PFLOG_ACTION_PASS  = 0
_PFLOG_ACTION_BLOCK = 1
_ACTION_NAMES = {0: "pass", 1: "block", 2: "scrub", 3: "no-scrub",
                 4: "nat", 5: "no-nat", 6: "binat", 7: "no-binat",
                 8: "rdr", 9: "no-rdr"}

# pflog directions
_DIR_INOUT = 0
_DIR_IN    = 1
_DIR_OUT   = 2

PROTO_NAMES: dict[int, str] = {
    1: "icmp", 6: "tcp", 17: "udp",
    47: "gre", 50: "esp", 58: "icmp6",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PflogPacket:
    pkt_num: int
    ts_sec: int
    ts_usec: int
    pflog_action: int        # raw pflog action code (0=pass, 1=block, …)
    pflog_action_name: str   # "pass", "block", etc.
    ifname: str
    direction: str           # "in" or "out"
    ip_version: int          # 4 or 6
    src_ip: str
    dst_ip: str
    proto_num: int
    proto_name: str          # "tcp", "udp", "icmp", … or "proto{N}"
    sport: Optional[int]
    dport: Optional[int]
    rule_num: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_ip4(data: bytes, off: int) -> tuple[str, int, int]:
    """Return (src_ip, dst_ip, proto, sport, dport) from an IPv4 header at offset."""
    if len(data) < off + 20:
        raise ValueError("IPv4 header truncated")
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    src = ".".join(str(b) for b in data[off + 12: off + 16])
    dst = ".".join(str(b) for b in data[off + 16: off + 20])
    sport, dport = _parse_l4_ports(data, off + ihl, proto)
    return src, dst, proto, sport, dport


def _parse_ip6(data: bytes, off: int) -> tuple[str, str, int, Optional[int], Optional[int]]:
    """Return (src_ip, dst_ip, proto, sport, dport) from an IPv6 header at offset."""
    if len(data) < off + 40:
        raise ValueError("IPv6 header truncated")
    next_hdr = data[off + 6]
    src_bytes = data[off + 8: off + 24]
    dst_bytes = data[off + 24: off + 40]
    src = _fmt_ipv6(src_bytes)
    dst = _fmt_ipv6(dst_bytes)
    sport, dport = _parse_l4_ports(data, off + 40, next_hdr)
    return src, dst, next_hdr, sport, dport


def _fmt_ipv6(raw: bytes) -> str:
    import ipaddress
    return str(ipaddress.IPv6Address(raw))


def _parse_l4_ports(data: bytes, off: int,
                    proto: int) -> tuple[Optional[int], Optional[int]]:
    if proto in (6, 17):  # TCP or UDP
        if len(data) < off + 4:
            return None, None
        sport = struct.unpack_from("!H", data, off)[0]
        dport = struct.unpack_from("!H", data, off + 2)[0]
        return sport, dport
    return None, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_pflog_pcap(path: str) -> list[PflogPacket]:
    """Parse a PFLOG pcap file and return a list of PflogPacket objects.

    Raises ValueError if the file is not a valid pcap or has the wrong link type.
    Prints a warning to stderr and skips packets that cannot be parsed.
    """
    with open(path, "rb") as fh:
        raw = fh.read()

    if len(raw) < 24:
        raise ValueError(f"{path}: file too small to be a valid pcap")

    # Global header: magic(4) ver_maj(2) ver_min(2) thiszone(4) sigfigs(4)
    #                snaplen(4) network(4)
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic == PCAP_GLOBAL_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_GLOBAL_MAGIC_BE:
        endian = ">"
    else:
        raise ValueError(f"{path}: not a pcap file (bad magic 0x{magic:08x})")

    link_type = struct.unpack_from(endian + "I", raw, 20)[0]
    if link_type != LINKTYPE_PFLOG:
        raise ValueError(
            f"{path}: expected PFLOG link type (117), got {link_type}"
        )

    packets: list[PflogPacket] = []
    offset = 24  # skip global header
    pkt_num = 0

    while offset < len(raw):
        # Per-packet record header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        if len(raw) - offset < 16:
            break
        ts_sec, ts_usec, incl_len, _ = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        pkt_num += 1

        if len(raw) - offset < incl_len:
            print(f"  [warning] pkt {pkt_num}: truncated packet data, skipping",
                  file=sys.stderr)
            offset += incl_len
            continue

        pkt_data = raw[offset: offset + incl_len]
        offset += incl_len

        try:
            pkt = _parse_pflog_packet(pkt_num, ts_sec, ts_usec, pkt_data)
            packets.append(pkt)
        except Exception as exc:  # noqa: BLE001
            print(f"  [warning] pkt {pkt_num}: {exc}, skipping", file=sys.stderr)

    return packets


def _parse_pflog_packet(pkt_num: int, ts_sec: int, ts_usec: int,
                        data: bytes) -> PflogPacket:
    """Parse one PFLOG frame from raw bytes."""
    if len(data) < 1:
        raise ValueError("empty packet")

    hdr_len = data[0]
    if len(data) < hdr_len:
        raise ValueError(f"pflog header claims {hdr_len} bytes but only {len(data)} available")

    af        = data[1]
    action    = data[2]
    # reason  = data[3]  (not needed)
    ifname    = data[4:20].rstrip(b"\x00").decode("ascii", errors="replace")
    # ruleset = data[20:36] (not needed)
    rule_num  = struct.unpack_from(">I", data, 36)[0]
    direction_byte = data[60]

    direction = "out" if direction_byte == _DIR_OUT else "in"
    action_name = _ACTION_NAMES.get(action, f"action{action}")

    # IP payload starts at the next 4-byte-aligned offset after hdr_len.
    # The pflog length field gives the raw header byte count, but the
    # payload is padded to a 4-byte boundary (FreeBSD pflog behaviour).
    ip_off = (hdr_len + 3) & ~3
    ip_data = data

    if af == _AF_INET:
        ip_version = 4
        src, dst, proto_num, sport, dport = _parse_ip4(ip_data, ip_off)
    elif af in (_AF_INET6_BSD, _AF_INET6_LNX, _AF_INET6_OSX):
        ip_version = 6
        src, dst, proto_num, sport, dport = _parse_ip6(ip_data, ip_off)
    else:
        raise ValueError(f"unsupported address family {af}")

    proto_name = PROTO_NAMES.get(proto_num, f"proto{proto_num}")

    return PflogPacket(
        pkt_num=pkt_num,
        ts_sec=ts_sec,
        ts_usec=ts_usec,
        pflog_action=action,
        pflog_action_name=action_name,
        ifname=ifname,
        direction=direction,
        ip_version=ip_version,
        src_ip=src,
        dst_ip=dst,
        proto_num=proto_num,
        proto_name=proto_name,
        sport=sport,
        dport=dport,
        rule_num=rule_num,
    )


# ---------------------------------------------------------------------------
# Generic multi-DLT support
# ---------------------------------------------------------------------------

# Supported link-layer types
LINKTYPE_NULL     = 0    # DLT_NULL — BSD loopback (4-byte AF header)
LINKTYPE_ETHERNET = 1    # DLT_EN10MB
LINKTYPE_LOOP     = 12   # DLT_LOOP — BSD loopback (same as NULL, big-endian AF)
LINKTYPE_RAW      = 101  # DLT_RAW — raw IP (version in first nibble)
LINKTYPE_IPV4     = 228  # DLT_IPV4 — raw IPv4

LINKTYPE_NAMES: dict[int, str] = {
    0: "NULL/Loopback",
    1: "Ethernet",
    12: "BSD Loopback",
    101: "Raw IP",
    117: "PFLOG",
    228: "Raw IPv4",
}


@dataclass
class GenericPacket:
    """Unified packet representation for any supported link type."""
    pkt_num:   int
    ts_sec:    int
    ts_usec:   int
    pkt_len:   int           # original (on-wire) length
    cap_len:   int           # captured length
    # IP-level fields (empty/0 when parse_error is set)
    ip_version: int          = 0   # 4 or 6
    src_ip:    str           = ""
    dst_ip:    str           = ""
    proto_num: int           = 0
    proto_name: str          = ""  # "tcp", "udp", "icmp", ... or "proto{N}"
    # L4 fields
    sport:     Optional[int] = None
    dport:     Optional[int] = None
    tcp_flags: Optional[int] = None  # raw flags byte; None for non-TCP
    # PFLOG-only fields (None for other link types)
    pflog_action:      Optional[int] = None
    pflog_action_name: Optional[str] = None
    ifname:    Optional[str] = None
    direction: Optional[str] = None
    rule_num:  Optional[int] = None
    # Error field
    parse_error: Optional[str] = None


# ---------------------------------------------------------------------------
# Generic L4 / IP helpers (also extract TCP flags)
# ---------------------------------------------------------------------------

def _parse_l4_generic(data: bytes, off: int,
                      proto: int) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Return (sport, dport, tcp_flags) from L4 header at *off*."""
    if proto in (6, 17):  # TCP or UDP
        if len(data) < off + 4:
            return None, None, None
        sport = struct.unpack_from("!H", data, off)[0]
        dport = struct.unpack_from("!H", data, off + 2)[0]
        tcp_flags = None
        if proto == 6 and len(data) >= off + 14:
            tcp_flags = data[off + 13]
        return sport, dport, tcp_flags
    return None, None, None


def _parse_ipv4_generic(data: bytes,
                        off: int) -> tuple[str, str, int, Optional[int], Optional[int], Optional[int]]:
    """Return (src, dst, proto, sport, dport, tcp_flags) from IPv4 at *off*."""
    if len(data) < off + 20:
        raise ValueError("IPv4 header truncated")
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    src = ".".join(str(b) for b in data[off + 12: off + 16])
    dst = ".".join(str(b) for b in data[off + 16: off + 20])
    sport, dport, tcp_flags = _parse_l4_generic(data, off + ihl, proto)
    return src, dst, proto, sport, dport, tcp_flags


def _parse_ipv6_generic(data: bytes,
                        off: int) -> tuple[str, str, int, Optional[int], Optional[int], Optional[int]]:
    """Return (src, dst, next_hdr, sport, dport, tcp_flags) from IPv6 at *off*."""
    if len(data) < off + 40:
        raise ValueError("IPv6 header truncated")
    next_hdr = data[off + 6]
    src = _fmt_ipv6(data[off + 8: off + 24])
    dst = _fmt_ipv6(data[off + 24: off + 40])
    sport, dport, tcp_flags = _parse_l4_generic(data, off + 40, next_hdr)
    return src, dst, next_hdr, sport, dport, tcp_flags


def _make_generic(pkt_num: int, ts_sec: int, ts_usec: int, orig_len: int, data: bytes,
                  ip_version: int, src: str, dst: str, proto_num: int,
                  sport: Optional[int], dport: Optional[int], tcp_flags: Optional[int],
                  **pflog_kw) -> GenericPacket:
    proto_name = PROTO_NAMES.get(proto_num, f"proto{proto_num}")
    return GenericPacket(
        pkt_num=pkt_num, ts_sec=ts_sec, ts_usec=ts_usec,
        pkt_len=orig_len, cap_len=len(data),
        ip_version=ip_version, src_ip=src, dst_ip=dst,
        proto_num=proto_num, proto_name=proto_name,
        sport=sport, dport=dport, tcp_flags=tcp_flags,
        **pflog_kw,
    )


# ---------------------------------------------------------------------------
# Per-DLT frame parsers → GenericPacket
# ---------------------------------------------------------------------------

def _parse_generic_pflog(pkt_num: int, ts_sec: int, ts_usec: int,
                         orig_len: int, data: bytes) -> GenericPacket:
    """Parse a PFLOG frame into a GenericPacket (includes PFLOG fields)."""
    if len(data) < 1:
        raise ValueError("empty PFLOG packet")
    hdr_len = data[0]
    if len(data) < hdr_len:
        raise ValueError(f"PFLOG header truncated ({len(data)} < {hdr_len})")

    af             = data[1]
    action         = data[2]
    ifname         = data[4:20].rstrip(b"\x00").decode("ascii", errors="replace")
    rule_num       = struct.unpack_from(">I", data, 36)[0]
    direction_byte = data[60]
    direction      = "out" if direction_byte == _DIR_OUT else "in"
    action_name    = _ACTION_NAMES.get(action, f"action{action}")

    ip_off = (hdr_len + 3) & ~3

    if af == _AF_INET:
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv4_generic(data, ip_off)
        ip_version = 4
    elif af in (_AF_INET6_BSD, _AF_INET6_LNX, _AF_INET6_OSX):
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv6_generic(data, ip_off)
        ip_version = 6
    else:
        raise ValueError(f"PFLOG: unsupported AF {af}")

    return _make_generic(
        pkt_num, ts_sec, ts_usec, orig_len, data,
        ip_version, src, dst, proto_num, sport, dport, tcp_flags,
        pflog_action=action, pflog_action_name=action_name,
        ifname=ifname, direction=direction, rule_num=rule_num,
    )


def _parse_generic_null(pkt_num: int, ts_sec: int, ts_usec: int,
                        orig_len: int, data: bytes) -> GenericPacket:
    """DLT_NULL (0) / DLT_LOOP (12): 4-byte host-order AF field then IP."""
    if len(data) < 4:
        raise ValueError("DLT_NULL frame too short")
    # BSD uses host byte order; most captures are little-endian
    af = struct.unpack_from("<I", data, 0)[0]
    ip_off = 4
    if af == 2:  # AF_INET
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv4_generic(data, ip_off)
        ip_version = 4
    elif af in (10, 24, 28, 30):  # AF_INET6 (Linux=10, NetBSD=24, FreeBSD=28, macOS=30)
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv6_generic(data, ip_off)
        ip_version = 6
    else:
        raise ValueError(f"DLT_NULL: unknown AF {af}")
    return _make_generic(pkt_num, ts_sec, ts_usec, orig_len, data,
                         ip_version, src, dst, proto_num, sport, dport, tcp_flags)


def _parse_generic_ethernet(pkt_num: int, ts_sec: int, ts_usec: int,
                             orig_len: int, data: bytes) -> GenericPacket:
    """DLT_EN10MB (1): 14-byte Ethernet header (handles 802.1Q VLAN tags)."""
    if len(data) < 14:
        raise ValueError("Ethernet frame too short")
    ethertype = struct.unpack_from("!H", data, 12)[0]
    ip_off = 14
    # Strip 802.1Q VLAN tags
    while ethertype == 0x8100 and len(data) >= ip_off + 4:
        ethertype = struct.unpack_from("!H", data, ip_off + 2)[0]
        ip_off += 4
    if ethertype == 0x0800:
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv4_generic(data, ip_off)
        ip_version = 4
    elif ethertype == 0x86DD:
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv6_generic(data, ip_off)
        ip_version = 6
    else:
        raise ValueError(f"Ethernet: unsupported ethertype 0x{ethertype:04x}")
    return _make_generic(pkt_num, ts_sec, ts_usec, orig_len, data,
                         ip_version, src, dst, proto_num, sport, dport, tcp_flags)


def _parse_generic_raw(pkt_num: int, ts_sec: int, ts_usec: int,
                       orig_len: int, data: bytes) -> GenericPacket:
    """DLT_RAW (101) / DLT_IPV4 (228): raw IP, version in first nibble."""
    if not data:
        raise ValueError("Raw IP frame is empty")
    version = (data[0] >> 4) & 0xF
    if version == 4:
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv4_generic(data, 0)
        ip_version = 4
    elif version == 6:
        src, dst, proto_num, sport, dport, tcp_flags = _parse_ipv6_generic(data, 0)
        ip_version = 6
    else:
        raise ValueError(f"Raw IP: unknown version nibble {version}")
    return _make_generic(pkt_num, ts_sec, ts_usec, orig_len, data,
                         ip_version, src, dst, proto_num, sport, dport, tcp_flags)


# Map link type → per-DLT parser function
_GENERIC_PARSERS = {
    LINKTYPE_NULL:     _parse_generic_null,
    LINKTYPE_ETHERNET: _parse_generic_ethernet,
    LINKTYPE_LOOP:     _parse_generic_null,    # same layout as DLT_NULL
    LINKTYPE_RAW:      _parse_generic_raw,
    LINKTYPE_PFLOG:    _parse_generic_pflog,
    LINKTYPE_IPV4:     _parse_generic_raw,     # same layout as DLT_RAW
}


def _dispatch_generic(pkt_num: int, ts_sec: int, ts_usec: int,
                      orig_len: int, data: bytes, link_type: int) -> GenericPacket:
    parser = _GENERIC_PARSERS.get(link_type)
    if parser is None:
        raise ValueError(f"unsupported link type {link_type} "
                         f"(supported: {sorted(_GENERIC_PARSERS)})")
    return parser(pkt_num, ts_sec, ts_usec, orig_len, data)


# ---------------------------------------------------------------------------
# Public generic reader
# ---------------------------------------------------------------------------

def read_pcap(path: str) -> tuple[list[GenericPacket], int]:
    """Parse any supported pcap file; return (packets, link_type).

    Supported DLTs: NULL(0), Ethernet(1), BSD Loopback(12),
                    Raw IP(101), PFLOG(117), Raw IPv4(228).

    Packets that cannot be decoded have *parse_error* set and empty IP fields.
    Raises ValueError if the file is not a valid pcap or the link type is
    unsupported.
    """
    with open(path, "rb") as fh:
        raw = fh.read()

    if len(raw) < 24:
        raise ValueError(f"{path}: too small to be a valid pcap")

    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic == PCAP_GLOBAL_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_GLOBAL_MAGIC_BE:
        endian = ">"
    else:
        raise ValueError(f"{path}: not a pcap file (bad magic 0x{magic:08x})")

    link_type = struct.unpack_from(endian + "I", raw, 20)[0]

    # Validate link type early so we surface a clear error
    if link_type not in _GENERIC_PARSERS:
        raise ValueError(
            f"{path}: unsupported link type {link_type} "
            f"(supported: {sorted(_GENERIC_PARSERS)})"
        )

    packets: list[GenericPacket] = []
    offset = 24
    pkt_num = 0

    while offset < len(raw):
        if len(raw) - offset < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
            endian + "IIII", raw, offset
        )
        offset += 16
        pkt_num += 1

        if len(raw) - offset < incl_len:
            packets.append(GenericPacket(
                pkt_num=pkt_num, ts_sec=ts_sec, ts_usec=ts_usec,
                pkt_len=orig_len, cap_len=incl_len,
                parse_error="truncated: packet data missing",
            ))
            break  # can't continue past truncation

        pkt_data = raw[offset: offset + incl_len]
        offset += incl_len

        try:
            pkt = _dispatch_generic(pkt_num, ts_sec, ts_usec, orig_len, pkt_data, link_type)
        except Exception as exc:  # noqa: BLE001
            pkt = GenericPacket(
                pkt_num=pkt_num, ts_sec=ts_sec, ts_usec=ts_usec,
                pkt_len=orig_len, cap_len=incl_len,
                parse_error=str(exc),
            )
        packets.append(pkt)

    return packets, link_type
