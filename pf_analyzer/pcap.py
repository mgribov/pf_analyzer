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
