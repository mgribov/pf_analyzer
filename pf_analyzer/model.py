"""Data model: dataclasses and enums for parsed pf.conf constructs."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class Action(Enum):
    PASS = "pass"
    BLOCK = "block"


class Direction(Enum):
    IN = "in"
    OUT = "out"
    ANY = "any"  # neither 'in' nor 'out' specified


class AddressFamily(Enum):
    INET = "inet"
    INET6 = "inet6"
    ANY = "any"


@dataclass
class Macro:
    name: str
    raw_value: str        # value as written (may contain $refs)
    expanded_value: str   # fully expanded value
    line_num: int


@dataclass
class Table:
    name: str
    flags: list[str]      # persist, const, etc.
    addrs: list[str]      # inline address strings
    file_paths: list[str] # file "..." entries
    line_num: int


@dataclass
class Option:
    name: str             # e.g. "block-policy", "loginterface", "skip"
    value: str            # raw value string
    line_num: int


@dataclass
class ScrubRule:
    direction: str        # "in", "out", or ""
    interface: Optional[str]
    address_family: AddressFamily
    options: str          # remainder as raw text
    raw_text: str
    line_num: int


@dataclass
class AddressSpec:
    """Universal address specification."""
    raw: str
    negated: bool = False
    addrs: list[str] = field(default_factory=list)   # CIDR strings or "any"
    interface_self: Optional[str] = None              # interface name for ($iface) refs
    interface_modifier: Optional[str] = None          # e.g. "0" from ($iface:0)
    table_name: Optional[str] = None                  # <tablename>
    is_any: bool = False

    def __str__(self) -> str:
        neg = "! " if self.negated else ""
        if self.is_any:
            return f"{neg}any"
        if self.table_name:
            return f"{neg}<{self.table_name}>"
        if self.interface_self:
            mod = f":{self.interface_modifier}" if self.interface_modifier else ""
            return f"{neg}({self.interface_self}{mod})"
        return f"{neg}{', '.join(self.addrs)}"


@dataclass
class PortSpec:
    """Port specification."""
    raw: str
    # Each spec is a tuple:
    #   ('=',  port)              single port
    #   ('>',  port)              greater than
    #   ('<',  port)              less than
    #   ('>=', port)              >=
    #   ('<=', port)              <=
    #   ('><', low, high)         exclusive range
    #   ('<>', low, high)         inclusive range
    specs: list[tuple]


@dataclass
class NatRule:
    interface: Optional[str]
    address_family: AddressFamily
    src: AddressSpec
    dst: AddressSpec
    redirect_to: AddressSpec        # target address
    redirect_port: Optional[PortSpec]
    raw_text: str
    line_num: int


@dataclass
class RdrRule:
    interface: Optional[str]
    address_family: AddressFamily
    proto: list[str]               # e.g. ["tcp", "udp", "icmp"]
    src: AddressSpec
    dst: AddressSpec
    redirect_to: AddressSpec
    redirect_port: Optional[PortSpec]
    raw_text: str
    line_num: int


@dataclass
class Anchor:
    anchor_type: str      # "anchor", "rdr-anchor", "nat-anchor"
    name: str
    raw_text: str
    line_num: int


@dataclass
class FilterRule:
    action: Action
    direction: Direction
    quick: bool
    log: bool
    interface: Optional[str]
    address_family: AddressFamily
    proto: Optional[str]           # tcp, udp, icmp, icmp6, etc.
    src: AddressSpec
    src_port: Optional[PortSpec]
    dst: AddressSpec
    dst_port: Optional[PortSpec]
    icmp_types: list[str]          # names or numeric strings
    flags: Optional[str]           # e.g. "S/SA"
    state: Optional[str]           # "keep", "modulate", "synproxy", or None
    state_opts: str                # raw state options string
    raw_text: str
    line_num: int


@dataclass
class ParsedConfig:
    macros: list[Macro] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    options: list[Option] = field(default_factory=list)
    scrub_rules: list[ScrubRule] = field(default_factory=list)
    nat_rules: list[NatRule] = field(default_factory=list)
    rdr_rules: list[RdrRule] = field(default_factory=list)
    anchors: list[Anchor] = field(default_factory=list)
    filter_rules: list[FilterRule] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)

    def get_table(self, name: str) -> Optional[Table]:
        for t in self.tables:
            if t.name == name:
                return t
        return None

    def get_macro(self, name: str) -> Optional[Macro]:
        for m in self.macros:
            if m.name == name:
                return m
        return None
