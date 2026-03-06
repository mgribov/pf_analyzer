"""Packet trace engine — simulates PF rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .matcher import (
    address_matches, af_matches, direction_matches, icmp_type_matches,
    interface_matches, port_matches, proto_matches,
)
from .model import Action, Direction, FilterRule, NatRule, ParsedConfig, RdrRule


@dataclass
class TracePacket:
    src_ip: str
    dst_ip: str
    proto: str                      # tcp, udp, icmp, icmp6
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    interface: Optional[str] = None
    direction: str = "in"           # "in" or "out"
    icmp_type: Optional[int] = None


@dataclass
class RuleEvaluation:
    index: int                      # 1-based rule index in filter_rules
    rule: FilterRule
    matched: bool
    reason: str
    is_final: bool = False          # True if this rule terminates evaluation


@dataclass
class NatTranslation:
    rule: NatRule
    original_src: str
    translated_src: str  # symbolic for ($iface) refs


@dataclass
class RdrTranslation:
    rule: RdrRule
    original_dst: str
    new_dst: str
    new_port: Optional[int] = None


@dataclass
class TraceResult:
    packet: TracePacket
    rdr_evaluations: list[tuple[RdrRule, bool, str]] = field(default_factory=list)
    evaluations: list[RuleEvaluation] = field(default_factory=list)
    final_action: Action = Action.BLOCK
    final_rule: Optional[FilterRule] = None
    nat_translations: list[NatTranslation] = field(default_factory=list)
    rdr_translation: Optional[RdrTranslation] = None


def trace(packet: TracePacket, config: ParsedConfig) -> TraceResult:
    result = TraceResult(packet=packet)

    # Step 1: Evaluate RDR rules (for inbound traffic)
    effective_dst = packet.dst_ip
    effective_dst_port = packet.dst_port

    if packet.direction == "in":
        for rdr in config.rdr_rules:
            matched, reason = _match_rdr(packet, rdr, config)
            result.rdr_evaluations.append((rdr, matched, reason))
            if matched:
                new_dst = str(rdr.redirect_to)
                new_port = None
                if rdr.redirect_port and rdr.redirect_port.specs:
                    spec = rdr.redirect_port.specs[0]
                    if spec[0] == '=':
                        new_port = spec[1]
                result.rdr_translation = RdrTranslation(
                    rule=rdr,
                    original_dst=effective_dst,
                    new_dst=new_dst,
                    new_port=new_port,
                )
                effective_dst = new_dst
                if new_port:
                    effective_dst_port = new_port
                break  # first matching RDR wins

    # Step 2: Evaluate filter rules
    # Default action: BLOCK (the last non-quick matching block rule wins)
    current_action = Action.BLOCK
    current_rule: Optional[FilterRule] = None

    for idx, rule in enumerate(config.filter_rules, start=1):
        matched, reason = _match_filter(
            packet, rule, config,
            effective_dst=effective_dst,
            effective_dst_port=effective_dst_port,
        )

        is_final = matched and rule.quick
        ev = RuleEvaluation(
            index=idx,
            rule=rule,
            matched=matched,
            reason=reason,
            is_final=is_final,
        )
        result.evaluations.append(ev)

        if matched:
            current_action = rule.action
            current_rule = rule
            if rule.quick:
                break

    result.final_action = current_action
    result.final_rule = current_rule

    # Step 3: NAT (outbound, after filter PASS)
    if result.final_action == Action.PASS and packet.direction == "out":
        for nat in config.nat_rules:
            matched, reason = _match_nat(packet, nat, config)
            if matched:
                orig = packet.src_ip
                translated = str(nat.redirect_to)
                result.nat_translations.append(
                    NatTranslation(rule=nat, original_src=orig,
                                   translated_src=translated)
                )
                break

    return result


# ---------------------------------------------------------------------------
# Per-rule matchers
# ---------------------------------------------------------------------------

def _match_rdr(packet: TracePacket, rdr: RdrRule,
               config: ParsedConfig) -> tuple[bool, str]:
    reasons: list[str] = []

    # Interface
    if not interface_matches(packet.interface, rdr.interface):
        return False, f"interface {packet.interface!r} != {rdr.interface!r}"
    if rdr.interface:
        reasons.append(f"iface={rdr.interface}")

    # AF
    if not af_matches(packet.src_ip, rdr.address_family):
        return False, f"address family mismatch"

    # Proto
    if rdr.proto:
        if not any(proto_matches(packet.proto, p) for p in rdr.proto):
            return False, f"proto {packet.proto!r} not in {rdr.proto}"

    # Source address
    ok, why = address_matches(packet.src_ip, rdr.src, config)
    if not ok:
        return False, f"src {packet.src_ip} {why}"
    if not rdr.src.is_any:
        reasons.append(f"src {why}")

    # Destination address
    ok, why = address_matches(packet.dst_ip, rdr.dst, config)
    if not ok:
        return False, f"dst {packet.dst_ip} {why}"
    if not rdr.dst.is_any:
        reasons.append(f"dst {why}")

    return True, "; ".join(reasons) if reasons else "all conditions met"


def _match_nat(packet: TracePacket, nat: NatRule,
               config: ParsedConfig) -> tuple[bool, str]:
    if not interface_matches(packet.interface, nat.interface):
        return False, f"interface mismatch"

    if not af_matches(packet.src_ip, nat.address_family):
        return False, f"address family mismatch"

    ok, why = address_matches(packet.src_ip, nat.src, config)
    if not ok:
        return False, f"src {packet.src_ip} {why}"

    ok, why = address_matches(packet.dst_ip, nat.dst, config)
    if not ok:
        return False, f"dst {packet.dst_ip} {why}"

    return True, "match"


def _match_filter(
    packet: TracePacket,
    rule: FilterRule,
    config: ParsedConfig,
    effective_dst: str,
    effective_dst_port: Optional[int],
) -> tuple[bool, str]:
    reasons: list[str] = []
    no_match_reasons: list[str] = []

    # Direction
    if not direction_matches(packet.direction, rule.direction):
        return False, f"direction {packet.direction!r} != {rule.direction.value!r}"

    # Interface
    if not interface_matches(packet.interface, rule.interface):
        return False, (f"interface {packet.interface!r} != {rule.interface!r}"
                       if rule.interface else "interface mismatch")

    # Address family
    if not af_matches(packet.src_ip, rule.address_family):
        return False, "address family mismatch (src)"
    if not af_matches(effective_dst, rule.address_family):
        return False, "address family mismatch (dst)"

    # Protocol
    if not proto_matches(packet.proto, rule.proto):
        return False, f"proto {packet.proto!r} != {rule.proto!r}"

    # Source address
    ok, why = address_matches(packet.src_ip, rule.src, config)
    if not ok:
        return False, f"src {packet.src_ip} {why}"
    if not rule.src.is_any:
        reasons.append(f"src {why}")

    # Source port
    if not port_matches(packet.src_port, rule.src_port):
        return False, f"src port {packet.src_port} not in {rule.src_port.raw if rule.src_port else '?'}"

    # Destination address
    ok, why = address_matches(effective_dst, rule.dst, config)
    if not ok:
        return False, f"dst {effective_dst} {why}"
    if not rule.dst.is_any:
        reasons.append(f"dst {why}")

    # Destination port
    if not port_matches(effective_dst_port, rule.dst_port):
        praw = rule.dst_port.raw if rule.dst_port else "?"
        return False, f"dst port {effective_dst_port} not in port {praw}"

    # ICMP type
    if not icmp_type_matches(packet.icmp_type, rule.icmp_types):
        return False, (f"icmp-type {packet.icmp_type} not in "
                       f"{{{', '.join(rule.icmp_types)}}}")

    reason = "; ".join(reasons) if reasons else "all conditions met"
    return True, reason


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

def suggest_counter_rule(result: TraceResult) -> str:
    """Return a formatted section suggesting a minimal rule to flip the verdict."""
    import ipaddress

    pkt = result.packet
    opposite = "pass" if result.final_action == Action.BLOCK else "block"
    verdict_word = "PASS" if opposite == "pass" else "BLOCK"

    # Determine address family and host prefix lengths
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

    # Build the rule string
    parts = [opposite, pkt.direction, "quick"]
    if pkt.interface:
        parts += ["on", pkt.interface]
    parts.append(af)
    parts += ["proto", pkt.proto]
    parts += ["from", f"{pkt.src_ip}{src_prefix}"]
    if pkt.src_port is not None:
        parts += ["port", str(pkt.src_port)]
    parts += ["to", f"{pkt.dst_ip}{dst_prefix}"]
    if pkt.dst_port is not None:
        parts += ["port", str(pkt.dst_port)]
    if pkt.proto in ("icmp", "icmp6") and pkt.icmp_type is not None:
        parts += ["icmp-type", str(pkt.icmp_type)]
    if opposite == "pass":
        if pkt.proto == "tcp":
            parts.append("flags S/SA modulate state")
        else:
            parts.append("keep state")

    rule_str = " ".join(parts)

    # Determine insertion point
    if result.final_rule is not None:
        insert_line = result.final_rule.line_num
        rule_desc = result.final_rule.raw_text
    elif result.evaluations:
        insert_line = result.evaluations[0].rule.line_num
        rule_desc = None
    else:
        insert_line = 1
        rule_desc = None

    sep = "\u2500" * 72
    out_lines = [
        sep,
        f"Suggested rule to {verdict_word} this packet:",
        "",
        f"  {rule_str}",
        "",
        f"  Insert BEFORE line {insert_line} in pf.conf",
    ]
    if rule_desc is not None:
        out_lines.append(f"  (that rule: {rule_desc})")

    return "\n".join(out_lines)


def format_trace(result: TraceResult) -> str:
    pkt = result.packet
    lines: list[str] = []

    # Header
    sport = f":{pkt.src_port}" if pkt.src_port else ""
    dport = f":{pkt.dst_port}" if pkt.dst_port else ""
    iface_str = f" on {pkt.interface}" if pkt.interface else ""
    lines.append(
        f"TRACE: {pkt.proto.upper()} "
        f"{pkt.src_ip}{sport} -> {pkt.dst_ip}{dport}"
        f"{iface_str} ({pkt.direction})"
    )
    lines.append("=" * 72)

    # RDR evaluation
    if result.rdr_evaluations:
        lines.append("RDR Evaluation:")
        for rdr, matched, reason in result.rdr_evaluations:
            sym = "MATCH" if matched else "NO MATCH"
            lines.append(f"  [line {rdr.line_num:>4}]  {rdr.raw_text}")
            lines.append(f"             -> {sym} ({reason})")
        if result.rdr_translation:
            rt = result.rdr_translation
            prt = f":{rt.new_port}" if rt.new_port else ""
            lines.append(f"  *** RDR applied: dst rewritten to {rt.new_dst}{prt}")
        lines.append("")

    # Filter rule evaluation
    lines.append("Filter Rule Evaluation:")
    for ev in result.evaluations:
        rule = ev.rule
        if ev.matched:
            quick_mark = " (quick)" if rule.quick else ""
            check = " ✓" if ev.is_final else ""
            lines.append(f"  #{ev.index:<3} [line {rule.line_num:>4}]  {rule.raw_text}")
            lines.append(f"               -> MATCH{quick_mark}{check} | {ev.reason}")
        else:
            lines.append(f"  #{ev.index:<3} [line {rule.line_num:>4}]  {rule.raw_text}")
            lines.append(f"               -> NO MATCH | {ev.reason}")

    # Verdict
    lines.append("")
    lines.append("-" * 72)
    action = result.final_action.value.upper()
    if result.final_rule:
        r = result.final_rule
        state_str = ""
        if r.state:
            state_str = f", {r.state} state"
            if r.state_opts:
                state_str += f" {r.state_opts}"
        lines.append(
            f"VERDICT: {action}  "
            f"(rule #{result.evaluations.index(next(e for e in result.evaluations if e.rule is r)) + 1}, "
            f"line {r.line_num}{state_str})"
        )
    else:
        lines.append(f"VERDICT: {action}  (default policy — no matching rule)")

    # NAT
    if result.nat_translations:
        lines.append("")
        lines.append("NAT Applied:")
        for nt in result.nat_translations:
            lines.append(f"  src {nt.original_src} -> {nt.translated_src}")

    return "\n".join(lines)
