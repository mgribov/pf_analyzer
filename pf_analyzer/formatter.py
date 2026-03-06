"""Shared output helpers: box drawing, tables, rule summaries."""

from __future__ import annotations

from .model import (
    Action, AddressFamily, AddressSpec, Direction, FilterRule,
    Macro, NatRule, ParsedConfig, PortSpec, RdrRule, Table,
)


# ---------------------------------------------------------------------------
# Box drawing
# ---------------------------------------------------------------------------

def make_box(title: str, lines: list[str], width: int = 60) -> str:
    inner_w = width - 4  # account for "║  " and "  ║"
    rows: list[str] = []

    title_padded = title.center(inner_w)
    rows.append("╔" + "═" * (width - 2) + "╗")
    rows.append("║  " + title_padded + "  ║")
    rows.append("╠" + "═" * (width - 2) + "╣")

    for line in lines:
        # Truncate if needed
        if len(line) > inner_w:
            line = line[:inner_w - 1] + "…"
        padded = line.ljust(inner_w)
        rows.append("║  " + padded + "  ║")

    rows.append("╚" + "═" * (width - 2) + "╝")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# ASCII table
# ---------------------------------------------------------------------------

def make_table(headers: list[str], rows: list[list[str]]) -> str:
    # Compute column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt_row = lambda cells: "|" + "|".join(
        f" {str(c).ljust(w)} " for c, w in zip(cells, widths)
    ) + "|"

    out: list[str] = [sep, fmt_row(headers), sep]
    for row in rows:
        # pad row to header count
        padded = list(row) + [""] * (len(headers) - len(row))
        out.append(fmt_row(padded))
    out.append(sep)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Rule formatting
# ---------------------------------------------------------------------------

def format_address(spec: AddressSpec) -> str:
    return str(spec)


def format_port(spec: PortSpec | None) -> str:
    if spec is None:
        return ""
    return f"port {spec.raw}"


def format_filter_rule(rule: FilterRule, expanded: bool = False) -> str:
    parts: list[str] = []
    parts.append(rule.action.value)
    if rule.direction != Direction.ANY:
        parts.append(rule.direction.value)
    if rule.log:
        parts.append("log")
    if rule.quick:
        parts.append("quick")
    if rule.interface:
        parts.append(f"on {rule.interface}")
    if rule.address_family != AddressFamily.ANY:
        parts.append(rule.address_family.value)
    if rule.proto:
        parts.append(f"proto {rule.proto}")

    src_str = format_address(rule.src)
    dst_str = format_address(rule.dst)

    if not (rule.src.is_any and rule.dst.is_any):
        parts.append(f"from {src_str}")
        if rule.src_port:
            parts.append(format_port(rule.src_port))
        parts.append(f"to {dst_str}")
        if rule.dst_port:
            parts.append(format_port(rule.dst_port))
    else:
        parts.append("all")

    if rule.icmp_types:
        parts.append(f"icmp-type {{ {', '.join(rule.icmp_types)} }}")
    if rule.flags:
        parts.append(f"flags {rule.flags}")
    if rule.state:
        parts.append(f"{rule.state} state")
        if rule.state_opts:
            parts.append(rule.state_opts)

    return " ".join(parts)


def format_nat_rule(rule: NatRule) -> str:
    parts = ["nat"]
    if rule.interface:
        parts.append(f"on {rule.interface}")
    if rule.address_family != AddressFamily.ANY:
        parts.append(rule.address_family.value)
    parts.append(f"from {rule.src} to {rule.dst}")
    parts.append(f"-> {rule.redirect_to}")
    if rule.redirect_port:
        parts.append(f"port {rule.redirect_port.raw}")
    return " ".join(parts)


def format_rdr_rule(rule: RdrRule) -> str:
    parts = ["rdr"]
    if rule.interface:
        parts.append(f"on {rule.interface}")
    if rule.address_family != AddressFamily.ANY:
        parts.append(rule.address_family.value)
    if rule.proto:
        parts.append(f"proto {{ {', '.join(rule.proto)} }}")
    parts.append(f"from {rule.src} to {rule.dst}")
    parts.append(f"-> {rule.redirect_to}")
    if rule.redirect_port:
        parts.append(f"port {rule.redirect_port.raw}")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def rules_summary(config: ParsedConfig) -> str:
    total = len(config.filter_rules)
    blocks = sum(1 for r in config.filter_rules if r.action == Action.BLOCK)
    passes = total - blocks
    return f"{total} filter rules ({passes} pass, {blocks} block)"


def tables_summary(config: ParsedConfig) -> str:
    lines: list[str] = []
    for t in config.tables:
        flags_str = " ".join(t.flags)
        addr_count = len(t.addrs)
        file_str = ", ".join(f'file "{f}"' for f in t.file_paths)
        desc = f"  <{t.name}> [{flags_str}]"
        if addr_count:
            desc += f" — {addr_count} inline addr(s)"
        if file_str:
            desc += f" — {file_str} (offline: unknown contents)"
        lines.append(desc)
    return "\n".join(lines) if lines else "  (no tables)"
