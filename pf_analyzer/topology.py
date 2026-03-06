"""ASCII network topology renderer."""

from __future__ import annotations

from .model import AddressFamily, NatRule, ParsedConfig, RdrRule


# ---------------------------------------------------------------------------
# Zone / interface discovery
# ---------------------------------------------------------------------------

# Heuristic zone-name map: macro name prefix → human-readable zone name
_ZONE_NAMES: dict[str, str] = {
    "ext":      "INTERNET (external)",
    "int2":     "INTERNAL",
    "int":      "JAIL ZONE",
    "bot":      "BOT NET",
    "tun":      "TUNNEL/VPN",
    "loopback": "LOOPBACK (skipped)",
    "lo":       "LOOPBACK (skipped)",
}


def _zone_label(macro_name: str) -> str:
    for prefix, label in _ZONE_NAMES.items():
        if macro_name == prefix or macro_name.startswith(prefix + "_"):
            return label
    return macro_name.upper()


def _is_subnet_macro(name: str) -> bool:
    return name.endswith("_net") or name.endswith("_net_gw")


def _iface_macro_for_subnet(subnet_name: str,
                              iface_macros: list[str]) -> str | None:
    """Heuristic: find the interface macro best matching a subnet macro."""
    # e.g. masto_net → int (jail zone), bot_net → bot, wireguard_net → tun
    prefix = subnet_name.split("_")[0]  # "masto", "bot", "wireguard", etc.

    subnet_to_iface: dict[str, str] = {
        "home": "int2",
        "andrew": "int2",
        "wifi": "int2",
        "masto": "int",
        "nextcloud": "int",
        "wireguard": "tun",
        "bot": "bot",
    }
    if prefix in subnet_to_iface:
        target = subnet_to_iface[prefix]
        if target in iface_macros:
            return target
    return None


# ---------------------------------------------------------------------------
# Topology data collection
# ---------------------------------------------------------------------------

def _collect_zones(config: ParsedConfig) -> list[dict]:
    """
    Return a list of zone dicts:
      { name, iface, label, subnets: [(subnet_str, macro_name)],
        children: [(child_iface_macro, child_iface)] }
    """
    macro_map = {m.name: m.expanded_value for m in config.macros}

    # Identify interface macros: those whose value looks like a network interface
    import re
    iface_macros: list[str] = []
    for m in config.macros:
        v = m.expanded_value.strip('"')
        if re.match(r'^[a-z]+[0-9]+[a-z0-9_]*$', v) and '_net' not in m.name:
            if '_gw' not in m.name and 'tunnelbroker' not in m.name:
                iface_macros.append(m.name)

    # Top-level interface macros (no underscore separating them from a parent)
    top_ifaces: list[str] = []
    child_ifaces: dict[str, list[str]] = {}  # parent → list of child macro names

    for name in iface_macros:
        # int_jail_nextcloud → child of "int"
        parts = name.split('_')
        if len(parts) > 1 and parts[0] in iface_macros:
            parent = parts[0]
            child_ifaces.setdefault(parent, []).append(name)
        else:
            top_ifaces.append(name)

    # Collect subnet macros (ending in _net, not _net_gw)
    subnet_macros = [m for m in config.macros
                     if m.name.endswith('_net') and not m.name.endswith('_net_gw')]

    zones: list[dict] = []
    for macro_name in top_ifaces:
        iface = macro_map.get(macro_name, macro_name)
        label = _zone_label(macro_name)
        subnets: list[tuple[str, str]] = []

        for sm in subnet_macros:
            owner = _iface_macro_for_subnet(sm.name, top_ifaces)
            if owner == macro_name:
                subnets.append((sm.expanded_value, sm.name))

        children: list[tuple[str, str]] = []
        for child_name in child_ifaces.get(macro_name, []):
            child_iface = macro_map.get(child_name, child_name)
            children.append((child_name, child_iface))

        zones.append({
            "macro": macro_name,
            "iface": iface,
            "label": label,
            "subnets": subnets,
            "children": children,
        })

    # Sort: ext first, loopback last
    def zone_sort_key(z: dict) -> int:
        if z["macro"] == "ext":
            return 0
        if "loopback" in z["macro"] or z["macro"].startswith("lo"):
            return 99
        return 50

    zones.sort(key=zone_sort_key)
    return zones


def _nat_summary(config: ParsedConfig) -> list[str]:
    lines: list[str] = []
    for n in config.nat_rules:
        src = str(n.src)
        dst = str(n.redirect_to)
        lines.append(f"NAT: {src} → {dst}")
    for r in config.rdr_rules:
        src = str(r.src)
        dst = str(r.redirect_to)
        lines.append(f"RDR: {src} → {dst}")
    return lines


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_topology(config: ParsedConfig) -> str:
    zones = _collect_zones(config)
    nat_lines = _nat_summary(config)
    tables_info = _blocking_summary(config)

    width = 62
    # Border: "╔" + "═"*(width-2) + "╗"  = width chars
    # Content: "║ " + content.ljust(inner) + " ║" = 1+1+inner+1+1 = inner+4 chars
    # For alignment: inner + 4 = width  →  inner = width - 4
    inner = width - 4
    rows: list[str] = []

    def box_line(content: str = "") -> str:
        if len(content) > inner:
            content = content[:inner - 1] + "…"
        return "║ " + content.ljust(inner) + " ║"

    rows.append("╔" + "═" * (width - 2) + "╗")
    title = "NETWORK TOPOLOGY"
    rows.append("║ " + title.center(inner) + " ║")
    rows.append("╠" + "═" * (width - 2) + "╣")

    ext_zone = next((z for z in zones if z["macro"] == "ext"), None)
    non_ext = [z for z in zones if z["macro"] != "ext"
               and "loopback" not in z["label"].lower()]
    loopback_zones = [z for z in zones if "loopback" in z["label"].lower()]

    # Internet cloud
    rows.append(box_line())
    rows.append(box_line("  [INTERNET]"))
    rows.append(box_line("      │"))

    # Firewall box
    fw_lines: list[str] = []
    if ext_zone:
        fw_lines.append(f"FIREWALL  ({ext_zone['macro']}={ext_zone['iface']})")
    else:
        fw_lines.append("FIREWALL")

    for nat in nat_lines:
        fw_lines.append("  " + nat)

    rows.append(box_line("  ┌" + "─" * (inner - 4) + "┐"))
    for fl in fw_lines:
        rows.append(box_line("  │  " + fl))
    rows.append(box_line("  └" + "─" * (inner - 4) + "┘"))
    rows.append(box_line("      │"))

    # Internal zones
    last_idx = len(non_ext) - 1
    for i, zone in enumerate(non_ext):
        is_last = (i == last_idx)
        connector = "└" if is_last else "├"
        line_char = " " if is_last else "│"

        zline = f"      {connector}─[{zone['iface']} / {zone['macro']}]"
        label_suffix = "─" * max(0, inner - len(zline) + 4 - len(zone['label']) - 1)
        zline_full = zline + label_suffix + " " + zone["label"]
        rows.append(box_line(zline_full))

        prefix = f"      {line_char}   "

        # Children (jail sub-interfaces)
        for j, (child_name, child_iface) in enumerate(zone["children"]):
            child_is_last = (j == len(zone["children"]) - 1) and not zone["subnets"]
            cc = "└" if child_is_last else "├"
            rows.append(box_line(f"{prefix}{cc}─ {child_iface}  ({child_name})"))

        # Subnets
        for k, (subnet, sname) in enumerate(zone["subnets"]):
            sub_is_last = (k == len(zone["subnets"]) - 1)
            sc = "└" if sub_is_last else "├"
            rows.append(box_line(f"{prefix}{sc}─ {subnet}  ({sname})"))

    # Loopback note
    if loopback_zones:
        rows.append(box_line())
        for lz in loopback_zones:
            rows.append(box_line(f"  [{lz['iface']} / {lz['macro']}] — LOOPBACK (set skip on lo0)"))

    rows.append(box_line())
    rows.append("╚" + "═" * (width - 2) + "╝")

    # Blocking policy section
    rows.append("")
    rows.append("Blocking policy:")
    rows.extend(tables_info)

    return "\n".join(rows)


def _blocking_summary(config: ParsedConfig) -> list[str]:
    lines: list[str] = []

    # Block policy option
    bp = next((o for o in config.options if o.name.lower() == "block-policy"), None)
    if bp:
        lines.append(f"  set block-policy {bp.value}")

    # Tables
    for t in config.tables:
        flags_str = " ".join(t.flags)
        n = len(t.addrs)
        fp_str = ""
        if t.file_paths:
            fp_str = f" + file(s): {', '.join(t.file_paths)}"
        lines.append(f"  table <{t.name}> [{flags_str}]: "
                     f"{n} inline addr(s){fp_str}")

    # Default-deny rules
    ifaces_blocked = set()
    for r in config.filter_rules:
        if (r.action.value == "block" and
                r.src.is_any and r.dst.is_any and
                not r.quick and r.interface):
            ifaces_blocked.add(r.interface)

    if ifaces_blocked:
        lines.append(f"  Default BLOCK on: {', '.join(sorted(ifaces_blocked))}")

    return lines
