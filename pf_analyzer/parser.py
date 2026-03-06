"""Two-pass parser for pf.conf files."""

from __future__ import annotations

import itertools
import re
from pathlib import Path

from .errors import MacroExpansionError, ParseError
from .lexer import lex, tokenize
from .model import (
    Action, AddressFamily, AddressSpec, Anchor, Direction, FilterRule,
    Macro, NatRule, Option, ParsedConfig, PortSpec, RdrRule, ScrubRule, Table,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_file(path: str | Path) -> ParsedConfig:
    source = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_source(source)


def parse_source(source: str) -> ParsedConfig:
    lines = lex(source)
    raw_lines = source.splitlines()
    config = ParsedConfig(raw_lines=raw_lines)

    # Pass 1: collect macros in definition order
    macro_map: dict[str, str] = {}
    for line_num, text in lines:
        m = re.match(r'^(\w+)\s*=\s*(.+)$', text)
        if m:
            name = m.group(1)
            raw_val = m.group(2).strip().strip('"')
            expanded = _expand_macros(raw_val, macro_map, line_num)
            macro_map[name] = expanded
            config.macros.append(Macro(name=name, raw_value=raw_val,
                                       expanded_value=expanded, line_num=line_num))

    # Pass 2: parse all non-macro lines
    for line_num, text in lines:
        # Skip macro definitions
        if re.match(r'^\w+\s*=', text):
            continue

        # Expand macros in the line
        try:
            expanded = _expand_macros(text, macro_map, line_num)
        except MacroExpansionError:
            expanded = text  # best-effort, warn later

        tokens = tokenize(expanded)
        if not tokens:
            continue

        keyword = tokens[0].lower()

        try:
            if keyword == 'set':
                config.options.append(_parse_option(tokens, line_num))
            elif keyword == 'scrub':
                config.scrub_rules.append(_parse_scrub(tokens, line_num, expanded))
            elif keyword == 'table':
                config.tables.append(_parse_table(tokens, line_num))
            elif keyword == 'nat':
                rule = _parse_nat(tokens, line_num, expanded)
                if rule:
                    config.nat_rules.append(rule)
            elif keyword == 'rdr':
                rule = _parse_rdr(tokens, line_num, expanded)
                if rule:
                    config.rdr_rules.append(rule)
            elif keyword in ('anchor', 'rdr-anchor', 'nat-anchor', 'binat-anchor'):
                config.anchors.append(_parse_anchor(tokens, line_num, expanded))
            elif keyword in ('block', 'pass'):
                rules = _parse_filter(tokens, line_num, expanded)
                config.filter_rules.extend(rules)
            elif keyword == 'include':
                # recursive parse - get the filename
                if len(tokens) > 1:
                    inc_path = tokens[1].strip('"')
                    try:
                        sub = parse_file(inc_path)
                        config.macros.extend(sub.macros)
                        config.tables.extend(sub.tables)
                        config.options.extend(sub.options)
                        config.scrub_rules.extend(sub.scrub_rules)
                        config.nat_rules.extend(sub.nat_rules)
                        config.rdr_rules.extend(sub.rdr_rules)
                        config.anchors.extend(sub.anchors)
                        config.filter_rules.extend(sub.filter_rules)
                    except FileNotFoundError:
                        pass  # included file not available offline
            # else: unknown keyword, skip
        except (ParseError, IndexError):
            pass  # best-effort, skip unparseable lines

    return config


# ---------------------------------------------------------------------------
# Macro expansion
# ---------------------------------------------------------------------------

def _expand_macros(text: str, macro_map: dict[str, str], line_num: int) -> str:
    """Replace all $name references with their expanded values."""
    # We do multiple passes to handle chained macros, but limit iterations
    # to avoid infinite loops.
    for _ in range(10):
        new_text = _expand_once(text, macro_map, line_num)
        if new_text == text:
            break
        text = new_text
    return text


def _expand_once(text: str, macro_map: dict[str, str], line_num: int) -> str:
    """Single pass of macro substitution."""
    result: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == '"':
            # skip quoted string
            j = i + 1
            while j < len(text) and text[j] != '"':
                j += 1
            result.append(text[i:j+1])
            i = j + 1
        elif text[i] == '$':
            # read macro name
            j = i + 1
            while j < len(text) and (text[j].isalnum() or text[j] == '_'):
                j += 1
            name = text[i+1:j]
            if name in macro_map:
                result.append(macro_map[name])
            else:
                # unknown macro - keep as-is (may be resolved later)
                result.append(text[i:j])
            i = j
        else:
            result.append(text[i])
            i += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# Token stream helper
# ---------------------------------------------------------------------------

class TokenStream:
    def __init__(self, tokens: list[str]):
        self._tokens = tokens
        self._pos = 0

    def peek(self, offset: int = 0) -> str | None:
        idx = self._pos + offset
        if idx < len(self._tokens):
            return self._tokens[idx]
        return None

    def consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def expect(self, value: str) -> str:
        tok = self.consume()
        if tok.lower() != value.lower():
            raise ParseError(f"Expected '{value}', got '{tok}'")
        return tok

    def at_end(self) -> bool:
        return self._pos >= len(self._tokens)

    def remaining(self) -> list[str]:
        return self._tokens[self._pos:]

    def consume_if(self, *values: str) -> str | None:
        for v in values:
            if self.peek() and self.peek().lower() == v.lower():
                return self.consume()
        return None

    def rest_as_str(self) -> str:
        r = self.remaining()
        self._pos = len(self._tokens)
        return " ".join(r)


# ---------------------------------------------------------------------------
# Address parsing
# ---------------------------------------------------------------------------

def _parse_address_spec(ts: TokenStream) -> AddressSpec:
    """Parse an address specification at current position."""
    negated = False
    if ts.peek() == '!':
        ts.consume()
        negated = True

    tok = ts.peek()
    if tok is None:
        return AddressSpec(raw="any", is_any=True, negated=negated)

    tok_lower = tok.lower()

    if tok_lower == 'any':
        ts.consume()
        return AddressSpec(raw="any", is_any=True, negated=negated)

    if tok_lower == 'all':
        # 'all' = from any to any; return any for the current side
        ts.consume()
        return AddressSpec(raw="all", is_any=True, negated=negated)

    # Table reference: <name>
    if tok.startswith('<') and tok.endswith('>'):
        ts.consume()
        tname = tok[1:-1]
        return AddressSpec(raw=tok, table_name=tname, negated=negated)

    # Interface self-reference: (iface) or (iface:0)
    if tok.startswith('(') and tok.endswith(')'):
        ts.consume()
        inner = tok[1:-1]
        if ':' in inner:
            iface, mod = inner.split(':', 1)
        else:
            iface, mod = inner, None
        return AddressSpec(raw=tok, interface_self=iface,
                           interface_modifier=mod, negated=negated)

    # Braced list: { a, b, c }
    if tok == '{':
        ts.consume()
        addrs = []
        while ts.peek() and ts.peek() != '}':
            item = ts.consume()
            if item != ',':
                addrs.append(item)
        if ts.peek() == '}':
            ts.consume()
        raw = "{ " + ", ".join(addrs) + " }"
        return AddressSpec(raw=raw, addrs=addrs, negated=negated)

    # Could be an IP/CIDR, hostname, or interface name
    ts.consume()
    return AddressSpec(raw=tok, addrs=[tok], negated=negated)


def _parse_port_spec(ts: TokenStream) -> PortSpec | None:
    """Parse a port spec after the 'port' keyword has been consumed."""
    specs = []

    tok = ts.peek()
    if tok is None:
        return None

    if tok == '{':
        ts.consume()
        ports = []
        while ts.peek() and ts.peek() != '}':
            item = ts.consume()
            if item != ',':
                ports.append(item)
        if ts.peek() == '}':
            ts.consume()
        for p in ports:
            try:
                specs.append(('=', int(p) if p.isdigit() else _named_port(p)))
            except ValueError:
                specs.append(('=', p))
        return PortSpec(raw="{ " + ", ".join(ports) + " }", specs=specs)

    # Check for binary range operators
    op = None
    if tok in ('><', '<>'):
        op = ts.consume()
        low_tok = ts.consume()
        high_tok = ts.consume()
        low = _port_val(low_tok)
        high = _port_val(high_tok)
        raw = f"{low} {op} {high}"
        return PortSpec(raw=raw, specs=[(op, low, high)])

    # Unary operators: > N, < N, >= N, <= N
    if tok in ('>', '<', '>=', '<='):
        op = ts.consume()
        val_tok = ts.consume()
        val = _port_val(val_tok)
        return PortSpec(raw=f"{op}{val}", specs=[(op, val)])

    # Single port (possibly with >< or <> following as next tokens)
    val_tok = ts.consume()
    next_tok = ts.peek()
    if next_tok in ('><', '<>'):
        op = ts.consume()
        high_tok = ts.consume()
        low = _port_val(val_tok)
        high = _port_val(high_tok)
        return PortSpec(raw=f"{low} {op} {high}", specs=[(op, low, high)])

    val = _port_val(val_tok)
    return PortSpec(raw=val_tok, specs=[('=', val)])


def _port_val(tok: str):
    try:
        return int(tok)
    except ValueError:
        return _named_port(tok)


def _named_port(name: str) -> int:
    known = {
        'http': 80, 'https': 443, 'ssh': 22, 'smtp': 25, 'dns': 53,
        'ftp': 21, 'telnet': 23, 'pop3': 110, 'imap': 143,
        'ntp': 123, 'snmp': 161, 'nntp': 119,
    }
    return known.get(name.lower(), name)  # return name if unknown


# ---------------------------------------------------------------------------
# Per-keyword parsers
# ---------------------------------------------------------------------------

def _parse_option(tokens: list[str], line_num: int) -> Option:
    # set block-policy drop
    # set loginterface $ext
    # set skip on { lo0 }
    # set optimization aggressive
    # set fingerprints "/etc/pf.os"
    ts = TokenStream(tokens)
    ts.expect('set')
    name = ts.consume()
    value = ts.rest_as_str()
    return Option(name=name, value=value, line_num=line_num)


def _parse_scrub(tokens: list[str], line_num: int, raw: str) -> ScrubRule:
    ts = TokenStream(tokens)
    ts.expect('scrub')

    direction = ""
    af = AddressFamily.ANY
    iface = None

    if ts.peek() in ('in', 'out'):
        direction = ts.consume()
    if ts.consume_if('on'):
        iface = ts.consume()
    if ts.peek() in ('inet', 'inet6'):
        af_tok = ts.consume()
        af = AddressFamily.INET if af_tok == 'inet' else AddressFamily.INET6

    opts = ts.rest_as_str()
    return ScrubRule(direction=direction, interface=iface,
                     address_family=af, options=opts,
                     raw_text=raw, line_num=line_num)


def _parse_table(tokens: list[str], line_num: int) -> Table:
    ts = TokenStream(tokens)
    ts.expect('table')

    name_tok = ts.consume()
    if name_tok.startswith('<') and name_tok.endswith('>'):
        name = name_tok[1:-1]
    else:
        name = name_tok

    flags: list[str] = []
    addrs: list[str] = []
    file_paths: list[str] = []

    while not ts.at_end():
        tok = ts.consume()
        tok_l = tok.lower()
        if tok_l in ('persist', 'const', 'counters'):
            flags.append(tok_l)
        elif tok_l == 'file':
            fp = ts.consume().strip('"')
            file_paths.append(fp)
        elif tok == '{':
            while ts.peek() and ts.peek() != '}':
                item = ts.consume()
                if item != ',':
                    addrs.append(item)
            if ts.peek() == '}':
                ts.consume()

    return Table(name=name, flags=flags, addrs=addrs,
                 file_paths=file_paths, line_num=line_num)


def _parse_nat(tokens: list[str], line_num: int, raw: str) -> NatRule | None:
    ts = TokenStream(tokens)
    ts.expect('nat')

    # nat-anchor handled elsewhere
    if ts.peek() and ts.peek().lower() == 'on':
        ts.consume()
        iface = ts.consume()
    else:
        iface = None

    af = AddressFamily.ANY
    if ts.peek() in ('inet', 'inet6'):
        af_tok = ts.consume()
        af = AddressFamily.INET if af_tok == 'inet' else AddressFamily.INET6

    # proto (optional)
    if ts.peek() and ts.peek().lower() == 'proto':
        ts.consume()
        _consume_list(ts)  # discard

    src = AddressSpec(raw="any", is_any=True)
    dst = AddressSpec(raw="any", is_any=True)

    if ts.consume_if('from'):
        src = _parse_address_spec(ts)
        if ts.consume_if('port'):
            _parse_port_spec(ts)  # discard for NAT src port

    if ts.consume_if('to'):
        dst = _parse_address_spec(ts)
        if ts.consume_if('port'):
            _parse_port_spec(ts)

    # -> redirect target
    redirect_to = AddressSpec(raw="any", is_any=True)
    redirect_port: PortSpec | None = None

    if ts.consume_if('->'):
        redirect_to = _parse_address_spec(ts)
        if ts.consume_if('port'):
            redirect_port = _parse_port_spec(ts)

    return NatRule(interface=iface, address_family=af,
                   src=src, dst=dst,
                   redirect_to=redirect_to,
                   redirect_port=redirect_port,
                   raw_text=raw, line_num=line_num)


def _parse_rdr(tokens: list[str], line_num: int, raw: str) -> RdrRule | None:
    ts = TokenStream(tokens)
    ts.expect('rdr')

    iface = None
    if ts.consume_if('on'):
        iface = ts.consume()

    af = AddressFamily.ANY
    if ts.peek() in ('inet', 'inet6'):
        af_tok = ts.consume()
        af = AddressFamily.INET if af_tok == 'inet' else AddressFamily.INET6

    protos: list[str] = []
    if ts.consume_if('proto'):
        protos = _consume_list(ts)

    src = AddressSpec(raw="any", is_any=True)
    dst = AddressSpec(raw="any", is_any=True)
    src_port: PortSpec | None = None
    dst_port: PortSpec | None = None

    if ts.consume_if('from'):
        src = _parse_address_spec(ts)
        if ts.consume_if('port'):
            src_port = _parse_port_spec(ts)

    if ts.consume_if('to'):
        dst = _parse_address_spec(ts)
        if ts.consume_if('port'):
            dst_port = _parse_port_spec(ts)

    redirect_to = AddressSpec(raw="any", is_any=True)
    redirect_port: PortSpec | None = None

    if ts.consume_if('->'):
        redirect_to = _parse_address_spec(ts)
        if ts.consume_if('port'):
            redirect_port = _parse_port_spec(ts)

    return RdrRule(interface=iface, address_family=af,
                   proto=protos, src=src, dst=dst,
                   redirect_to=redirect_to,
                   redirect_port=redirect_port,
                   raw_text=raw, line_num=line_num)


def _parse_anchor(tokens: list[str], line_num: int, raw: str) -> Anchor:
    ts = TokenStream(tokens)
    anchor_type = ts.consume().lower()
    name = ts.rest_as_str().strip('"')
    return Anchor(anchor_type=anchor_type, name=name,
                  raw_text=raw, line_num=line_num)


def _parse_filter(tokens: list[str], line_num: int, raw: str) -> list[FilterRule]:
    """Parse a filter rule, expanding lists into multiple rules."""
    ts = TokenStream(tokens)

    action_tok = ts.consume().lower()
    action = Action.PASS if action_tok == 'pass' else Action.BLOCK

    direction = Direction.ANY
    if ts.peek() in ('in', 'out'):
        direction = Direction.IN if ts.consume() == 'in' else Direction.OUT

    log = False
    quick = False
    iface: str | None = None
    af = AddressFamily.ANY
    proto: str | None = None
    src = AddressSpec(raw="any", is_any=True)
    src_port: PortSpec | None = None
    dst = AddressSpec(raw="any", is_any=True)
    dst_port: PortSpec | None = None
    icmp_types: list[str] = []
    flags: str | None = None
    state: str | None = None
    state_opts = ""

    while not ts.at_end():
        tok = ts.peek()
        if tok is None:
            break
        tok_l = tok.lower()

        if tok_l == 'log':
            ts.consume()
            log = True
            if ts.peek() == '(':
                # consume log options
                depth = 0
                while not ts.at_end():
                    t = ts.consume()
                    if t == '(':
                        depth += 1
                    elif t == ')':
                        depth -= 1
                        if depth == 0:
                            break
        elif tok_l == 'quick':
            ts.consume()
            quick = True
        elif tok_l == 'on':
            ts.consume()
            iface = ts.consume()
        elif tok_l in ('inet', 'inet6'):
            ts.consume()
            af = AddressFamily.INET if tok_l == 'inet' else AddressFamily.INET6
        elif tok_l == 'proto':
            ts.consume()
            protos = _consume_list(ts)
            proto = protos[0] if len(protos) == 1 else "|".join(protos)
        elif tok_l == 'from':
            ts.consume()
            src = _parse_address_spec(ts)
            if ts.peek() and ts.peek().lower() == 'port':
                ts.consume()
                src_port = _parse_port_spec(ts)
        elif tok_l == 'to':
            ts.consume()
            dst = _parse_address_spec(ts)
            if ts.peek() and ts.peek().lower() == 'port':
                ts.consume()
                dst_port = _parse_port_spec(ts)
        elif tok_l == 'all':
            ts.consume()
            src = AddressSpec(raw="any", is_any=True)
            dst = AddressSpec(raw="any", is_any=True)
        elif tok_l == 'flags':
            ts.consume()
            flag_part = ts.consume()
            # flags S/SA — the / may or may not be a separate token
            if ts.peek() and ts.peek().startswith('/'):
                flag_part += ts.consume()
            elif '/' not in flag_part and ts.peek():
                # next token might be the denominator if it looks like SA, A, etc.
                nxt = ts.peek()
                if nxt and re.match(r'^[FSRPAUEW/]+$', nxt):
                    flag_part += ts.consume()
            flags = flag_part
        elif tok_l == 'icmp-type':
            ts.consume()
            icmp_types = _consume_list(ts)
        elif tok_l == 'icmp6-type':
            ts.consume()
            icmp_types = _consume_list(ts)
        elif tok_l in ('keep', 'modulate', 'synproxy'):
            state = tok_l
            ts.consume()
            if ts.peek() and ts.peek().lower() == 'state':
                ts.consume()
            # optional state options in parens
            if ts.peek() == '(':
                depth = 0
                opts_toks = []
                while not ts.at_end():
                    t = ts.consume()
                    opts_toks.append(t)
                    if t == '(':
                        depth += 1
                    elif t == ')':
                        depth -= 1
                        if depth == 0:
                            break
                state_opts = " ".join(opts_toks)
        elif tok_l == 'state':
            ts.consume()
        elif tok_l == 'no':
            ts.consume()
            if ts.peek() and ts.peek().lower() == 'state':
                ts.consume()
                state = 'no'
        elif tok_l == 'label':
            ts.consume()
            ts.consume()  # label string
        elif tok_l == 'tag':
            ts.consume()
            ts.consume()  # tag value
        elif tok_l == 'tagged':
            ts.consume()
            ts.consume()
        elif tok_l == 'queue':
            ts.consume()
            _consume_list(ts)
        elif tok_l == 'os':
            ts.consume()
            ts.consume()
        elif tok_l == 'tos':
            ts.consume()
            ts.consume()
        elif tok_l == 'set':
            ts.consume()
            ts.consume()  # option name
            ts.consume()  # option value
        elif tok_l == 'with':
            ts.consume()
            ts.consume()
        elif tok_l == 'fragment':
            ts.consume()
        elif tok_l == 'allow-opts':
            ts.consume()
        elif tok_l == 'once':
            ts.consume()
        elif tok_l == 'divert-to':
            ts.consume()
            ts.consume()
            if ts.consume_if('port'):
                ts.consume()
        elif tok_l == 'prio':
            ts.consume()
            ts.consume()
        else:
            # Unknown token — skip it
            ts.consume()

    # Build base rule
    base = FilterRule(
        action=action,
        direction=direction,
        quick=quick,
        log=log,
        interface=iface,
        address_family=af,
        proto=proto,
        src=src,
        src_port=src_port,
        dst=dst,
        dst_port=dst_port,
        icmp_types=icmp_types,
        flags=flags,
        state=state,
        state_opts=state_opts,
        raw_text=raw,
        line_num=line_num,
    )

    # Expand multi-proto into separate rules
    return _expand_proto(base)


def _expand_proto(rule: FilterRule) -> list[FilterRule]:
    """If proto is 'tcp|udp|icmp', expand into separate rules."""
    if rule.proto and '|' in rule.proto:
        protos = rule.proto.split('|')
        rules = []
        for p in protos:
            import copy
            r = copy.copy(rule)
            r.proto = p.strip()
            rules.append(r)
        return rules
    return [rule]


# ---------------------------------------------------------------------------
# List consumption helper
# ---------------------------------------------------------------------------

def _consume_list(ts: TokenStream) -> list[str]:
    """
    Consume a list token: either a single token or a brace-delimited list.
    Returns list of items.
    """
    items = []
    if ts.peek() == '{':
        ts.consume()
        while ts.peek() and ts.peek() != '}':
            tok = ts.consume()
            if tok != ',':
                items.append(tok)
        if ts.peek() == '}':
            ts.consume()
    elif ts.peek() is not None:
        items.append(ts.consume())
    return items
