"""Lexer: strip comments, join continuations, return (line_num, text) pairs."""

from __future__ import annotations


def lex(source: str) -> list[tuple[int, str]]:
    """
    Preprocess pf.conf source text.

    Returns a list of (original_line_num, cleaned_text) tuples, one per
    logical line (after joining backslash continuations).  Comment-only
    lines and blank lines are omitted.
    """
    raw_lines = source.splitlines()
    result: list[tuple[int, str]] = []

    i = 0
    while i < len(raw_lines):
        line_num = i + 1  # 1-based
        line = raw_lines[i]

        # Strip inline comment (# not inside a quoted string)
        line = _strip_comment(line)

        # Join continuation lines
        while line.rstrip().endswith("\\"):
            line = line.rstrip()[:-1]  # remove trailing backslash
            i += 1
            if i < len(raw_lines):
                cont = _strip_comment(raw_lines[i])
                line = line + " " + cont.strip()

        line = line.strip()
        if line:
            result.append((line_num, line))

        i += 1

    return result


def _strip_comment(line: str) -> str:
    """Remove everything from # to end of line, respecting quoted strings."""
    in_quote = False
    out: list[str] = []
    j = 0
    while j < len(line):
        ch = line[j]
        if ch == '"' and not in_quote:
            in_quote = True
            out.append(ch)
        elif ch == '"' and in_quote:
            in_quote = False
            out.append(ch)
        elif ch == '#' and not in_quote:
            break
        else:
            out.append(ch)
        j += 1
    return "".join(out)


def tokenize(text: str) -> list[str]:
    """
    Split a preprocessed line into tokens.

    Preserves:
      - <tablename>      as a single token
      - ($iface)         as a single token
      - ($iface:0)       as a single token
      - "quoted string"  as a single token
      - {, }, ,          as individual tokens
    """
    import re
    pattern = re.compile(
        r'"[^"]*"'            # quoted string
        r'|\(\$?[^)]*\)'      # ($iface), ($iface:0), or (iface) after macro expansion
        r'|<[^>]+>'           # <table>
        r'|->'                # redirect arrow (must come before plain token)
        r'|><'                # exclusive range operator
        r'|<>'                # inclusive range operator
        r'|>='                # >= port operator
        r'|<='                # <= port operator
        r'|\{'                # open brace
        r'|\}'                # close brace
        r'|,'                 # comma
        r'|[^\s{},<>(">]+'   # plain token (no < > { } , ( " whitespace)
    )
    return pattern.findall(text)
