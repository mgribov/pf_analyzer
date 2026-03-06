class PfAnalyzerError(Exception):
    """Base exception for pf_analyzer."""


class ParseError(PfAnalyzerError):
    """Raised when the parser cannot understand a pf.conf construct."""

    def __init__(self, message: str, line_num: int | None = None):
        self.line_num = line_num
        prefix = f"[line {line_num}] " if line_num is not None else ""
        super().__init__(f"{prefix}{message}")


class MacroExpansionError(PfAnalyzerError):
    """Raised when a macro reference cannot be resolved."""

    def __init__(self, name: str, line_num: int | None = None):
        self.name = name
        self.line_num = line_num
        prefix = f"[line {line_num}] " if line_num is not None else ""
        super().__init__(f"{prefix}Undefined macro: ${name}")


class TraceError(PfAnalyzerError):
    """Raised when a packet trace cannot proceed."""
