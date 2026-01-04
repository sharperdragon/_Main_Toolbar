from __future__ import annotations

# * Standard library
import os
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Pattern
from .data_defs import RunConfig  

__all__ = [
    "TS_FORMAT",
    "DESKTOP_PATH",
    "MODULES_CONFIG_PATH",
    "now_stamp",
    "FIELD_REMOVE_RULES_PATH",
    "load_field_remove_rules",
    "anki_query_escape_controls",
    "md_inline",
    "md_table_cell",
]

TS_FORMAT: str = "%H-%M_%m-%d"  
DESKTOP_PATH: Path = Path("/Users/claytongoddard/Desktop")

# Hard-coded rules path override
RULES_PATH: Path = Path("/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/modules/batch_FR/rules")
MODULES_CONFIG_PATH: Path = Path("/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/modules/modules_config.json")

# Path to the global field remove rules file
FIELD_REMOVE_RULES_PATH: Path = Path(RULES_PATH) / "field_remove_rules.txt"


def _coerce_int(val, fallback: int) -> int:
    try:
        return int(val)
    except Exception:
        return fallback

def _norm_path(p: str | None) -> Path | None:
    if not p:
        return None
    try:
        return Path(os.path.expanduser(p)).resolve()
    except Exception:
        return None

def now_stamp() -> str:
    return datetime.now().strftime(TS_FORMAT)


# * Field remove rules helpers

def load_field_remove_rules(path: Optional[Path] = None) -> List[Pattern[str]]:
    import re
    if path is None:
        path = FIELD_REMOVE_RULES_PATH
    patterns: List[Pattern[str]] = []
    try:
        rules_path = Path(path)
    except TypeError:
        rules_path = FIELD_REMOVE_RULES_PATH
    if not rules_path.exists():
        return patterns
    with rules_path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                patterns.append(re.compile(line))
            except re.error:
                continue

    return patterns


# * Anki Browser query helpers

def anki_query_escape_controls(val: Any) -> str:
    """Return a query-safe string for Anki Browser/find_notes.

    Ensures *literal* control characters never appear in the returned string.
    This prevents multi-line/ambiguous Browser queries (e.g., a regex like `\n+`
    accidentally becoming a real newline).

    Rules:
    - CRLF/CR -> `\\n`
    - LF -> `\\n`
    - TAB -> `\\t`

    NOTE: This is NOT markdown-specific. It intentionally does not escape pipes
    or backticks; use `md_inline/md_table_cell` for log rendering.
    """
    s = "" if val is None else str(val)
    if not s:
        return s

    # Normalize line endings first
    s = s.replace("\r\n", "\n").replace("\r", "\n")

    # Make control characters visible (query-safe)
    s = s.replace("\n", r"\\n")
    s = s.replace("\t", r"\\t")

    return s


# * Markdown-safe display helpers (debug logs)

def _escape_control_chars(s: str) -> str:
    """Make control characters visible (for log readability + copy/paste)."""
    if not s:
        return s
    # Normalize and make visible
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\n", r"\\n")
    s = s.replace("\t", r"\\t")
    return s


def md_inline(val: Any) -> str:
    """Return a markdown-inline-safe string (for use inside backticks).

    - Converts real newlines/tabs to visible sequences (\\n, \\t)
    - Escapes pipes so tables aren't accidentally broken
    - Avoids raw backticks breaking inline-code formatting
    """
    s = "" if val is None else str(val)
    s = _escape_control_chars(s)

    # Escape table pipes (even outside tables, it's harmless)
    s = s.replace("|", r"\\|")

    # Avoid breaking markdown inline code with backticks
    s = s.replace("`", "ˋ")

    return s


def md_table_cell(val: Any) -> str:
    """Return a markdown-table-safe cell string.

    Same as md_inline, but also guarantees no literal newlines (tables break easily).
    """
    s = md_inline(val)
    # Ensure absolutely no real newlines remain
    s = s.replace("\n", r"\\n")
    return s
