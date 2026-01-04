# anki_query_utils.py

"""Utilities for building Anki Browser search strings.

This module is intentionally *Anki-search-layer* aware (not Python regex-layer aware).

Key concept:
- When we embed a regex pattern in an Anki search query via `re:...`, the Anki search parser
  consumes backslashes first.
- Therefore, regex backslashes must be doubled (e.g., `\w` becomes `\\w` in the query string)
  so that the regex engine ultimately receives the intended escapes.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Union

from .data_defs import Rule


def sanitize_clause(s: str) -> str:
    """Sanitize a query clause for safe inclusion in Anki search.

    We avoid literal newlines/tabs because they can confuse Anki search parsing/logging.
    Keep this conservative: convert CRLF/CR to LF, then replace LF/TAB with visible sequences.
    """
    if not s:
        return s
    s = str(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\n", r"\\n")
    s = s.replace("\t", r"\\t")
    return s.strip()


def escape_for_anki_re(pat: str) -> str:
    """Escape a Python-regex pattern for use inside an Anki `re:` search clause.

    Anki's search parser treats backslashes as escape characters *before* the regex engine.
    To ensure the regex engine receives a single backslash, we must double them here.

    Example:
        pattern r"\w+" -> query "re:\\w+" (string contains two backslashes)
    """
    if not pat:
        return pat
    # Critical: double escapes for the Anki search parser layer
    return pat.replace("\\", "\\\\")


def _as_list(x: Union[str, Sequence[str], None]) -> List[str]:
    """Normalize string/list/None into a cleaned list of non-empty strings."""
    if x is None:
        return []
    if isinstance(x, str):
        s = x.strip()
        return [s] if s else []
    out: List[str] = []
    for v in x:
        sv = str(v).strip()
        if sv:
            out.append(sv)
    return out


def _pattern_of(rule: Rule) -> str:
    """Return the primary pattern string for a rule."""
    if isinstance(rule.pattern, list):
        for p in rule.pattern:
            ps = str(p).strip()
            if ps:
                return ps
        return ""
    return str(rule.pattern).strip() if rule.pattern is not None else ""


def _looks_already_escaped_for_anki_re(pat: str) -> bool:
    """Heuristic: if pattern already contains a double backslash sequence, assume already escaped."""
    return "\\\\" in pat


def _split_re_clause(clause: str) -> tuple[Optional[str], Optional[str]]:
    """Split a clause into (prefix, pattern) if it contains an Anki `re:` segment.

    Supports:
      - `re:<pat>`
      - `<field>:re:<pat>`

    Returns (prefix, pat) where prefix is None for bare `re:` clauses.
    Returns (None, None) if the clause is not an `re:` clause.

    Note: detection is case-insensitive, but we always rebuild using lowercase `re:`.
    """
    c = clause.strip()
    if not c:
        return None, None

    lc = c.lower()

    # Bare re:
    if lc.startswith("re:"):
        return None, c[3:]

    # Field-scoped <field>:re:
    marker = ":re:"
    idx = lc.find(marker)
    if idx == -1:
        return None, None

    prefix = c[:idx]  # keep original casing
    pat = c[idx + len(marker) :]
    return prefix, pat


def _normalize_explicit_re_clause(clause: str) -> str:
    """Normalize explicit regex clauses so Anki search parser receives valid escapes.

    Handles both:
      - `re:<pat>`
      - `<field>:re:<pat>`

    If it looks already escaped, leave it alone.
    Otherwise, double backslashes in the pattern portion.
    """
    c = clause.strip()
    if not c:
        return c

    prefix, pat = _split_re_clause(c)
    if pat is None:
        return c

    if not pat:
        return c

    if _looks_already_escaped_for_anki_re(pat):
        return c

    escaped = escape_for_anki_re(pat)

    if prefix is None:
        return "re:" + escaped

    # Preserve prefix verbatim; always rebuild with lowercase `re:`
    return f"{prefix}:re:{escaped}"


def _quote_clause(s: str) -> str:
    """Match legacy engine quoting behavior (with field-scoped regex support).

    - Always quote clauses that contain an Anki regex segment (`re:` or `<field>:re:`)
    - Otherwise quote only if whitespace exists
    """
    s = s.strip()
    if not s:
        return s

    # Escape embedded quotes
    s = s.replace('"', r'\"')

    ls = s.lower()
    if ls.startswith("re:") or ":re:" in ls:
        return f'"{s}"'

    if any(ch.isspace() for ch in s):
        return f'"{s}"'

    return s


def effective_query(rule: Rule) -> List[str]:
    """Return include clauses for a rule.

    Matches legacy engine behavior:
    1) If rule.query is provided -> use as-is (no field scoping), but normalize explicit `re:` escapes.
    2) Otherwise derive from rule.pattern, then field-scope only if fields != ALL.
    """
    # 1) Explicit query wins, no field scoping (legacy engine behavior)
    include = _as_list(rule.query)
    if include:
        out: List[str] = []
        for c in include:
            cs = c.strip()
            if not cs:
                continue
            out.append(_normalize_explicit_re_clause(cs))
        return out

    # 2) Derive from pattern
    pat = _pattern_of(rule)
    if not pat:
        return []

    if rule.regex:
        base = f"re:{escape_for_anki_re(pat)}"
    else:
        base = pat.strip()

    # 3) Field scoping ONLY for derived clause
    fields = [str(f).strip() for f in (rule.fields or []) if str(f).strip()]
    if not fields or (len(fields) == 1 and fields[0].upper() == "ALL"):
        return [base]

    return [f"{field}:{base}" for field in fields]


def compose_search(rule: Rule) -> str:
    """Compose the final Anki Browser search string for a rule (legacy engine-compatible)."""
    parts: List[str] = []

    # Includes
    for c in effective_query(rule):
        cs = sanitize_clause(c)
        if cs:
            parts.append(_quote_clause(cs))

    # Excludes (legacy engine behavior: no field scoping)
    for ex in _as_list(rule.exclude_query):
        exs = sanitize_clause(ex)
        if not exs:
            continue
        parts.append(f"-({_quote_clause(exs)})")

    return " ".join(p for p in parts if p).strip()