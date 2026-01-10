from __future__ import annotations

import html
import re
from typing import Iterable, Iterator

# * Precompiled regexes (faster at runtime)
BR_REGEX = re.compile(
    r"(?:<\s*br\s*/?\s*>|</\s*p\s*>|</\s*div\s*>|<\s*li\s*>)", re.IGNORECASE
)
TAG_REGEX = re.compile(r"<[^>]+>")
WS_REGEX = re.compile(r"\s+")

__all__ = [
    "visible_len",
    "strip_html",
    "collapse_ws",
    "chunks",
    "normalize_newlines",
    "unescape_entities",
    "safe_truncate",
    "pattern_has_backspace",
]


def strip_html(s: str, /, *, preserve_breaks: bool = False) -> str:
    """
    * Remove simple HTML tags; not a sanitizer — just for visibility estimates.
    - When preserve_breaks=True, convert <br>, </p>, </div>, and <li> into a single space
      before stripping tags to maintain word boundaries.
    """
    if not s:
        return ""
    text = s
    if preserve_breaks:
        text = BR_REGEX.sub(" ", text)
    # strip remaining tags
    return TAG_REGEX.sub("", text)


def normalize_newlines(s: str) -> str:
    """* Convert CRLF/CR to LF for consistent processing."""
    if not s:
        return ""
    return s.replace("\r\n", "\n").replace("\r", "\n")


def unescape_entities(s: str) -> str:
    """* HTML entity → Unicode (single pass)."""
    return html.unescape(s or "")


def collapse_ws(s: str) -> str:
    """
    * Collapse runs of whitespace to a single space and trim ends.
    """
    return WS_REGEX.sub(" ", (s or "")).strip()


def pattern_has_backspace(pattern: str) -> bool:
    """Return True if a regex pattern contains the BACKSPACE control char (\x08).

    Why this exists:
    - In JSON, the escape sequence `\b` is a *backspace* character, not a regex word-boundary.
    - If a rule file includes `"\b"` it will parse into `\x08` and the regex will not behave as intended.

    Use this to warn in logs when a pattern is likely corrupted.
    """
    if not pattern:
        return False
    try:
        return "\x08" in pattern
    except Exception:
        return False


def visible_len(s: str, *, count_spaces: bool = True) -> int:
    """
    * Heuristic 'visible' character count used by deletion guards.
    - Pipeline: normalize_newlines → strip_html(preserve_breaks=True) → unescape_entities
    - If count_spaces=False, remove all whitespace before counting
    """
    if not s:
        return 0
    text = normalize_newlines(s)
    text = strip_html(text, preserve_breaks=True)
    text = unescape_entities(text)
    if not count_spaces:
        text = WS_REGEX.sub("", text)
    return len(text)


def safe_truncate(s: str, max_chars: int, /, *, count_spaces: bool = True) -> str:
    """
    * Truncate by *visible* characters while returning a prefix of the ORIGINAL string.
    - Useful for logs/previews where we want real text, not stripped text.
    """
    if max_chars <= 0 or not s:
        return s or ""
    # Fast path: compute visible length once; if within limit, return as-is.
    if visible_len(s, count_spaces=count_spaces) <= max_chars:
        return s
    # Slow path: expand a sliding window until the visible count exceeds the limit.
    # Binary search could be added if needed; linear is fine for short log snippets.
    lo, hi = 0, len(s)
    while lo < hi:
        mid = (lo + hi) // 2
        if visible_len(s[:mid], count_spaces=count_spaces) < max_chars:
            lo = mid + 1
        else:
            hi = mid
    # Ensure we don't exceed the target by one char
    out = s[: max(lo - 1, 0)]
    return out


def chunks(iterable: Iterable, size: int) -> Iterator[list]:
    """
    * Yield lists of at most `size` items from `iterable`.
    """
    buf: list = []
    for item in iterable:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf
