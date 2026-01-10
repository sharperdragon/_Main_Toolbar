from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple, Union, Set
import re

from .text_utils import visible_len


# =========================
# Regex helpers (compile, flags, validation, guards)
# =========================
# ! All pattern/flags/replacement logic lives here (no I/O, no Anki).

__all__ = [
    "apply_rule_defaults",
    "validate_regex_replacement",
    "flags_from_str",
    "compile_pattern",
    "apply_substitution",
    "apply_rule_to_text",
    "deletion_exceeds_limit",
    "basic_html_cloze_balance_ok",
    "ensure_dir",
    "ensure_parent",
]

# =========================
# Anki Browser regex helpers (lightweight, best-effort)
# =========================
# ! Anki's Browser search supports only a small set of escaped characters.
# ! Anything else (like \w, \s, \d, \{, \}) tends to raise
# ! "the escape sequence `\x` is not defined" at search time.


ANKI_ALLOWED_ESCAPES = set(r'\\":*_()')


def compiled_can_match_empty(patt: str, flags: Union[str, int, None]) -> bool:
    """Return True if the regex pattern can match the empty string."""
    try:
        rx = re.compile(patt, flags_from_str(flags))
        return rx.search("") is not None
    except Exception:
        return False


def _apply_patterns_loop_safe(
    *,
    patterns: List[str],
    repl: str,
    text: str,
    is_regex: bool,
    flags: Union[str, int, None],
    loops_cap: int,
) -> Tuple[str, int, int, str, bool]:
    """Apply the rule's pattern list with deterministic looping.

    A "loop" here means: apply ALL patterns once (in order) = 1 pass.

    Break conditions:
    - 0 substitutions in a pass OR no net change -> stable
    - output repeats a prior state -> cycle
    - pass cap reached -> cap

    Returns:
      (final_text, total_subs, passes_used, break_reason, empty_match_forced_single)
    where break_reason in {'stable','cycle','cap'}.
    """
    if loops_cap < 1:
        loops_cap = 1

    empty_match_forced_single = False

    # If looping is enabled and ANY pattern can match empty, force single-pass.
    # Empty-matchable regexes are a classic source of runaway looping.
    if is_regex and loops_cap > 1:
        try:
            for p in patterns:
                if compiled_can_match_empty(p, flags if flags is not None else "m"):
                    empty_match_forced_single = True
                    loops_cap = 1
                    break
        except Exception:
            pass

    working = text
    total_subs = 0
    passes_used = 0
    seen: Set[str] = {working}

    for _ in range(loops_cap):
        before_pass = working
        pass_subs = 0

        # One pass: apply each pattern exactly once.
        for p in patterns:
            working, subs, _ignored = apply_substitution(
                p,
                repl,
                working,
                is_regex=is_regex,
                flags=flags,
                max_loops=1,
            )
            if subs:
                pass_subs += subs

        passes_used += 1
        if pass_subs:
            total_subs += pass_subs

        # Stable: no subs or no net change.
        if pass_subs == 0 or working == before_pass:
            return working, total_subs, passes_used, "stable", empty_match_forced_single

        # Cycle guard: output repeats prior state.
        if working in seen:
            return working, total_subs, passes_used, "cycle", empty_match_forced_single
        seen.add(working)

    return working, total_subs, passes_used, "cap", empty_match_forced_single


def find_anki_unsupported_escapes(pattern: str) -> List[str]:
    """Return a list of escape sequences that are likely invalid in Anki Browser regex.

    Example: '\\w foo \\s' -> ['\\w', '\\s']
    """
    if not pattern:
        return []
    bad: List[str] = []
    for m in re.finditer(r"\\(.)", pattern):
        ch = m.group(1)
        if ch not in ANKI_ALLOWED_ESCAPES:
            bad.append("\\" + ch)
    # Deduplicate while preserving order
    seen: set[str] = set()
    uniq: List[str] = []
    for esc in bad:
        if esc not in seen:
            uniq.append(esc)
            seen.add(esc)
    return uniq


def validate_anki_search_string(search: str) -> Tuple[bool, str]:
    s = (search or "").strip()
    if not s:
        return True, "ok"

    # Simple case: whole query is a regex search.
    if s.startswith("re:"):
        pattern = s[3:]
        bad = find_anki_unsupported_escapes(pattern)
        if bad:
            return False, f"Anki Browser regex likely invalid; unsupported escapes: {', '.join(bad)}"
        return True, "ok"

    # More complex multi-clause queries (deck:, tag:, etc.) are passed through for now.
    return True, "ok"

# =========================
# Defaults + simple helpers
# =========================

def apply_rule_defaults(r: Dict[str, Any]) -> Dict[str, Any]:
    """
    * Ensure required rule keys exist; do NOT clobber explicit values.
    - This is light-touch; deeper normalization happens in rules_io.normalize_rule.
    """
    out = dict(r)
    out.setdefault("regex", True)
    out.setdefault("flags", "m")
    out.setdefault("fields", ["ALL"])  # engine expands later
    out.setdefault("loop", False)

    # ! Safety: always coerce delete_chars into a well-formed dict
    dc = out.get("delete_chars", {})
    if not isinstance(dc, dict):
        dc = {}
    out["delete_chars"] = {
        "max_chars": int(dc.get("max_chars", 0) or 0),
        "count_spaces": bool(dc.get("count_spaces", True)),
    }
    return out


def flags_from_str(flags: Union[str, int, None]) -> int:
    """
    * Convert 'imsx' into re flags; if already int, return as-is.
    - Unknown chars are ignored. Order is irrelevant for bitwise flags.
    """
    if isinstance(flags, int):
        return flags
    fbits = 0
    for ch in str(flags or "").lower():
        if ch == "i":
            fbits |= re.IGNORECASE
        elif ch == "m":
            fbits |= re.MULTILINE
        elif ch == "s":
            fbits |= re.DOTALL
        elif ch == "x":
            fbits |= re.VERBOSE
    return fbits


def compile_pattern(pattern: str, flags: Union[str, int, None]) -> re.Pattern:
    """
    * Compile a regex using our canonical flag parser.
    - Callers decide whether pattern is regex vs literal; we assume regex here.
    """
    return re.compile(pattern, flags_from_str(flags))


# =========================
# Validation + substitution
# =========================

def _coerce_repl_for_python(raw: str, is_regex: bool) -> str:
    """
    * Translate Rust/PCRE-style $1, $2, ... replacement syntax into Python-compatible form.
    - Only applies when the rule is regex-based; literal replacements are returned unchanged.
    - Handles $$ as a literal dollar.
    """
    if not is_regex or not raw:
        return raw

    s = raw
    # Use a placeholder for literal $$ to avoid treating them as group backrefs.
    placeholder = "\uFFFF"
    s = s.replace("$$", placeholder)

    # Convert $1, $2, ... into \g<1>, \g<2>, ... for Python's re.sub semantics.
    def _num_backref(m: re.Match) -> str:
        return r"\g<%s>" % m.group(1)

    s = re.sub(r"\$(\d+)", _num_backref, s)

    # Restore literal dollars
    s = s.replace(placeholder, "$")
    return s


def validate_regex_replacement(
    patterns: Union[str, List[str]],
    replacement: str,
    flags: Union[str, int, None] = None,
) -> Tuple[bool, str]:
    """
    * Try compiling each pattern and running a dry sub on a trivial string.
    - Return (ok, message). On failure, message contains the reason.
    - Catches common backref issues early.

    Note: this does not auto-escape invalid patterns. The engine uses the
    boolean result to decide which rules to skip and report as invalid.
    """
    pats = [patterns] if isinstance(patterns, str) else list(patterns or [])
    if not pats:
        return True, "ok"

    # Coerce Rust/PCRE-style $1, $2, ... into a Python-compatible replacement
    repl_for_py = _coerce_repl_for_python(replacement, is_regex=True)

    test = "_abcDEF123_\n"
    for p in pats:
        try:
            rx = re.compile(p, flags_from_str(flags))
            _ = rx.sub(repl_for_py, test)
        except Exception as e:
            return False, f"pattern={p!r}: {e}"
    return True, "ok"


def subn_until_stable(
    pattern: str,
    replacement: str,
    text: str,
    *,
    flags: Union[str, int, None] = None,
    max_loops: int = 30,
) -> Tuple[str, int, int]:
    total = 0
    loops = 0
    current = text
    rx = compile_pattern(pattern, flags)
    while loops < max_loops:
        new, n = rx.subn(replacement, current)
        total += n
        loops += 1
        if n == 0 or new == current:
            break
        current = new
    return current, total, loops


# =========================
# Literal substitution helper
# =========================

def subn_literal_until_stable(
    find: str,
    replacement: str,
    text: str,
    *,
    max_loops: int = 30,
) -> Tuple[str, int, int]:
    if not find:
        return text, 0, 0
    total = 0
    loops = 0
    current = text
    while loops < max_loops:
        n = current.count(find)
        if n == 0:
            break
        current = current.replace(find, replacement)
        total += n
        loops += 1
    return current, total, loops


# =========================
# Unified apply helper (regex vs literal)
# =========================

def apply_substitution(
    pattern_or_find: str,
    replacement: str,
    text: str,
    *,
    is_regex: bool = True,
    flags: Union[str, int, None] = None,
    max_loops: int = 30,
) -> Tuple[str, int, int]:
    if is_regex:
        return subn_until_stable(pattern_or_find, replacement, text, flags=flags, max_loops=max_loops)
    return subn_literal_until_stable(pattern_or_find, replacement, text, max_loops=max_loops)


def apply_rule_to_text(
    *,
    patterns: Union[str, List[str]],
    replacement: str,
    text: str,
    is_regex: bool,
    flags: Union[str, int, None],
    loop: bool,
    loops_cap: int,
) -> Tuple[str, Dict[str, Any]]:
    """Single engine-facing API to apply one rule to one text string.

    Returns:
      (new_text, meta)

    Meta fields are chosen to match engine.py accounting:
      - subs_total: int
      - passes_used: int
      - break_reason: 'stable'|'cycle'|'cap'
      - empty_match_forced_single: bool
    """
    pats = [patterns] if isinstance(patterns, str) else list(patterns or [])
    pats = [p for p in pats if str(p).strip()]
    if not pats:
        return text, {
            "subs_total": 0,
            "passes_used": 0,
            "break_reason": "stable",
            "empty_match_forced_single": False,
        }

    repl_for_py = _coerce_repl_for_python(replacement, is_regex=is_regex)

    cap = int(loops_cap or 1)
    if not loop:
        cap = 1

    new_text, subs_total, passes_used, break_reason, forced_single = _apply_patterns_loop_safe(
        patterns=pats,
        repl=repl_for_py,
        text=text,
        is_regex=is_regex,
        flags=flags,
        loops_cap=cap,
    )

    meta = {
        "subs_total": int(subs_total),
        "passes_used": int(passes_used),
        "break_reason": str(break_reason),
        "empty_match_forced_single": bool(forced_single),
    }
    return new_text, meta


# =========================
# Deletion guards
# =========================

# ! Safety: this is the only place we decide if a rule deletes "too much" text.

def deletion_exceeds_limit(
    before: str,
    after: str,
    max_chars: int,
    *,
    count_spaces: bool = True,
) -> Tuple[bool, int]:
    """
    * Compare 'visible' char counts; return (exceeded, deleted_count).
    - Uses text_utils.visible_len so the policy is consistent across the add-on.
    """
    if max_chars <= 0:
        return (False, 0)
    v_before = visible_len(before, count_spaces=count_spaces)
    v_after = visible_len(after, count_spaces=count_spaces)
    deleted = max(0, v_before - v_after)
    return (deleted > max_chars, deleted)


def basic_html_cloze_balance_ok(before: str, after: str) -> bool:
    if before == after:
        return True

    def counts(s: str) -> Dict[str, int]:
        return {
            "open_cloze": s.count("{{"),
            "close_cloze": s.count("}}"),
        }

    cb = counts(before)
    ca = counts(after)

    # If clozes were balanced before, require the same counts and balance after.
    if cb["open_cloze"] == cb["close_cloze"]:
        if (
            ca["open_cloze"] != ca["close_cloze"]
            or ca["open_cloze"] != cb["open_cloze"]
            or ca["close_cloze"] != cb["close_cloze"]
        ):
            return False

    return True


# =========================
# File-system helpers (for logs/reports) — small, isolated
# =========================

def ensure_dir(path: Union[str, Path]) -> Path:
    """* Ensure a directory exists; return its resolved Path."""
    p = Path(path).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def ensure_parent(path: Union[str, Path]) -> Path:
    """* Ensure the parent directory of a file exists; return the file path."""
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p