#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compute_max_delete_chars.py  —  READ-ONLY ANALYZER

Purpose:
    Analyze rule files and print a conservative lower-bound estimate of
    'delete_chars.max_chars' for each rule to the terminal. This script NEVER
    modifies any files.

What it does:
    • Discovers rule files (defaults to the repo's /rules folder) using your
      utils.discover_rule_files helper, filtered by glob patterns that catch
      both '*rule.json' and '*rules.json'.
    • Loads rules via a robust local loader (no direct json.load).
    • Computes deletion caps with a minimal-match regex synthesizer.
    • Prints concise per-rule output and totals.

    Both the new 'delete_chars' object and legacy 'max_delete_chars' are recognized.

CLI:
    Positional: [files ...]         Explicit file paths; if provided, discovery is skipped.
    Options:
        --dir DIR                   Root directory to search for rule files (default: repo /rules)
        --glob PATTERNS             Comma-separated glob(s); default: "*rule.json,*rules.json"
        --rule N                    Only compute & display this 0-based rule index within each file
        --assume-repeat K           Minimal repeat used for '+' and '{m,}' (default: 1)

Examples (zsh):
    python3 utils/compute_max_delete_chars.py
    python3 utils/compute_max_delete_chars.py --dir "/Users/claytongoddard/FR_simple/rules"
    python3 utils/compute_max_delete_chars.py rules/base_rules.json rules/img_rules.json
    python3 utils/compute_max_delete_chars.py --glob "img_*rules.json"
    python3 utils/compute_max_delete_chars.py --rule 0 --assume-repeat 2
"""
from __future__ import annotations
import argparse
import os
import re
import sys, types
import unicodedata
import html
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional



# --- Import project helpers ---------------------------------------------------
# In the add-on build, this script lives under .../modules/batch_FR/
# so the batch_FR folder itself is our local "root" that contains /utils and /rules.
FR_ROOT = Path(__file__).resolve().parent      # .../batch_FR
UTILS_DIR = FR_ROOT / "utils"

# Ensure the repo root is importable
if str(FR_ROOT) not in sys.path:
    sys.path.insert(0, str(FR_ROOT))

# Fallback: make 'utils' behave like a package even if __init__.py is missing
if "utils" not in sys.modules:
    utils_pkg = types.ModuleType("utils")
    utils_pkg.__path__ = [str(UTILS_DIR)]  # namespace package path
    sys.modules["utils"] = utils_pkg

# Try FR_simple-style helpers first; fall back to batch_FR utils.rules_io in add-on build
try:
    from utils.main_utils import _is_rules_json, discover_rule_files  # FR_simple layout
except ModuleNotFoundError:
    from utils.rules_io import discover_rule_files  # batch_FR layout

    # Minimal local filter: treat normal .json/.jsonl (non-backup) files as rules JSON
    def _is_rules_json(path) -> bool:
        p = Path(path)
        if not p.is_file():
            return False
        if p.suffix.lower() not in {".json", ".jsonl"}:
            return False
        if p.name.startswith("."):
            return False
        if any(tag in p.name for tag in ("backup", "bak", "~")):
            return False
        return True

# ------------------------------ Helpers --------------------------------------
REP_MAP_SINGLE = {
    r"\s": " ",
    r"\S": "x",
    r"\d": "1",
    r"\w": "a",
    r".":  "x",
}


def robust_load_rules_from_file(path):
    """
    Robust loader for rules JSON.
    - Accepts str or Path
    - Tries strict JSON parse first
    - On failure, sanitizes common issues (e.g., missing value for 'max_delete_chars' or 'delete_chars')
    - Normalizes per-rule fields for downstream consumers
    Returns: list[dict]
    """
    from pathlib import Path
    import json, re

    p = Path(path)
    text = p.read_text(encoding="utf-8")

    # 1) Strict parse first
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # 2) Sanitize then retry
        cleaned = text.replace("\ufeff", "")  # strip BOM
        # Fill missing values for "max_delete_chars": → null
        cleaned = re.sub(r'("max_delete_chars"\s*:\s*)(?=[,\}\]])', r'\1null', cleaned)
        # Fill missing values for "delete_chars": → null
        cleaned = re.sub(r'("delete_chars"\s*:\s*)(?=[,\}\]])', r'\1null', cleaned)
        # (You can add other targeted fixes here if needed)
        data = json.loads(cleaned)

    # 3) Accept top-level list or {"rules":[...]}
    if not isinstance(data, list):
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            data = data["rules"]
        else:
            raise ValueError(f"{p} did not contain a list of rules")

    # 4) Normalize per-rule fields
    normalized = []
    for r in data:
        if not isinstance(r, dict):
            continue

        # exclude_query → list
        rq = r.get("exclude_query", [])
        if rq is None:
            rq = []
        elif isinstance(rq, str):
            rq = [rq] if rq.strip() else []
        elif not isinstance(rq, list):
            rq = [str(rq)]
        r["exclude_query"] = rq

        # replacement → string
        if r.get("replacement") is None:
            r["replacement"] = ""

        # regex → bool (default False)
        if "regex" not in r or r["regex"] in ("", None):
            r["regex"] = False

        # Infer regex from query "re:" prefix or pattern metacharacters if flag not explicitly true
        if r.get("regex") is not True:
            qtxt = str(r.get("query") or "")
            if qtxt.startswith("re:") or _looks_like_regex_text(str(r.get("pattern") or "")):
                r["regex"] = True

        normalized.append(r)

    return normalized



# Helper to coerce new/legacy delete guard for display, supporting nested normalize dict
def _extract_delete_chars(val) -> Optional[Dict[str, Any]]:
    """Coerce delete guard into {max_chars:int, count_spaces:bool, normalize:dict|None} or None."""
    if val is None:
        return None
    if isinstance(val, int):
        return {"max_chars": int(val), "count_spaces": True, "normalize": None}
    if isinstance(val, dict):
        norm = val.get("normalize")
        if isinstance(norm, dict):
            norm = {
                "unicode": norm.get("unicode"),
                "casefold": bool(norm.get("casefold", False)),
                "collapse_spaces": bool(norm.get("collapse_spaces", False)),
                "trim": bool(norm.get("trim", False)),
            }
        else:
            norm = None
        return {
            "max_chars": int(val.get("max_chars", 0)),
            "count_spaces": bool(val.get("count_spaces", True)),
            "normalize": norm,
        }
    return None


# Helper: Normalize a string for comparison, using normalization options
def _normalize_for_compare(s: str, *, count_spaces: bool, normalize: Optional[Dict[str, Any]]) -> str:
    """
    Apply optional normalization before comparing lengths:
      - Unicode normalization: NFC/NFD/NFKC/NFKD
      - Case fold (unicode-aware)
      - Collapse runs of whitespace to a single space
      - Trim leading/trailing whitespace
      - Finally, if count_spaces is False, remove ASCII space characters
    """
    if s is None:
        s = ""
    # 1) Unicode normalization
    if normalize and normalize.get("unicode"):
        form = str(normalize["unicode"]).upper()
        if form in ("NFC", "NFD", "NFKC", "NFKD"):
            s = unicodedata.normalize(form, s)
    # 2) Case folding
    if normalize and normalize.get("casefold", False):
        s = s.casefold()
    # 3) Collapse whitespace
    if normalize and normalize.get("collapse_spaces", False):
        s = re.sub(r"\s+", " ", s)
    # 4) Trim
    if normalize and normalize.get("trim", False):
        s = s.strip()
    # 5) Respect count_spaces
    if not count_spaces:
        s = s.replace(" ", "")
    return s


# --- New helper: _to_visible ---
def _to_visible(s: str, *, count_spaces: bool = True, normalize: Optional[Dict[str, Any]] = None) -> str:
    """
    Convert a string to an approximation of 'what the user sees' for length comparison:
      1) HTML entity unescape
      2) Strip simple HTML tags
      3) Unicode normalize (default NFKC if not provided)
      4) Remove zero-width & control chars (Cf/Cc)
      5) Optional casefold/collapse_spaces/trim via normalize dict
      6) Apply count_spaces (if False, drop ASCII spaces)
    """
    if s is None:
        s = ""
    # 1) Unescape entities
    s = html.unescape(s)
    # 2) Strip tags
    s = re.sub(r"<[^>]+>", "", s)
    # 3) Unicode normalize (default NFKC)
    form = "NFKC"
    if normalize and normalize.get("unicode"):
        form = str(normalize["unicode"]).upper()
        if form not in ("NFC", "NFD", "NFKC", "NFKD"):
            form = "NFKC"
    s = unicodedata.normalize(form, s)
    # 4) Remove zero-width & control characters
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cf", "Cc"))
    # 5) Optional casefold/collapse/trim from normalize
    if normalize and normalize.get("casefold", False):
        s = s.casefold()
    if normalize and normalize.get("collapse_spaces", False):
        s = re.sub(r"\s+", " ", s)
    if normalize and normalize.get("trim", False):
        s = s.strip()
    # 6) Respect count_spaces
    if not count_spaces:
        s = s.replace(" ", "")
    return s


# --- LCS helper for deletion math ---
def _lcs_len(a: str, b: str) -> int:
    """
    Longest Common Subsequence length (O(n*m) DP).
    We keep memory O(min(n,m)) by ensuring b is the shorter dimension.
    """
    if a is None: a = ""
    if b is None: b = ""
    # Ensure b is the shorter sequence for smaller DP width
    if len(b) > len(a):
        a, b = b, a
    n, m = len(a), len(b)
    prev = [0] * (m + 1)
    cur = [0] * (m + 1)
    for i in range(1, n + 1):
        ai = a[i - 1]
        for j in range(1, m + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev, cur = cur, prev  # swap
    return prev[m]


def _debug(s: str):
    # flip to True if you want verbose internal logs
    if False:
        print(f"[dbg] {s}", file=sys.stderr)

# Heuristic: does a string look like a regex pattern?
def _looks_like_regex_text(s: str) -> bool:
    """
    Heuristic check: does the text look like a regex?
    Triggers on common metacharacters, escapes, or character classes.
    """
    if not s:
        return False
    return bool(re.search(r"[().\[\]|?*+{}\\]|\\[dDsSwW]", s))

def _is_regex(rule: Dict[str, Any]) -> bool:
    # 1) explicit flag wins
    if rule.get("regex") is True:
        return True
    # 2) infer from query prefix
    q = str(rule.get("query", "")) if rule.get("query") is not None else ""
    if q.startswith("re:"):
        return True
    # 3) infer from pattern heuristics
    pat = str(rule.get("pattern", ""))
    return _looks_like_regex_text(pat)

def _coalesce_replacement(rep: Optional[str]) -> str:
    return "" if rep is None else str(rep)

def _replace_backrefs(template: str, groups: List[str]) -> str:
    """Expand $1..$99 and \\1..\\99 using synthesized group texts."""
    def sub_dollar(m):
        idx = int(m.group(1))
        return groups[idx-1] if 1 <= idx <= len(groups) else ""
    def sub_backslash(m):
        idx = int(m.group(1))
        return groups[idx-1] if 1 <= idx <= len(groups) else ""

    #? 1, $2...
    s = re.sub(r"\$(\d{1,2})", sub_dollar, template)
    # \1, \2...
    s = re.sub(r"\\(\d{1,2})", sub_backslash, s)
    return s

def _charclass_rep(cc: str) -> str:
    # Return one representative char for a class like [^>], [A-Za-z], etc.
    # Prefer a visible, safe placeholder.
    if cc.startswith("[^") and cc.endswith("]"):
        # anything-but → 'x' is fine
        return "x"
    # Try to detect digits/letters quickly
    if re.fullmatch(r"\[0-9\-]+\]", cc) or re.search(r"\d", cc):
        return "1"
    if re.search(r"[A-Za-z]", cc):
        return "a"
    # whitespace set
    if re.search(r"\s", cc):
        return " "
    # default
    return "x"

def _apply_min_quantifier(unit: str, quant: str, assume_repeat: int) -> str:
    """
    Expand a single 'unit' by the minimal feasible occurrences per quantifier.
    unit is already a literal piece (e.g., '<b>', 'x', ' ').
    """
    if quant == "?":
        return ""  # 0 copies allowed
    if quant == "*":
        return ""  # minimal 0
    if quant == "+":
        return unit * max(1, assume_repeat)  # minimal >=1
    m = re.fullmatch(r"\{(\d+),(\d+)\}", quant)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return unit * lo
    m = re.fullmatch(r"\{(\d+),\}", quant)
    if m:
        lo = int(m.group(1))
        return unit * max(lo, 1)
    m = re.fullmatch(r"\{(\d+)\}", quant)
    if m:
        n = int(m.group(1))
        return unit * n
    # unknown -> leave unit
    return unit

def _split_top_level_alts(s: str) -> List[str]:
    """
    Split a group body by '|' only at top level (no nested parentheses/brackets).
    """
    parts = []
    level = 0
    bracket = 0
    cur = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            # keep escape and next char together
            cur.append(ch)
            if i+1 < len(s):
                cur.append(s[i+1])
                i += 2
                continue
        elif ch == "(":
            level += 1
        elif ch == ")":
            if level > 0:
                level -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            if bracket > 0:
                bracket -= 1
        elif ch == "|" and level == 0 and bracket == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts

def _synthesize_from_group(body: str, assume_repeat: int) -> str:
    """
    Given the body of a (...) group, choose the shortest alternative (by synthesized length).
    """
    alts = _split_top_level_alts(body)
    synths = [ _synthesize_regex_fragment(alt, assume_repeat)[0] for alt in alts ]
    # pick shortest synthesized; tie -> first
    best = min(synths, key=len) if synths else ""
    return best

def _synthesize_regex_fragment(pat: str, assume_repeat: int) -> Tuple[str, List[str]]:
    """
    Synthesize a minimal matching string for a regex fragment.
    Returns (text, captured_groups_list)
    """
    out = []
    groups: List[str] = []
    i = 0
    L = len(pat)

    def emit_unit_with_quant(unit_text: str, i_ref: int) -> Tuple[str, int]:
        # Look ahead for quantifier
        j = i_ref
        if j < L:
            # quantifiers: ?, *, +, {m}, {m,}, {m,n}
            m = re.match(r"\?|\*|\+|\{\d+(?:,\d+)?\}|\{\d+,\}", pat[j:])
            if m:
                q = m.group(0)
                expanded = _apply_min_quantifier(unit_text, q, assume_repeat)
                return expanded, j + len(q)
        return unit_text, j

    while i < L:
        ch = pat[i]

        # escape sequence -> literal next char or special class
        if ch == "\\" and i+1 < L:
            nxt = pat[i+1]
            pair = "\\" + nxt
            if pair in REP_MAP_SINGLE:
                unit_text = REP_MAP_SINGLE[pair]
                i += 2
                unit_text, i = emit_unit_with_quant(unit_text, i)
                out.append(unit_text)
                continue
            # escaped literal (e.g., \. \* \( \) \{ \})
            unit_text = nxt
            i += 2
            unit_text, i = emit_unit_with_quant(unit_text, i)
            out.append(unit_text)
            continue

        # character class [...]
        if ch == "[":
            j = i + 1
            while j < L and pat[j] != "]":
                # allow escapes inside
                if pat[j] == "\\" and j+1 < L:
                    j += 2
                else:
                    j += 1
            cc = pat[i:j+1] if j < L else pat[i:]
            rep = _charclass_rep(cc)
            i = j + 1 if j < L else L
            rep, i = emit_unit_with_quant(rep, i)
            out.append(rep)
            continue

        # group (...) or (?:...)
        if ch == "(":
            # detect non-capturing prefix
            noncap = pat.startswith("(?:", i)
            # find matching ')'
            j = i + 1
            level = 1
            while j < L and level > 0:
                if pat[j] == "\\" and j+1 < L:
                    j += 2
                    continue
                if pat[j] == "(":
                    level += 1
                elif pat[j] == ")":
                    level -= 1
                j += 1
            body = pat[(i + (3 if noncap else 1)):(j-1 if j <= L else L)]
            synth = _synthesize_from_group(body, assume_repeat)
            # record captured groups only if capturing
            if not noncap:
                groups.append(synth)
            i = j
            synth, i = emit_unit_with_quant(synth, i)
            out.append(synth)
            continue

        # anchors and flags: ^ $ \A \Z \b \B etc. → produce nothing
        if ch in "^$":
            i += 1
            continue

        # quantifier directly after literal char/seq (handled in emit_unit_with_quant via lookahead)
        # literals: treat as single-char unit and then process quantifier
        unit_text = ch
        i += 1
        unit_text, i = emit_unit_with_quant(unit_text, i)
        out.append(unit_text)

    return "".join(out), groups

def synthesize_min_match(pattern: str, is_regex: bool, assume_repeat: int) -> Tuple[str, List[str]]:
    """
    Returns a minimal matching string and the list of captured group texts.
    For literal patterns, the minimal match is the pattern itself.
    """
    if not is_regex:
        return pattern, []
    try:
        text, groups = _synthesize_regex_fragment(pattern, assume_repeat)
        return text, groups
    except Exception as e:
        _debug(f"synthesis failed for pattern={pattern!r}: {e}")
        return "", []  # safest: unknown → empty minimal



def compute_deletion(pattern: str,
                     replacement: str,
                     is_regex: bool,
                     assume_repeat: int,
                     *,
                     vis_count_spaces: bool = True,
                     vis_normalize: Optional[Dict[str, Any]] = None) -> Tuple[int, int, str, str, Dict[str, Any]]:
    """
    Compute conservative deletion estimates using synthesized minimal match.
    Returns (raw_del, visible_del, synthesized_match, expanded_replacement, debug_dict).
      - raw_del: deletions estimated as len(match_raw) - LCS(match_raw, repl_raw)
      - visible_del: deletions estimated as len(match_vis) - LCS(match_vis, repl_vis)
    """
    match_text, caps = synthesize_min_match(pattern, is_regex, assume_repeat)
    repl = _replace_backrefs(_coalesce_replacement(replacement), caps)

    # Raw deletions via LCS
    lcs_raw = _lcs_len(match_text, repl)
    raw_del = max(0, len(match_text) - lcs_raw)

    # Visible deletions via 'visible' pipeline + LCS
    vis_match = _to_visible(match_text, count_spaces=vis_count_spaces, normalize=vis_normalize)
    vis_repl  = _to_visible(repl,        count_spaces=vis_count_spaces, normalize=vis_normalize)
    lcs_vis = _lcs_len(vis_match, vis_repl)
    visible_del = max(0, len(vis_match) - lcs_vis)

    dbg = {
        "match_raw": match_text,
        "repl_raw": repl,
        "match_vis": vis_match,
        "repl_vis": vis_repl,
        "lcs_raw": lcs_raw,
        "lcs_vis": lcs_vis,
    }
    return raw_del, visible_del, match_text, repl, dbg

# ------------------------------- IO Layer ------------------------------------

def process_file(path: Path, args) -> Tuple[int, int]:
    """
    Load, analyze, and print results for a single rules JSON file.

    Args:
        path: Path to the rules JSON file.
        args: Command-line arguments.

    Returns:
        (rc, rules_analyzed)
        rc = 0 on success, 1 on failure
    """
    try:
        p = Path(path)
        rules = robust_load_rules_from_file(p)
    except Exception as e:
        print(f"[!] Failed to load {path}: {e}", file=sys.stderr)
        return 1, 0

    if not isinstance(rules, list):
        print(f"[!] {path}: expected a list of rules", file=sys.stderr)
        return 1, 0

    print(f"\n▶️  {p.name}")
    print("   · assume_repeat:", args.assume_repeat)

    analyzed = 0
    for idx, rule in enumerate(rules):
        if args.rule is not None and idx != args.rule:
            continue
        pat = str(rule.get("pattern", ""))
        rep = _coalesce_replacement(rule.get("replacement"))
        is_rx = _is_regex(rule)

        # Guard is informational and can provide normalization knobs for *visible* diff.
        guard = _extract_delete_chars(rule.get("delete_chars"))
        if guard is None and "max_delete_chars" in rule:
            guard = {"max_chars": int(rule.get("max_delete_chars", 0)), "count_spaces": True, "normalize": None}

        vis_count_spaces = True if guard is None else bool(guard.get("count_spaces", True))
        vis_normalize = None if guard is None else guard.get("normalize")

        raw_del, vis_del, synth, out, dbg = compute_deletion(
            pat, rep, is_rx, args.assume_repeat,
            vis_count_spaces=vis_count_spaces,
            vis_normalize=vis_normalize
        )

        # Compute insertions (raw & visible) using LCS as baseline
        raw_ins = max(0, len(dbg['repl_raw']) - dbg['lcs_raw'])
        vis_ins = max(0, len(dbg['repl_vis']) - dbg['lcs_vis'])

        # Build guard summary
        if guard is None:
            guard_str = "max=–"
        else:
            mc = guard.get("max_chars", 0)
            cs = guard.get("count_spaces", True)
            norm = guard.get("normalize")
            if mc == -1:
                base = "max=∞"
            else:
                base = f"max={mc}"
            base += f", spaces={'yes' if cs else 'no'}"
            if isinstance(norm, dict):
                bits = []
                if norm.get("unicode"):         bits.append(f"U={norm['unicode']}")
                if norm.get("casefold"):        bits.append("cf")
                if norm.get("collapse_spaces"): bits.append("collapse")
                if norm.get("trim"):            bits.append("trim")
                if bits:
                    base += ", norm=[" + ",".join(bits) + "]"
            guard_str = base

        # Recommend based on visible deletions
        recommend = vis_del
        kind = "regex" if is_rx else "literal"
        line = (f" - rule {idx} | {kind} | "
                f"del={raw_del}, ins={raw_ins} | "
                f"vis_del={vis_del}, vis_ins={vis_ins} | "
                f"guard={guard_str} | recommend={recommend}")
        # Mismatch indicator
        guard_max = None if guard is None else guard.get('max_chars', None)
        if guard_max is not None and guard_max != recommend:
            line += " ⚠︎ mismatch"
        print(line)

        # Optional verbose block
        if getattr(args, 'verbose', False):
            print(f"   match_raw: {dbg['match_raw']!r}")
            print(f"   repl_raw : {dbg['repl_raw']!r}")
            print(f"   match_vis(len {len(dbg['match_vis'])}): {dbg['match_vis']!r}")
            print(f"   repl_vis (len {len(dbg['repl_vis'])}): {dbg['repl_vis']!r}")
            print(f"   LCS_raw={dbg['lcs_raw']}, raw_del={raw_del}, raw_ins={raw_ins} | "
                  f"LCS_vis={dbg['lcs_vis']}, vis_del={vis_del}, vis_ins={vis_ins}")

        analyzed += 1

    if analyzed == 0:
        print("   (no matching rules to analyze in this file)")
    else:
        print(f"   Total rules analyzed in file: {analyzed}")
    return 0, analyzed

def discover_or_use_explicit(args) -> List[Path]:
    """
    Decide which files to analyze:
      - If positional files were provided, use them verbatim (as Paths).
      - Otherwise, discover files using utils.discover_rule_files with the given dir/globs.
      - Filter with _is_rules_json for safety.
    """
    if args.files:
        print("▶️  Using explicit file list (discovery skipped)")
        return [Path(f) for f in args.files]

    root = Path(args.dir).expanduser().resolve()
    patterns = [p.strip() for p in args.glob.split(",") if p.strip()] or None
    try:
        # Adapt to different helper signatures:
        #   A) discover_rule_files(root, patterns)
        #   B) discover_rule_files(root)
        #   C) discover_rule_files()
        try:
            candidates = discover_rule_files(root, patterns)
        except TypeError:
            try:
                candidates = discover_rule_files(root)
            except TypeError:
                candidates = discover_rule_files()
    except Exception as e:
        print(f"[!] Discovery failed under {root}: {e}", file=sys.stderr)
        return []

    # Normalize to Paths, deduplicate by resolved path, then sort case-insensitively by filename
    cand_paths = [Path(p) for p in candidates]
    unique = {}
    for p in cand_paths:
      try:
          key = p.resolve()
      except Exception:
          key = p
      if key not in unique:
          unique[key] = p
    cand_paths = sorted(unique.values(), key=lambda p: p.name.casefold())

    files: List[Path] = []
    for p in cand_paths:
        try:
            if _is_rules_json(p):
                files.append(p)
        except Exception as e:
            print(f"[!] Skipping {p}: _is_rules_json error: {e}", file=sys.stderr)

    if not files:
        print(f"[!] No valid rules JSON files found under {root} (glob: {args.glob})", file=sys.stderr)
        return []

    print(f"▶️  Discovered {len(files)} rule file(s) (dir={root}, glob={args.glob}):")
    for i, p in enumerate(files, 1):
        print(f"   {i:2d}) {p.name}")
    return files

def _print_available_files(files) -> None:
    print("\nAvailable rule files:")
    for i, p in enumerate(files, 1):
        print(f"  {i}. {p.name}")

def _prompt_file_selection(files) -> list:
    """
    Prompt user to select files using the same UX as _find_replace.py:
      - Accepts: 'All' (case-insensitive) → all files
      - Accepts: comma-separated list of indices (e.g., '1,3,5')
      - Accepts: ranges like '1-4'
      - Accepts: negative indices to exclude (e.g., '-2' or '-2,-4')
      - Accepts: combinations (e.g., '1-3, 5' or '-1, -3')
    Returns the selected subset in original order.
    """
    prompt = "Select files (e.g., 1,2,3 | -1 | -2, -4 | 1-3, 5 | All): "
    while True:
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            # On non-interactive/CI, default to All
            return files[:]

        if not raw or raw.lower() == "all":
            return files[:]

        # Split tokens
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
        include_set = set()
        exclude_set = set()
        try:
            for tok in tokens:
                # Negative exclusion like "-2"
                if re.fullmatch(r"-\d+", tok):
                    idx = int(tok)
                    exclude_set.add(-idx)  # store positive index
                    continue
                # Range like "1-3"
                m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", tok)
                if m:
                    a, b = int(m.group(1)), int(m.group(2))
                    if a > b:
                        a, b = b, a
                    include_set.update(range(a, b + 1))
                    continue
                # Single positive index
                if re.fullmatch(r"\d+", tok):
                    include_set.add(int(tok))
                    continue
                raise ValueError(f"Unrecognized token: {tok}")
        except ValueError as e:
            print(f"[!] {e}")
            continue

        n = len(files)
        # sanitize indices: 1..n
        include = [i for i in sorted(include_set) if 1 <= i <= n] if include_set else list(range(1, n + 1))
        exclude = {i for i in exclude_set if 1 <= i <= n}

        final_idx = [i for i in include if i not in exclude]
        if not final_idx:
            print("[!] Selection empty; try again or type 'All'.")
            continue

        # Map to paths, preserve original order
        return [files[i - 1] for i in final_idx]

# ------------------------------- Main ----------------------------------------

def main():
    repo_rules_default = FR_ROOT / "rules"
    ap = argparse.ArgumentParser(
        description="Analyze rules and print a conservative lower-bound for delete_chars.max_chars (read-only). Supports legacy max_delete_chars."
    )
    ap.add_argument("files", nargs="*", help="Explicit JSON rule file(s). If provided, discovery is skipped.")
    ap.add_argument("--dir", default=str(repo_rules_default), help="Root directory to search for rule files (default: repo /rules)")
    ap.add_argument("--glob", default="*rule.json,*rules.json", help="Comma-separated globs for discovery (default: '*rule.json,*rules.json').")
    ap.add_argument("--rule", type=int, help="Only compute & display this 0-based rule index within each file.")
    ap.add_argument("--assume-repeat", type=int, default=1, help="Minimal repeat used for + and {m,}. Default 1.")
    ap.add_argument("--verbose", action="store_true", help="Print synthesized texts and LCS details per rule.")
    args = ap.parse_args()

    files = discover_or_use_explicit(args)

    # If files were discovered (not explicit), prompt for selection like _find_replace.py
    if not args.files:
        _print_available_files(files)
        files = _prompt_file_selection(files)
        if not files:
            print("[!] No files selected.", file=sys.stderr)
            sys.exit(1)

    if not files:
        sys.exit(1)

    rc = 0
    total_analyzed = 0
    for p in files:
        code, n = process_file(p, args)
        rc |= code
        total_analyzed += n

    print("\n--------------------------------------------------")
    print(f"Grand total rules analyzed: {total_analyzed}")
    sys.exit(rc)

if __name__ == "__main__":
    main()