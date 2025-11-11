from __future__ import annotations
from pathlib import Path
import csv
import json
import re
from typing import Dict, List, Sequence, Tuple, Set

from .data import Pair, Preflight, Outcome, ExecResult, RegexRuleDebug

_SANITIZE_CHILD_TAIL = re.compile(r"::\((?:\.\+\?|\.\*)\)\$$")
_SANITIZE_REPL_TAIL  = re.compile(r"::(?:\\\d+|\$\d+)\s*$")

# SAFE by default — replacements are never altered in prefix preflight
DROP_TAILS_IN_PREFIX = False



def _discover_rule_files(rules_dir: Path) -> tuple[list[Path], list[Path]]:
    """
    Return (csv_files, json_files) from rules_dir, both sorted.
    CSVs always run first. Ignores dotfiles/backup/temp files.
    """
    csv_files: list[Path] = []
    json_files: list[Path] = []
    if not rules_dir.exists():
        return csv_files, json_files

    for p in sorted(rules_dir.rglob("*")):
        name = p.name
        if p.is_dir():
            continue
        if name.startswith(".") or name.endswith("~") or name.endswith(".bak"):
            continue
        # prefer explicit naming, then general CSV/JSON
        if p.suffix.lower() == ".csv":
            csv_files.append(p)
        elif p.suffix.lower() == ".json":
            json_files.append(p)
    return csv_files, json_files




def _load_pairs_from_csv(path: Path) -> List[Pair]:
    out: List[Pair] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            # Allow optional header: if first row contains 'old' and 'new', skip it.
            if reader.line_num == 1 and any(cell.lower() == "old" for cell in row):
                continue
            if len(row) < 2:
                continue
            old = (row[0] or "").strip()
            new = (row[1] or "").strip()
            if old and new and old != new:
                out.append(Pair(old=old, new=new, src="csv", kind="literal"))
    return out


def _load_pairs_from_json(path: Path) -> List[Pair]:
    out: List[Pair] = []
    if not path.exists():
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    if not isinstance(data, list):
        return out

    for item in data:
        # Skip file-level defaults blocks if present
        if isinstance(item, dict) and "file-defaults" in item:
            continue
        # 1) direct old/new
        if isinstance(item, dict) and "old" in item and "new" in item:
            old = str(item["old"]).strip(); new = str(item["new"]).strip()
            if old and new and old != new:
                out.append(Pair(old=old, new=new, src="json", kind="literal"))
            continue
        # 2) list form ["old","new"]
        if isinstance(item, list) and len(item) >= 2:
            old = str(item[0]).strip(); new = str(item[1]).strip()
            if old and new and old != new:
                out.append(Pair(old=old, new=new, src="json", kind="literal"))
            continue
        # 3) pattern/replacement (regex; $1 → \1)
        if isinstance(item, dict) and "pattern" in item and "replacement" in item:
            repl_raw = str(item["replacement"]).strip()
            repl = re.sub(r"(?<!\\)\$(\d+)", r"\\\1", repl_raw)
            pats = item["pattern"]
            if isinstance(pats, str):
                pats = [pats]
            if isinstance(pats, list):
                for pat in (p for p in pats if isinstance(p, str)):
                    pat = pat.strip()
                    if pat and repl:
                        out.append(Pair(old=pat, new=repl, src="json", kind="regex"))
    return out



# =========================
# Normalize / resolve
# =========================
def _norm_tag(t: str) -> str:
    # collapse whitespace, normalize separators, remove accidental quotes
    t = t.strip().strip('"').strip("'")
    t = re.sub(r"\s+", " ", t)
    t = t.replace(":::", "::")
    # forbid stray separators
    t = re.sub(r"(^:|:$)", "", t)
    return t


def _normalize_pairs(pairs: Sequence[Pair]) -> List[Pair]:
    seen: Dict[str, Pair] = {}
    for p in pairs:
        old = _norm_tag(p.old)
        new = _norm_tag(p.new)
        if not old or not new or old == new:
            continue
        # keep FIRST mapping (CSV is loaded first ⇒ CSV wins), preserving metadata
        if old not in seen:
            seen[old] = Pair(old=old, new=new, src=p.src, kind=p.kind)
    return list(seen.values())


def _resolve_chains(pairs: Sequence[Pair]) -> Tuple[List[Pair], List[Tuple[str, str]]]:
    """
    Resolve A->B, B->C to A->C. Detect cycles and block them.
    Returns (resolved_pairs, cycles_blocked). Metadata (src/kind) is preserved from the original 'old'.
    """
    nxt: Dict[str, str] = {p.old: p.new for p in pairs}
    meta_by_old: Dict[str, Pair] = {p.old: p for p in pairs}
    blocked: List[Tuple[str, str]] = []
    resolved: Dict[str, str] = {}

    def resolve(x: str) -> str | None:
        seen: Set[str] = set()
        cur = x
        while cur in nxt:
            if cur in seen:
                return None  
            seen.add(cur)
            cur = nxt[cur]
        return cur

    for old in list(nxt.keys()):
        dest = resolve(old)
        if dest is None:
            blocked.append((old, nxt[old]))
            continue
        resolved[old] = dest

    final: List[Pair] = []
    for o, n in resolved.items():
        if o != n:
            meta = meta_by_old.get(o)
            if meta is not None:
                final.append(Pair(o, n, meta.src, meta.kind))
            else:
                final.append(Pair(o, n))
    return final, blocked




def _rename_tag_token(tag: str, old: str, new: str) -> str:
    """Rename a tag token, moving a subtree when applicable."""
    if tag == old:
        return new
    if tag.startswith(old + "::"):
        # Preserve child path while moving the parent subtree.
        return new + tag[len(old):]
    return tag



def _sanitize_parent_only(pattern: str, replacement: str) -> tuple[str, str, bool]:
    """
    Prefixes-only sanitizer.

    - Always drop a terminal child-tail from the *pattern* ( '::(.+?)$' or '::(.*)$' ) so
      we can match the parent prefix.
    - By default (SAFE), do NOT alter the replacement (keeps $1/$2 and literal '#').
    - If DROP_TAILS_IN_PREFIX is True, and the pattern had a child-tail, remove ONE
      trailing '::\\d+' or '::$\\d+' from the replacement. Leave any preceding literals (e.g. '::#') intact.
    """
    changed = False

    # 1) Pattern: remove child tail if present
    pat2 = _SANITIZE_CHILD_TAIL.sub("$", pattern)
    had_child_tail = (pat2 != pattern)
    if had_child_tail:
        changed = True

    # 2) Replacement: SAFE by default (no change)
    rep2 = replacement

    # 3) Optional targeted tail-drop
    if had_child_tail and DROP_TAILS_IN_PREFIX:
        new_rep = _SANITIZE_REPL_TAIL.sub("", rep2, count=1)  # drop exactly one trailing ::\d+ / ::$d+
        if new_rep != rep2:
            rep2 = new_rep
            changed = True

    return pat2, rep2, changed

# ? [19-41_11-10] Helpers for left-path wrapping and safe replacement bumping

_LEFT_PATH_PREFIX_RX = re.compile(r"""
    ^\s*\^?                # optional leading ^ and whitespace
    (?:                     # either form already present...
       \(\(\?:\.\*::\)\?\) #   ^((?:.*::)?)
     | \(\.\*::\)           #   ^(.*::)
    )
""", re.X)

_DOLLAR_GROUP_RX = re.compile(r"(?<!\\)\$(\d+)")  # matches $n not preceded by a backslash

def has_left_path_capture(pattern: str) -> bool:
    """Return True if pattern already starts with an explicit left-path capture."""
    return bool(_LEFT_PATH_PREFIX_RX.match(pattern or ""))

def inject_left_path_capture(pattern: str, prefix_pat: str = r"^((?:.*::)?)") -> str:
    """
    Insert an optional left-path capture:
      - If the pattern begins with optional whitespace and a '^', insert right after the first '^'
      - Else, prepend at the very beginning
    Never appends '$' here; fullmatch() is used by the caller.
    """
    if not pattern:
        return prefix_pat
    m = re.match(r"^\s*\^", pattern)
    if m:
        i = pattern.find("^")
        return pattern[:i+1] + prefix_pat[1:] + pattern[i+1:]
    return prefix_pat + pattern

def bump_replacement_groups(repl: str, bump: int = 1) -> str:
    """
    Increase every $n by +bump, ignoring \$n (literal dollars).
    Handles multi-digit indices ($10 -> $11) and $0 as well.
    """
    def _inc(m: re.Match) -> str:
        n = int(m.group(1))
        return f"${n + bump}"
    return _DOLLAR_GROUP_RX.sub(_inc, repl or "")

def _compute_prefixes(existing_tags: list[str]) -> tuple[set[str], dict[str, list[str]]]:
    """Return (prefixes, root->prefixes) from full tag list; 'A::B::C' yields A, A::B, A::B::C."""
    prefixes: set[str] = set()
    root_to_prefixes: dict[str, list[str]] = {}
    for t in existing_tags:
        parts = t.split("::")
        for i in range(1, len(parts)+1):
            p = "::".join(parts[:i])
            if p not in prefixes:
                prefixes.add(p)
                r = parts[0]
                root_to_prefixes.setdefault(r, []).append(p)
    return prefixes, root_to_prefixes

def _first_segment(s: str) -> str:
    return s.split("::", 1)[0]

def _looks_literal_segment(seg: str) -> bool:
    # conservative: metacharacters => not literal
    return re.search(r"[.\\^$*+?{}\\[\\]()]|\\|", seg) is None


__all__ = [
    "Pair", "Preflight", "Outcome", "RegexRuleDebug", "ExecResult",
    "_discover_rule_files", "_load_pairs_from_csv", "_load_pairs_from_json",
    "_norm_tag", "_normalize_pairs", "_resolve_chains",
    "_rename_tag_token", "_sanitize_parent_only", "_compute_prefixes",
    "_first_segment", "_looks_literal_segment",
    "has_left_path_capture", "inject_left_path_capture", "bump_replacement_groups",
]
