import re
import sys
import json
import csv
from html import unescape
from pathlib import Path
from datetime import datetime
import time
from typing import Optional, Iterable, List, Dict, Any, Tuple
from collections import defaultdict

from .FR_global_utils import now_stamp, md_inline, md_table_cell, TS_FORMAT

from .data_defs import RunConfig, Rule

from .anki_query_utils import compose_search, effective_query
from .rules_io import to_rule



# --- Rule provenance helper (for logs/reports) -------------------------------

def rule_prov(rule: Any) -> str:
    """Small provenance string used in logs.

    Supports both dict-based rules (legacy) and Rule dataclasses (preferred).

    Canonical provenance:
    - source_file (filename)
    - source_index (int)

    Back-compat fallbacks:
    - _source_file/_source_index
    - source_path/_source_path/__source_file (may be a full path)
    """

    def _name_from_pathlike(x: Any) -> str:
        if not x:
            return ""
        try:
            return Path(str(x)).name
        except Exception:
            return str(x)

    src = "?"
    idx: Optional[Any] = None
    nm = ""

    # Dataclass Rule
    if isinstance(rule, Rule):
        src = (str(rule.source_file).strip() if rule.source_file else "?")
        idx = rule.source_index
        # Rule currently doesn't have a `name` field
        nm = ""
    # Dict rule
    elif isinstance(rule, dict):
        try:
            src = str(
                rule.get("source_file")
                or rule.get("_source_file")
                or _name_from_pathlike(rule.get("source_path"))
                or _name_from_pathlike(rule.get("_source_path"))
                or _name_from_pathlike(rule.get("__source_file"))
                or "?"
            )
        except Exception:
            src = str(rule.get("source_file") or rule.get("_source_file") or rule.get("__source_file") or "?")

        idx = rule.get("source_index")
        if idx is None:
            idx = rule.get("_source_index")
        if idx is None:
            idx = rule.get("__source_index")
        # Legacy logger used __rule_index sometimes
        if idx is None:
            idx = rule.get("__rule_index")

        nm = (rule.get("name") or "").strip()
    else:
        # Fallback: treat as path-like
        src = _name_from_pathlike(rule) or "?"

    try:
        idx_i = int(idx) if idx is not None else None
    except Exception:
        idx_i = None

    base = f"[{src}#{idx_i}]" if idx_i is not None else f"[{src}]"
    return f"{base} {nm}" if nm else base


# --- Helper: coerce dict/Rule into a Rule dataclass --------------------------

def _as_rule(rule_like: Any) -> Rule:
    """Return a Rule dataclass for downstream helpers.

    - If already a Rule, return it.
    - If a dict, convert via rules_io.to_rule() (expects normalized-ish input).
    - Otherwise, raise TypeError.
    """
    if isinstance(rule_like, Rule):
        return rule_like
    if isinstance(rule_like, dict):
        return to_rule(rule_like)
    raise TypeError(f"Unsupported rule type: {type(rule_like)!r}")


# --- Helper: resolve rule source info (path + label) ---
def _resolve_source_info(raw: Any) -> Tuple[str, str]:
    """Return (source_path, source_file_label).

    Accepts:
    - a per-rule dict (or rule dict)
    - a Rule dataclass
    - a Path/string

    Prefers `source_path` (full path) when present, but always returns a usable
    label (usually a filename).
    """
    try:
        # If a dict was passed, pull from canonical + compat keys.
        if isinstance(raw, dict):
            sp = raw.get("source_path") or raw.get("_source_path")
            sf = raw.get("source_file") or raw.get("_source_file")
            # Historical: __source_file sometimes stored full path
            hist = raw.get("__source_file")

            if sp:
                try:
                    p = Path(str(sp)).expanduser().resolve()
                    return str(p), (sf or p.name or "?")
                except Exception:
                    return str(sp), (sf or Path(str(sp)).name if str(sp) else "?")

            if hist:
                try:
                    p = Path(str(hist)).expanduser().resolve()
                    return str(p), (sf or p.name or "?")
                except Exception:
                    return str(hist), (sf or Path(str(hist)).name if str(hist) else "?")

            # Only a filename known
            if sf:
                return "", str(sf)

            return "", ""

        # If a Rule dataclass was passed, use its provenance.
        if isinstance(raw, Rule):
            sf = str(raw.source_file).strip() if getattr(raw, "source_file", None) else ""
            sp = getattr(raw, "source_path", None)

            if sp:
                try:
                    p = Path(str(sp)).expanduser().resolve()
                    return str(p), (sf or p.name or "?")
                except Exception:
                    sps = str(sp)
                    return sps, (sf or (Path(sps).name if sps else "?"))

            return "", sf

        # Not a dict: treat as path-like / label
        if raw is None:
            return "", ""
        s = str(raw).strip()
        if not s:
            return "", ""

        # If it looks like a path, try to use it as such; otherwise just a label.
        if "/" in s or "\\" in s or s.endswith(".json") or s.endswith(".txt"):
            try:
                p = Path(s).expanduser().resolve()
                return str(p), (p.name or s)
            except Exception:
                return s, (Path(s).name if s else s)

        return "", s

    except Exception:
        return "", ""


def _pick_rule_source(per: Dict[str, Any]) -> Tuple[str, str]:
    """Resolve a per-rule record's source consistently."""
    # Prefer per-rule level keys
    sp, sf = _resolve_source_info(per)
    if sp or sf:
        return sp, sf

    # Fall back into embedded rule metadata
    rule_meta = per.get("rule")
    if isinstance(rule_meta, dict):
        sp2, sf2 = _resolve_source_info(rule_meta)
        if sp2 or sf2:
            return sp2, sf2

    # Older keys
    return _resolve_source_info(per.get("file") or per.get("__source_file") or "")


# --- Helper: group-aware label for rule file sources ---
def _log_rule_group_and_name(raw_src: Any, rules_root: Optional[Path]) -> Tuple[str, str, str]:
    """Return (group, file_name, display_label) for a rule source.

    - group: first folder under rules_root, or "" if not applicable
    - file_name: basename of the file
    - display_label: "[group] file_name" if group present, else "file_name"

    Supports raw sources that may be:
    - full paths (preferred)
    - filename-only labels (common for TXT remove rules)
    """
    src_path, src_file = _resolve_source_info(raw_src)

    if not src_path and not src_file:
        return "", "", "unknown_source"

    # If we only have a filename/label, we cannot compute group reliably.
    if not src_path:
        file_name = src_file or "unknown_source"
        return "", file_name, file_name

    try:
        p = Path(str(src_path)).expanduser().resolve()
    except Exception:
        file_name = src_file or Path(str(src_path)).name or "unknown_source"
        return "", file_name, file_name

    file_name = src_file or p.name or "unknown_source"

    if rules_root is None:
        return "", file_name, file_name

    try:
        rel = p.relative_to(rules_root)
        parts = rel.parts
        if len(parts) > 1:
            group = parts[0]
            return group, file_name, f"[{group}] {file_name}"
    except Exception:
        pass

    return "", file_name, file_name


# --- Remove TXT rule helpers: detect, resolve fields, build previews ---
def _is_remove_rule(per: Dict[str, Any], cfg: Any) -> bool:
    """Decide if this per-rule record came from a TXT-based remove file.

    This is used so we can render field-aware query/search previews instead of
    treating remove TXT rules like normal JSON rules in logs.
    """
    # Try several possible locations for the originating rule file
    candidates: list[Any] = [
        per.get("source_path"),
        per.get("source_file"),
        per.get("_source_path"),
        per.get("_source_file"),
        per.get("file"),
        per.get("__source_file"),
    ]

    rule_meta = per.get("rule")
    if isinstance(rule_meta, dict):
        candidates.append(rule_meta.get("source_path"))
        candidates.append(rule_meta.get("source_file"))
        candidates.append(rule_meta.get("_source_path"))
        candidates.append(rule_meta.get("_source_file"))
        candidates.append(rule_meta.get("__source_file"))
        candidates.append(rule_meta.get("file"))

    raw_src = ""
    for c in candidates:
        if c:
            raw_src = c
            break

    try:
        src_name = Path(str(raw_src)).name.lower()
    except Exception:
        src_name = str(raw_src).lower()

    if not src_name:
        return False

    # Heuristic: TXT remove-rule files end with these exact suffixes
    if src_name.endswith("_remove_rule.txt") or src_name.endswith("_remove_rules.txt"):
        return True

    # Respect configured names/suffixes when present
    field_rm_name = getattr(cfg, "field_remove_rules_name", "") or ""
    if field_rm_name:
        try:
            if src_name == Path(str(field_rm_name)).name.lower():
                return True
        except Exception:
            pass

    remove_suffix = getattr(cfg, "remove_rules_suffix", "") or ""
    if remove_suffix and src_name.endswith(str(remove_suffix).lower()):
        return True

    return False




def _highlight_diff_snippet(
    before: str,
    after: str,
    max_len: int = 240,
    context: int = 40,
) -> tuple[str, str]:
    """
    * Return BEFORE/AFTER strings with the changed region highlighted.
    - Wrap the differing span in [[...]] for both before and after.
    - Trim to a small window around the change, with basic max_len clipping.
    - Debug-only; meant for DRY_RUN previews.
    """
    try:
        b = before or ""
        a = after or ""
        if b == a:
            # No change -> just clip for safety
            if len(b) > max_len:
                clipped = b[: max_len - 1] + "…"
                return clipped, clipped
            return b, a

        # 1) Common prefix length
        prefix = 0
        for cb, ca in zip(b, a):
            if cb != ca:
                break
            prefix += 1

        # 2) Common suffix length (avoid crossing prefix)
        suffix = 0
        for cb, ca in zip(reversed(b), reversed(a)):
            if len(b) - suffix <= prefix or len(a) - suffix <= prefix:
                break
            if cb != ca:
                break
            suffix += 1

        b_diff_end = len(b) - suffix
        a_diff_end = len(a) - suffix

        # 3) Window around the change
        win_start = max(0, prefix - context)
        win_end_b = min(len(b), b_diff_end + context)
        win_end_a = min(len(a), a_diff_end + context)

        b_window = b[win_start:win_end_b]
        a_window = a[win_start:win_end_a]

        # Local indices inside each window
        b_start = max(0, prefix - win_start)
        b_end = max(b_start, b_diff_end - win_start)
        a_start = max(0, prefix - win_start)
        a_end = max(a_start, a_diff_end - win_start)

        def mark(s: str, start: int, end: int) -> str:
            start = max(0, min(len(s), start))
            end = max(start, min(len(s), end))
            return s[:start] + "[[" + s[start:end] + "]]" + s[end:]

        b_marked = mark(b_window, b_start, b_end)
        a_marked = mark(a_window, a_start, a_end)

        # 4) Clip to max_len
        def clip(s: str) -> str:
            if len(s) <= max_len:
                return s
            return s[: max_len - 1] + "…"

        return clip(b_marked), clip(a_marked)

    except Exception:
        # Fail-safe: just return originals
        return before, after


# --- Helper: format errors in red HTML for logs/tables ---
def _format_error_html(err: Any, escape_pipes: bool = False) -> str:
    """\
    * Format an error string with a red, bold HTML span for markdown logs.
    - When escape_pipes=True, escape '|' so it is safe inside markdown tables.
    """
    text = str(err or "")
    if not text.strip():
        return ""
    if escape_pipes:
        text = text.replace("|", "\\|")
    return f'<span style="color:#ff2d00;font-weight:600">{text}</span>'


def _slug_for_filename(label: str) -> str:
    """
    * Produce a filesystem-friendly slug for a rule-file label.
    - Keeps alphanumerics, underscore, dash, and dot; everything else -> '_'.
    """
    s = str(label or "").strip()
    if not s:
        return "file"
    s = re.sub(r"[^\w\-.]+", "_", s)
    # Keep it reasonably short to avoid path issues
    return s[:64] or "file"


def _write_per_file_debug_logs(
    out_dir: Path,
    ts: str,
    rules_root: Optional[Path],
    per_rules: List[Dict[str, Any]],
    dry: bool,
    max_per_file: int,
) -> None:
    """
    * When extensive debugging is enabled, emit one markdown file per rule source file.
    - Each file shows up to `max_per_file` edited note fields (examples) aggregated across rules.
    """
    try:
        if max_per_file <= 0:
            return
        # Collect examples by rule-file label
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for per in per_rules:
            examples = list(per.get("examples") or [])
            if not examples:
                continue
            src_path, src_file = _pick_rule_source(per)
            raw_src = src_path or src_file or ""
            _, _, label = _log_rule_group_and_name(raw_src, rules_root)
            if not label:
                label = "<?>"
            current = grouped[label]
            for ex in examples:
                if len(current) >= max_per_file:
                    break
                current.append({"rule_index": per.get("index", "?"), "example": ex})

        for label, items in grouped.items():
            if not items:
                continue
            slug = _slug_for_filename(label)
            filename = f"Batch_FR_File_Debug__{slug}__{ts}.md"
            out_path = out_dir / filename

            lines: List[str] = []
            lines.append(f"# Batch Find & Replace File Debug — {label} — {ts}")
            lines.append("")
            lines.append(
                "This log shows example note fields edited by rules sourced from this file."
            )
            lines.append("")
            lines.append("| rule | field | BEFORE | AFTER |")
            lines.append("|---|---|---|---|")

            for item in items:
                idx = item.get("rule_index", "?")
                ex = item.get("example", {}) or {}
                fld = ex.get("field", "")
                before_raw = str(ex.get("before", ""))
                after_raw = str(ex.get("after", ""))
                if dry:
                    before_disp, after_disp = _highlight_diff_snippet(
                        before_raw, after_raw, max_len=240
                    )
                else:
                    before_disp, after_disp = before_raw, after_raw

                before_disp = md_table_cell(before_disp)
                after_disp = md_table_cell(after_disp)
                fld_disp = md_table_cell(fld)

                lines.append(
                    f"| {idx} | `{fld_disp}` | `{before_disp}` | `{after_disp}` |"
                )

            out_text = "\n".join(lines) + "\n"
            out_path.write_text(out_text, encoding="utf-8")
    except Exception:
        # Debug helper: failures here should not break the main debug log.
        return


def write_batch_fr_debug(
    report: Dict[str, Any],
    cfg: Any,
    debug_cfg: Optional[Dict[str, Any]] = None,
) -> Optional[Path]:
    """\
    * Emit a markdown debug file summarizing a batch_FR run.
    - Returns the Path to the written file, or None if disabled or on error.
    """
    debug_cfg = debug_cfg or {}
    enabled = bool(debug_cfg.get("enabled", True))
    if not enabled:
        return None

    try:
        # Resolve timestamp format and log directory
        ts_fmt = getattr(cfg, "ts_format", None) or report.get("ts_format") or "%H-%M_%m-%d"
        ts = datetime.now().strftime(ts_fmt)

        # Normalize / resolve log_dir; cfg.log_dir may already be a Path
        raw_log_dir = getattr(cfg, "log_dir", None) or report.get("log_dir") or "."
        out_dir = Path(raw_log_dir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        log_dir_str = str(out_dir)

        filename = f"Batch_FR_Debug__{ts}.md"
        out_path = out_dir / filename

        max_rules = int(debug_cfg.get("max_rules", 200) or 200)
        max_examples = int(debug_cfg.get("max_examples_per_rule", 3) or 3)

        per_rules = list(report.get("per_rule") or [])[:max_rules]
        invalid_rules = list(report.get("invalid_rules") or [])
        error_rules = [p for p in per_rules if str(p.get("error") or "").strip()]

        lines: List[str] = []

        # Header
        lines.append(f"# Batch Find & Replace Debug — {ts}")
        lines.append("")
        lines.append("Generated by batch_FR engine. This file summarizes rule behavior for this run.")
        lines.append("")

        # Settings section
        lines.append("## Settings")
        dry = report.get("dry_run", False)
        lines.append(f"- DRY_RUN: {dry}")
        lines.append(f"- log_dir: `{log_dir_str}`")
        extensive = bool(report.get("extensive_debug", False))
        try:
            extensive_max = int(report.get("extensive_debug_max_examples", max_examples))
        except Exception:
            extensive_max = max_examples
        lines.append(f"- extensive_debug: {extensive}")
        lines.append(f"- extensive_debug_max_examples: {extensive_max}")
        rules_path = getattr(cfg, "rules_path", "") or ""
        lines.append(f"- rules_path: `{rules_path}`")

        # Derive a rules_root Path for group-aware displays
        rules_root = None
        try:
            if rules_path:
                rules_root = Path(str(rules_path)).expanduser().resolve()
        except Exception:
            rules_root = None

        # Prefer the canonical key, but fall back to older report schemas
        rules_files_used = (
            report.get("rules_files_used")
            or report.get("rules_files_expanded")
            or report.get("rules_files_in")
            or []
        )

        # Raw UI selection inputs (if present)
        rules_files_selected = (
            report.get("rules_files_selected")
            or report.get("rules_files_in")
            or []
        )

        # Show the raw selection first (helps diagnose UI vs expansion issues)
        if isinstance(rules_files_selected, (list, tuple)) and rules_files_selected:
            lines.append(f"- rule_files_selected ({len(rules_files_selected)}):")

            def _rule_file_sort_key_sel(p: Any) -> str:
                try:
                    return Path(str(p)).name.lower()
                except Exception:
                    return str(p).lower()

            for rf in sorted(rules_files_selected, key=_rule_file_sort_key_sel):
                _, _, label = _log_rule_group_and_name(rf, rules_root)
                lines.append(f"  - `{label}`")

        # Then show the expanded/effective set used for the run
        if isinstance(rules_files_used, (list, tuple)) and rules_files_used:
            lines.append(f"- rule_files_used ({len(rules_files_used)}):")

            def _rule_file_sort_key(p: Any) -> str:
                try:
                    return Path(str(p)).name.lower()
                except Exception:
                    return str(p).lower()

            for rf in sorted(rules_files_used, key=_rule_file_sort_key):
                _, _, label = _log_rule_group_and_name(rf, rules_root)
                lines.append(f"  - `{label}`")
        else:
            lines.append("- rule_files_used: (all discovered under rules_path)")
        lines.append(f"- log_mode: `{getattr(cfg, 'log_mode', '')}`")
        lines.append(f"- include_unchanged: {getattr(cfg, 'include_unchanged', False)}")
        lines.append(f"- max_loops: {getattr(cfg, 'max_loops', 0)}")

        remove_cfg = getattr(cfg, "remove_config", {}) or {}
        lines.append(f"- remove_config.loop (JSON rules/UI): {bool(remove_cfg.get('loop', True))}")
        lines.append(
            f"- remove_config.max_loops: {remove_cfg.get('max_loops', getattr(cfg, 'max_loops', 0))}"
        )
        # Field-remove global cleanup configuration (field_remove_rules.txt)
        lines.append(
            f"- remove_config.field_remove_enable: {bool(remove_cfg.get('field_remove_enable', True))}"
        )
        fr_fields = remove_cfg.get("field_remove_fields")
        if isinstance(fr_fields, (list, tuple)):
            fr_fields_disp = ", ".join(str(f) for f in fr_fields)
        else:
            fr_fields_disp = str(fr_fields or "None")
        lines.append(f"- remove_config.field_remove_fields: {fr_fields_disp}")
        # TXT-based remove-rule files: a dedicated Remove_FR_Debug is written when such a file is selected.
        lines.append(
            "- remove_rules_logging: a dedicated `Remove_FR_Debug__*.md` is written when the selected rule files "
            "include a TXT remove-rule file ending with `_remove_rule.txt` or `_remove_rules.txt`."
        )
        lines.append("")

        # Summary section
        lines.append("## Summary")
        lines.append(f"- Total rules: {report.get('rules', 0)}")
        lines.append(f"- Invalid rules: {len(invalid_rules)}")
        lines.append(f"- Notes matched: {report.get('notes_touched', 0)}")
        if dry:
            lines.append(f"- Notes that would change: {report.get('notes_would_change', 0)}")
            lines.append(f"- Notes actually changed (DRY RUN): {report.get('notes_changed', 0)}")
        else:
            lines.append(f"- Notes changed: {report.get('notes_changed', 0)}")
        lines.append(f"- Guard skips: {report.get('guard_skips', 0)}")
        lines.append(f"- Rules with errors: {len(error_rules)}")
        lines.append("")

        # Invalid rules section
        lines.append("## Invalid rules")
        if not invalid_rules:
            lines.append("_None._")
        else:
            lines.append("")
            lines.append("| # | file | error | pattern | replacement |")
            lines.append("|---:|------|-------|---------|-------------|")
            for idx, item in enumerate(invalid_rules, start=1):
                rule = item.get("rule") or {}
                err = str(item.get("error") or "")
                pat = str(rule.get("pattern", ""))
                rep = str(rule.get("replacement", ""))

                raw_src = rule.get("source_path") or rule.get("_source_path") or rule.get("__source_file") or rule.get("source_file") or rule.get("_source_file") or ""
                _, fname, label = _log_rule_group_and_name(raw_src, rules_root)
                if not label:
                    label = "<?>"

                err_disp = _format_error_html(err, escape_pipes=True)
                pat_disp = md_table_cell(pat)
                rep_disp = md_table_cell(rep)
                lines.append(f"| {idx} | `{label}` | {err_disp or ''} | `{pat_disp}` | `{rep_disp}` |")
        lines.append("")

        # Per-rule details table
        lines.append("## Per-rule details")
        if not per_rules:
            lines.append("_No rules were executed._")
        else:
            # Group rules by source file for clearer organization (group-aware)
            grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for per in per_rules:
                src_path, src_file = _pick_rule_source(per)
                raw_src = src_path or src_file or ""
                _, fname, label = _log_rule_group_and_name(raw_src, rules_root)
                if not label:
                    label = "<?>"
                grouped[label].append(per)

            # Table 1: core numeric stats, grouped by file (and folder)
            for label in sorted(grouped.keys(), key=str.lower):
                rules_for_file = grouped[label]
                lines.append("")
                lines.append(f"### {label}")
                lines.append("")
                if dry:
                    lines.append("| # | fields | flags | loop | matched | would_change | subs | guard_skips | rm_field_subs | rm_loop | rm_loops_sum | rm_loops_max | rm_fields_looped | rm_cap_hits | rm_cycle_hits | rm_empty_forced | rm_max_loops | fr_loop | fr_loops_used | fr_break_stable | fr_break_cap | fr_break_cycle | fr_empty_forced |")
                else:
                    lines.append("| # | fields | flags | loop | matched | changed | subs | guard_skips | rm_field_subs | rm_loop | rm_loops_sum | rm_loops_max | rm_fields_looped | rm_cap_hits | rm_cycle_hits | rm_empty_forced | rm_max_loops | fr_loop | fr_loops_used | fr_break_stable | fr_break_cap | fr_break_cycle | fr_empty_forced |")
                lines.append("|---:|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|")

                for per in rules_for_file:
                    idx = per.get("index", "?")
                    fields = per.get("fields", [])
                    fields_disp = ", ".join(str(f) for f in (fields or []))
                    flags = per.get("flags", "")
                    loop = per.get("loop", False)
                    matched = per.get("notes_matched", 0)
                    changed = per.get("notes_changed", 0)
                    would_change = per.get("notes_would_change", 0)
                    subs = per.get("total_subs", 0)
                    guard_skips = per.get("guard_skips", 0)
                    rm_field_subs = per.get("remove_field_subs", 0)
                    rm_loop = per.get("remove_loop", False)
                    rm_loops_sum = per.get("remove_loops_used_sum", per.get("remove_loops_used", 0))
                    rm_loops_max = per.get("remove_loops_used_max", 0)
                    rm_fields_looped = per.get("remove_fields_looped", 0)
                    rm_cap_hits = per.get("remove_cap_hits", 0)
                    rm_cycle_hits = per.get("remove_cycle_hits", 0)
                    rm_empty_forced = per.get("remove_empty_match_forced_single", 0)
                    rm_max_loops = per.get("remove_max_loops", 0)

                    fr_loop = per.get("fr_loop", False)
                    fr_loops_used = per.get("fr_loops_used", 0)
                    fr_break_stable = per.get("fr_break_stable", 0)
                    fr_break_cap = per.get("fr_break_cap", 0)
                    fr_break_cycle = per.get("fr_break_cycle", 0)
                    fr_empty_forced = per.get("fr_empty_match_forced_single", 0)

                    if dry:
                        lines.append(
                            f"| {idx} | `{fields_disp}` | `{flags}` | {loop} | {matched} | {would_change} | {subs} | {guard_skips} | {rm_field_subs} | {rm_loop} | {rm_loops_sum} | {rm_loops_max} | {rm_fields_looped} | {rm_cap_hits} | {rm_cycle_hits} | {rm_empty_forced} | {rm_max_loops} | {fr_loop} | {fr_loops_used} | {fr_break_stable} | {fr_break_cap} | {fr_break_cycle} | {fr_empty_forced} |"
                        )
                    else:
                        lines.append(
                            f"| {idx} | `{fields_disp}` | `{flags}` | {loop} | {matched} | {changed} | {subs} | {guard_skips} | {rm_field_subs} | {rm_loop} | {rm_loops_sum} | {rm_loops_max} | {rm_fields_looped} | {rm_cap_hits} | {rm_cycle_hits} | {rm_empty_forced} | {rm_max_loops} | {fr_loop} | {fr_loops_used} | {fr_break_stable} | {fr_break_cap} | {fr_break_cycle} | {fr_empty_forced} |"
                        )

            # Table 2: error / pattern / replacement (with file column)
            lines.append("")
            lines.append("| # | file | error | pattern | replacement |")
            lines.append("|---:|------|-------|---------|-------------|")
            for per in per_rules:
                idx = per.get("index", "?")
                err = str(per.get("error", "") or "")
                pat = per.get("pattern", "")
                rep = per.get("replacement", "")

                src_path, src_file = _pick_rule_source(per)
                raw_src = src_path or src_file or ""
                _, fname, label = _log_rule_group_and_name(raw_src, rules_root)
                if not label:
                    label = "<?>"

                # Escape pipes so the Markdown table doesn't break
                err_disp = _format_error_html(err, escape_pipes=True)
                pat_disp = md_table_cell(pat)
                rep_disp = md_table_cell(rep)
                lines.append(
                    f"| {idx} | `{label}` | {err_disp or ''} | `{pat_disp}` | `{rep_disp}` |"
                )
        lines.append("")

        # Per-rule examples
        lines.append("## Per-rule examples")
        any_examples = False
        for per in per_rules:
            examples = list(per.get("examples") or [])[:max_examples]
            has_error = bool(str(per.get("error") or "").strip())
            has_search = bool(str(per.get("search") or "").strip())
            if not examples and not has_error and not has_search:
                continue
            any_examples = True
            idx = per.get("index", "?")

            # TXT-based remove rules: detailed per-field behavior is logged in Remove_FR_Debug__*.md
            if _is_remove_rule(per, cfg):
                lines.append("")
                lines.append(f"### Rule {idx} (remove TXT)")
                lines.append("")
                pattern = str(per.get("pattern", "") or "")
                lines.append(f"- pattern: `{md_inline(pattern)}`")
                lines.append(
                    "- details: see `Remove_FR_Debug__*.md` for per-field remove behavior and examples "
                    "(written when a selected rule file ends with `_remove_rule(s).txt`)."
                )
                if has_error:
                    err_html = _format_error_html(per.get("error", ""))
                    lines.append(f"- error: {err_html}")
                # No BEFORE/AFTER table here – examples live in the dedicated remove log
                continue
            else:
                # Normal rule → keep existing behavior
                lines.append("")
                lines.append(f"### Rule {idx}")
                lines.append("")
                lines.append(f"- query: `{md_inline(per.get('query', ''))}`")
                if per.get("query_input") is not None:
                    lines.append(f"- query_input: `{md_inline(per.get('query_input', ''))}`")
                lines.append(f"- exclude: `{md_inline(per.get('exclude', ''))}`")
                if per.get("exclude_input") is not None:
                    lines.append(f"- exclude_input: `{md_inline(per.get('exclude_input', ''))}`")
                if has_search:
                    lines.append(f"- search (Browser): `{md_inline(per.get('search', ''))}`")
                if has_error:
                    err_html = _format_error_html(per.get("error", ""))
                    lines.append(f"- error: {err_html}")
                dc = per.get("delete_chars", {}) or {}
                lines.append(
                    f"- delete guard: max_chars={dc.get('max_chars', 0)}, count_spaces={dc.get('count_spaces', True)}"
                )
                lines.append("")
                lines.append("| field | BEFORE | AFTER |")
                lines.append("|---|---|---|")
                for ex in examples:
                    fld = ex.get("field", "")
                    before_raw = str(ex.get("before", ""))
                    after_raw = str(ex.get("after", ""))
                    if dry:
                        before_disp, after_disp = _highlight_diff_snippet(
                            before_raw, after_raw, max_len=240
                        )
                    else:
                        before_disp, after_disp = before_raw, after_raw
                    lines.append(
                        f"| `{md_table_cell(fld)}` | `{md_table_cell(before_disp)}` | `{md_table_cell(after_disp)}` |"
                    )

        if not any_examples:
            lines.append("")
            lines.append("_No examples were recorded for this run._")

        # If extensive debugging is enabled, emit per-file logs with up to N examples each.
        extensive = bool(report.get("extensive_debug", False))
        if extensive:
            try:
                max_per_file = int(report.get("extensive_debug_max_examples", max_examples))
            except Exception:
                max_per_file = max_examples
            if max_per_file > 0:
                _write_per_file_debug_logs(
                    out_dir=out_dir,
                    ts=ts,
                    rules_root=rules_root,
                    per_rules=per_rules,
                    dry=dry,
                    max_per_file=max_per_file,
                )

        out_text = "\n".join(lines) + "\n"
        out_path.write_text(out_text, encoding="utf-8")

        return out_path

    except Exception as e:  # pragma: no cover
        print(f"[batch_FR] Failed to write debug markdown: {e}", file=sys.stderr)
        return None


def write_regex_debug(
    report: Dict[str, Any],
    cfg: Any,
    debug_cfg: Optional[Dict[str, Any]] = None,
) -> Optional[Path]:
    """\
    * Emit a markdown debug file focused on regex-heavy rules and errors.
    - Returns the Path to the written file, or None if disabled or on error.
    """
    debug_cfg = debug_cfg or {}
    enabled = bool(debug_cfg.get("enabled", True))
    if not enabled:
        return None

    try:
        # Resolve timestamp format and log directory
        ts_fmt = getattr(cfg, "ts_format", None) or report.get("ts_format") or "%H-%M_%m-%d"
        ts = datetime.now().strftime(ts_fmt)

        # Normalize / resolve log_dir; cfg.log_dir may already be a Path
        raw_log_dir = getattr(cfg, "log_dir", None) or report.get("log_dir") or "."
        out_dir = Path(raw_log_dir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        log_dir_str = str(out_dir)

        filename = f"Regex_Debug__{ts}.md"
        out_path = out_dir / filename

        max_rules = int(debug_cfg.get("max_rules", 200) or 200)
        max_examples = int(debug_cfg.get("max_examples_per_rule", 3) or 3)

        per_rules = list(report.get("per_rule") or [])[:max_rules]
        invalid_rules = list(report.get("invalid_rules") or [])

        rules_path = getattr(cfg, "rules_path", "") or ""
        rules_root = None
        try:
            if rules_path:
                rules_root = Path(str(rules_path)).expanduser().resolve()
        except Exception:
            rules_root = None

        # --- Helper: decide if a per-rule record is "regex-like" -------------
        def _is_regex_rule(per: Dict[str, Any]) -> bool:
            q = per.get("query")
            if isinstance(q, list):
                q = " ".join(str(x) for x in q)
            q_str = str(q or "")
            if "re:" in q_str:
                return True
            flags = per.get("flags") or ""
            return bool(flags)

        regex_rules = [p for p in per_rules if _is_regex_rule(p)]
        regex_invalids = []
        for item in invalid_rules:
            # invalid_rules entries may be shaped as {"rule": <rule>, "error": ...}
            rule = item.get("rule") or {}
            if _is_regex_rule(rule):
                regex_invalids.append(item)

        if not regex_rules and not regex_invalids:
            # Nothing regex-specific to report
            return None

        lines: List[str] = []

        # Header
        lines.append(f"# Regex Debug — {ts}")
        lines.append("")
        lines.append("Generated by batch_FR engine. This file focuses on regex rules and errors.")
        lines.append("")

        # Sources / settings
        lines.append("## Sources")
        # Prefer the canonical key, but fall back to older report schemas
        rule_files_used = (
            report.get("rules_files_used")
            or report.get("rules_files_expanded")
            or report.get("rules_files_in")
            or []
        )

        rule_files_selected = (
            report.get("rules_files_selected")
            or report.get("rules_files_in")
            or []
        )
        if rule_files_selected:
            lines.append(f"- Rule files selected: {len(rule_files_selected)}")
            lines.append("")
            lines.append("  - Selected:")
            for rf in rule_files_selected:
                _, _, label = _log_rule_group_and_name(rf, rules_root)
                lines.append(f"    - `{label}`")
            lines.append("")

        lines.append(f"- Rule files used: {len(rule_files_used)}")
        if rule_files_used:
            def _rule_file_sort_key(p: Any) -> str:
                try:
                    return Path(str(p)).name.lower()
                except Exception:
                    return str(p).lower()

            lines.append("")
            lines.append("  - Files:")
            for rf in sorted(rule_files_used, key=_rule_file_sort_key):
                _, _, label = _log_rule_group_and_name(rf, rules_root)
                lines.append(f"    - `{label}`")
        lines.append("")

        dry = report.get("dry_run", False)
        lines.append("## Settings")
        lines.append(f"- DRY_RUN (this run): {dry}")
        lines.append(f"- log_dir: `{log_dir_str}`")
        lines.append(f"- ts_format: `{ts_fmt}`")
        lines.append("")

        # Summary
        total_regex = len(regex_rules) + len(regex_invalids)
        compile_errors = sum(1 for item in regex_invalids if str(item.get("error") or "").strip())
        zero_match = sum(
            1
            for per in regex_rules
            if not str(per.get("error") or "").strip()
            and int(per.get("notes_matched") or 0) == 0
        )
        matched_ge1 = sum(
            1
            for per in regex_rules
            if int(per.get("notes_matched") or 0) > 0
        )

        lines.append("## Summary")
        lines.append(f"- Total regex-like rules: {total_regex}")
        lines.append(f"- Compile / runtime errors: {compile_errors}")
        lines.append(f"- 0-match rules (no error): {zero_match}")
        lines.append(f"- Rules that matched ≥1 note: {matched_ge1}")
        lines.append("")

        # Per-rule table
        lines.append("## Per-rule details")
        lines.append("")
        lines.append("| # | source | compile | matches | error | pattern | replacement |")
        lines.append("|---:|--------|---------|--------:|-------|---------|-------------|")

        def _rule_source_name(raw_src: Any) -> str:
            _, _, label = _log_rule_group_and_name(raw_src, rules_root)
            return label or "unknown_source"

        # Valid regex rules
        for per in regex_rules:
            idx = per.get("index", "?")
            src_path, src_file = _pick_rule_source(per)
            raw_src = src_path or src_file or ""
            src = _rule_source_name(raw_src)
            err = str(per.get("error") or "").strip()
            compile_status = "error" if err else "ok"
            matches = int(per.get("notes_matched") or 0)
            pat = str(per.get("pattern") or "")
            rep = str(per.get("replacement") or "")

            err_disp = _format_error_html(err, escape_pipes=True)
            pat_disp = md_table_cell(pat)
            rep_disp = md_table_cell(rep)

            lines.append(
                f"| {idx} | `{src}` | {compile_status} | {matches} | {err_disp or ''} | `{pat_disp}` | `{rep_disp}` |"
            )

        # Invalid regex rules (compile-time errors)
        for item in regex_invalids:
            rule = item.get("rule") or {}
            idx = rule.get("__rule_index", "?")
            raw_src = rule.get("source_path") or rule.get("_source_path") or rule.get("__source_file") or rule.get("source_file") or rule.get("_source_file") or ""
            src = _rule_source_name(raw_src)
            err = str(item.get("error") or "").strip()
            pat = str(rule.get("pattern") or "")
            rep = str(rule.get("replacement") or "")

            err_disp = _format_error_html(err, escape_pipes=True)
            pat_disp = md_table_cell(pat)
            rep_disp = md_table_cell(rep)

            lines.append(
                f"| {idx} | `{src}` | error | — | {err_disp or ''} | `{pat_disp}` | `{rep_disp}` |"
            )

        # Optional examples section
        lines.append("")
        lines.append("## Per-rule examples")
        any_examples = False

        for per in regex_rules:
            examples = list(per.get("examples") or [])[:max_examples]
            has_error = bool(str(per.get("error") or "").strip())
            has_search = bool(str(per.get("search") or "").strip())
            if not examples and not has_error and not has_search:
                continue

            any_examples = True
            idx = per.get("index", "?")

            if _is_remove_rule(per, cfg):
                lines.append("")
                lines.append(f"### Rule {idx} (remove TXT)")
                lines.append("")
                pattern = str(per.get("pattern", "") or "")
                lines.append(f"- pattern: `{md_inline(pattern)}`")
                lines.append(
                    "- details: see `Remove_FR_Debug__*.md` for per-field remove behavior and examples "
                    "(written when a selected rule file ends with `_remove_rule(s).txt`)."
                )
                if has_error:
                    err_html = _format_error_html(per.get("error", ""))
                    lines.append(f"- error: {err_html}")
                # No per-field examples here – those are in the dedicated remove log
                continue
            else:
                lines.append("")
                lines.append(f"### Rule {idx}")
                lines.append("")
                lines.append(f"- query: `{md_inline(per.get('query', ''))}`")
                if per.get("query_input") is not None:
                    lines.append(f"- query_input: `{md_inline(per.get('query_input', ''))}`")
                lines.append(f"- exclude: `{md_inline(per.get('exclude', ''))}`")
                if per.get("exclude_input") is not None:
                    lines.append(f"- exclude_input: `{md_inline(per.get('exclude_input', ''))}`")
                if has_search:
                    lines.append(f"- search (Browser): `{md_inline(per.get('search', ''))}`")
                if has_error:
                    err_html = _format_error_html(per.get("error", ""))
                    lines.append(f"- error: {err_html}")
                lines.append("")
                lines.append("| field | BEFORE | AFTER |")
                lines.append("|---|---|---|")

                for ex in examples:
                    fld = ex.get("field", "")
                    before_raw = str(ex.get("before", ""))
                    after_raw = str(ex.get("after", ""))
                    if dry:
                        before_disp, after_disp = _highlight_diff_snippet(
                            before_raw, after_raw, max_len=240
                        )
                    else:
                        before_disp, after_disp = before_raw, after_raw
                    lines.append(
                        f"| `{md_table_cell(fld)}` | `{md_table_cell(before_disp)}` | `{md_table_cell(after_disp)}` |"
                    )

        if not any_examples:
            lines.append("")
            lines.append("_No examples were recorded for regex rules in this run._")

        out_text = "\n".join(lines) + "\n"
        out_path.write_text(out_text, encoding="utf-8")

        return out_path

    except Exception as e:  # pragma: no cover
        print(f"[batch_FR] Failed to write regex debug markdown: {e}", file=sys.stderr)
        return None


def _init_report(cfg: RunConfig) -> Dict[str, Any]:
    return {
        "ts_format": cfg.ts_format,
        # * Store log_dir as a string in the report for stable markdown rendering
        "log_dir": str(cfg.log_dir),
        # * Extensive-debug settings (may be overridden later from config_snapshot)
        "extensive_debug": getattr(cfg, "extensive_debug", False),
        "extensive_debug_max_examples": getattr(cfg, "extensive_debug_max_examples", 60),
        "rules": 0,
        "notes_touched": 0,        # notes matched by rules
        "notes_changed": 0,        # actual commits
        "notes_would_change": 0,   # simulated changes (esp. DRY_RUN)
        "guard_skips": 0,
        "per_rule": [],
        "report_paths": {},
    }

def _init_per_rule(rule: Any, idx: int) -> Dict[str, Any]:
    # Normalize to a Rule dataclass for consistent access
    try:
        r = _as_rule(rule)
    except Exception:
        # Fail-safe: build a minimal per-rule record
        return {
            "index": idx,
            "file": "",
            "source_file": "",
            "source_path": "",
            "source_index": None,
            "query": [],
            "query_input": [],
            "exclude": [],
            "exclude_input": [],
            "pattern": "",
            "flags": "",
            "fields": [],
            "loop": False,
            # remove-loop logging additions:
            "remove_loop": False,
            "remove_max_loops": 0,
            "remove_loops_used": 0,
            "remove_loops_used_sum": 0,
            "remove_loops_used_max": 0,
            "remove_fields_looped": 0,
            "remove_cap_hits": 0,
            "remove_cycle_hits": 0,
            "remove_empty_match_forced_single": 0,
            # main-rule loop logging additions:
            "fr_loop": False,
            "fr_loops_used": 0,
            "replacement": "",
            "notes_matched": 0,
            "notes_changed": 0,
            "notes_would_change": 0,
            "total_subs": 0,
            "guard_skips": 0,
            "remove_field_subs": 0,
            "examples": [],
            "search": "",
            "search_repr": "",
            "error": "",
        }

    # Source info (dict rules may carry full path; Rule currently carries filename only)
    raw_src = ""
    if isinstance(rule, dict):
        raw_src = (
            rule.get("source_path")
            or rule.get("_source_path")
            or rule.get("__source_file")
            or rule.get("source_file")
            or rule.get("_source_file")
            or ""
        )
    else:
        raw_src = getattr(r, "source_file", None) or ""

    # `file` is a short label (filename-only)
    file_name = ""
    try:
        file_name = Path(str(raw_src)).name if raw_src else (str(getattr(r, "source_file", "")) or "")
    except Exception:
        file_name = str(getattr(r, "source_file", "")) or ""

    # Preserve full path when available (dict rules or Rule dataclass)
    source_path = ""
    if isinstance(rule, dict):
        source_path = str(rule.get("source_path") or rule.get("_source_path") or "")
    else:
        try:
            source_path = str(getattr(r, "source_path", "") or "")
        except Exception:
            source_path = ""

    # Pattern display
    patt_disp = r.pattern if isinstance(r.pattern, str) else (r.pattern[:1] if r.pattern else "")

    # Query/exclude display
    # - rules_io normalizes missing query to []
    # - effective_query() derives include clauses from pattern/fields when input is empty
    include_input: List[str] = []
    if isinstance(r.query, list):
        include_input = [str(x) for x in r.query]
    elif isinstance(r.query, str) and r.query.strip():
        include_input = [r.query.strip()]

    try:
        include_effective = [str(x) for x in (effective_query(r) or [])]
    except Exception:
        include_effective = list(include_input)

    exclude_clauses: List[str] = []
    if isinstance(r.exclude_query, list):
        exclude_clauses = [str(x) for x in r.exclude_query]
    elif isinstance(r.exclude_query, str) and r.exclude_query.strip():
        exclude_clauses = [r.exclude_query.strip()]

    # Compose the actual Browser search string (engine-compatible)
    search = ""
    try:
        search = compose_search(r)
    except Exception:
        search = ""

    return {
        "index": idx,
        # * Short name for backward-compatible displays
        "file": file_name,
        # * Full source path preserved for group-aware logging
        "source_file": file_name,
        "source_path": source_path,
        "source_index": getattr(r, "source_index", None),
        # `query` is the effective include clauses actually used by compose_search()
        "query": include_effective,
        # `query_input` is the raw rule-provided query (often empty)
        "query_input": include_input,
        "exclude": exclude_clauses,
        "exclude_input": exclude_clauses,
        "pattern": patt_disp,
        "flags": r.flags,
        "fields": r.fields,
        "loop": r.loop,
        # --- remove-loop logging additions:
        "remove_loop": False,
        "remove_max_loops": 0,
        "remove_loops_used": 0,
        "remove_loops_used_sum": 0,
        "remove_loops_used_max": 0,
        "remove_fields_looped": 0,
        "remove_cap_hits": 0,
        "remove_cycle_hits": 0,
        "remove_empty_match_forced_single": 0,
        # --- main-rule (JSON) loop logging additions:
        "fr_loop": False,
        "fr_loops_used": 0,
        "replacement": r.replacement,
        "notes_matched": 0,
        "notes_changed": 0,
        "notes_would_change": 0,
        "total_subs": 0,
        "guard_skips": 0,
        "remove_field_subs": 0,
        "examples": [],
        # ! actual Browser search string (precomputed for logging)
        "search": search,
        "search_repr": repr(search),
        "error": "",
    }


def _append_rule_summary(report: Dict[str, Any], per: Dict[str, Any]) -> None:
    report["per_rule"].append(per)
    report["rules"] = len(report["per_rule"])
    report["notes_touched"] += per.get("notes_matched", 0)
    report["notes_changed"] += per.get("notes_changed", 0)
    report["notes_would_change"] += per.get("notes_would_change", 0)
    report["guard_skips"] += per.get("guard_skips", 0)


def _write_reports(report: Dict[str, Any], cfg: RunConfig) -> None:
    # Prefer the config-provided ts_format, fall back to module default if missing
    ts_fmt = cfg.ts_format or TS_FORMAT
    ts = datetime.now().strftime(ts_fmt)
    dry = bool(report.get("dry_run", False))

    # Human-readable summary (kept in-memory only)
    lines: List[str] = []
    lines.append(f"Batch Find & Replace — {ts}")
    lines.append(f"Rules: {report.get('rules', 0)}")
    lines.append(f"Notes matched: {report.get('notes_touched', 0)}")
    if dry:
        lines.append(f"Notes that would change: {report.get('notes_would_change', 0)}")
        lines.append(f"Notes actually changed (DRY RUN): {report.get('notes_changed', 0)}")
    else:
        lines.append(f"Notes changed: {report.get('notes_changed', 0)}")
    lines.append(f"Guard skips: {report.get('guard_skips', 0)}")
    lines.append("")
    for per in report.get("per_rule", []):
        lines.append(f"- Rule {per.get('index')}: fields={per.get('fields')} flags={per.get('flags')} loop={per.get('loop')}")
        lines.append(f"  query={per.get('query')} exclude={per.get('exclude')}")
        if per.get("search"):
            lines.append(f"  search={per.get('search')}")
        if per.get("error"):
            lines.append(f"  error={per.get('error')}")
        matched = per.get("notes_matched", 0)
        would_change = per.get("notes_would_change", 0)
        changed = per.get("notes_changed", 0)
        subs = per.get("total_subs", 0)
        guard_skips = per.get("guard_skips", 0)
        rm_field_subs = per.get("remove_field_subs", 0)
        # --- Fetch remove-loop metrics for summary
        rm_loop = per.get("remove_loop", False)
        rm_max_loops = per.get("remove_max_loops", 0)
        rm_loops_sum = per.get("remove_loops_used_sum", per.get("remove_loops_used", 0))
        rm_loops_max = per.get("remove_loops_used_max", 0)
        rm_fields_looped = per.get("remove_fields_looped", 0)
        rm_cap_hits = per.get("remove_cap_hits", 0)
        rm_cycle_hits = per.get("remove_cycle_hits", 0)
        rm_empty_forced = per.get("remove_empty_match_forced_single", 0)

        # --- Fetch main-rule loop metrics for summary
        fr_loop = per.get("fr_loop", False)
        fr_loops_used = per.get("fr_loops_used", 0)
        fr_empty_forced = per.get("fr_empty_match_forced_single", 0)
        fr_break_stable = per.get("fr_break_stable", 0)
        fr_break_cap = per.get("fr_break_cap", 0)
        fr_break_cycle = per.get("fr_break_cycle", 0)

        if dry:
            lines.append(
                f"  matched={matched} "
                f"would_change={would_change} "
                f"subs={subs} "
                f"guard_skips={guard_skips} "
                f"rm_field_subs={rm_field_subs} "
                f"rm_loop={rm_loop} "
                f"rm_loops_sum={rm_loops_sum} "
                f"rm_loops_max={rm_loops_max} "
                f"rm_fields_looped={rm_fields_looped} "
                f"rm_cap_hits={rm_cap_hits} "
                f"rm_cycle_hits={rm_cycle_hits} "
                f"rm_empty_forced={rm_empty_forced} "
                f"rm_max_loops={rm_max_loops} "
                f"fr_loop={fr_loop} "
                f"fr_loops_used={fr_loops_used} "
                f"fr_break_stable={fr_break_stable} "
                f"fr_break_cap={fr_break_cap} "
                f"fr_break_cycle={fr_break_cycle} "
                f"fr_empty_forced={fr_empty_forced}"
            )
        else:
            lines.append(
                f"  matched={matched} "
                f"changed={changed} "
                f"subs={subs} "
                f"guard_skips={guard_skips} "
                f"rm_field_subs={rm_field_subs} "
                f"rm_loop={rm_loop} "
                f"rm_loops_sum={rm_loops_sum} "
                f"rm_loops_max={rm_loops_max} "
                f"rm_fields_looped={rm_fields_looped} "
                f"rm_cap_hits={rm_cap_hits} "
                f"rm_cycle_hits={rm_cycle_hits} "
                f"rm_empty_forced={rm_empty_forced} "
                f"rm_max_loops={rm_max_loops} "
                f"fr_loop={fr_loop} "
                f"fr_loops_used={fr_loops_used} "
                f"fr_break_stable={fr_break_stable} "
                f"fr_break_cap={fr_break_cap} "
                f"fr_break_cycle={fr_break_cycle} "
                f"fr_empty_forced={fr_empty_forced}"
            )
        ex = per.get("examples", [])
        for i, e in enumerate(ex, 1):
            lines.append(f"  ex{i} [{e.get('field','?')}]: BEFORE: {e.get('before','')}")
            lines.append(f"  ex{i} [{e.get('field','?')}]: AFTER : {e.get('after','')}")
        lines.append("")

    # Store the text summary in the report (no files written here)
    details_txt = "\n".join(lines)
    report["details_txt"] = details_txt