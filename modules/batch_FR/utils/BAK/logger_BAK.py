import re
import sys
import json
import csv
from html import unescape
from pathlib import Path
from datetime import datetime
import time
from typing import Optional, Iterable, List, Dict, Any
from collections import defaultdict
from ...log_cleanup import delete_old_anki_log_files
from .FR_global_utils import now_stamp


# --- Internal helpers for human-friendly previews ---------------------------

def _scrub_whitespace_tokens_global(pat: str) -> str:
    """\
    * Make whitespace tokens a bit more readable in preview strings.
    - Example: "re:foo\\s*bar" -> "re:foo *bar".
    """
    s = str(pat or "")
    # Show common whitespace tokens in a compact, readable way
    s = re.sub(r"\\s\*", " *", s)
    s = re.sub(r"\\s\+", " +", s)
    s = re.sub(r"\\s\?", " ?", s)
    s = re.sub(r"\\s", " ␣", s)  # generic \s fallback
    return s


def format_field_re_clause_preview(field: str, display_pat: str) -> str:
    """\
    * Format a single field-specific regex clause for preview.
    - Example: field="Text", display_pat="^foo *bar" -> "\"Text:re:^foo *bar\"".
    """
    f = (field or "").strip()
    return f'"{f}:re:{display_pat}"'


# --- Rule provenance helper (for logs/reports) -------------------------------

def rule_prov(rule: dict) -> str:
    try:
        src = Path(str(rule.get("__source_file") or "")).name
    except Exception:
        src = str(rule.get("__source_file") or "?")
    idx = rule.get("__rule_index")
    nm = (rule.get("name") or "").strip()
    base = f"[{src}#{idx}]" if idx is not None else (f"[{src}]" if src else "[?]")
    return f"{base} {nm}" if nm else base


# --- Helper: group-aware label for rule file sources ---
def _log_rule_group_and_name(raw_src: Any, rules_root: Path | None) -> tuple[str, str, str]:
    """
    Return (group, file_name, display_label) for a rule source.

    - group: first folder under rules_root, or "" if not applicable
    - file_name: basename of the file
    - display_label: "[group] file_name" if group present, else "file_name"
    """
    if not raw_src:
        return "", "", "<?>"

    try:
        p = Path(str(raw_src)).expanduser().resolve()
    except Exception:
        s = str(raw_src)
        s = s or "<?>"
        return "", s, s

    file_name = p.name or "<?>"

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
        per.get("source_file"),
        per.get("file"),
        per.get("__source_file"),
    ]

    rule_meta = per.get("rule")
    if isinstance(rule_meta, dict):
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

    # Heuristic: any file with "remove_rules" in the name is considered TXT-based remove
    if "remove_rules" in src_name:
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



def _effective_fields_for_remove_rule(per: Dict[str, Any], cfg: Any) -> list[str] | None:
    """Resolve the field list that a remove TXT rule conceptually acts on.

    Precedence:
    1) per-rule fields
    2) cfg.fields
    3) cfg.fields_all
    """
    fields = per.get("fields")
    if isinstance(fields, str):
        fields = [fields]
    if fields:
        return list(fields)

    cfg_fields = getattr(cfg, "fields", None)
    if isinstance(cfg_fields, str):
        cfg_fields = [cfg_fields]
    if cfg_fields:
        return list(cfg_fields)

    cfg_all = getattr(cfg, "fields_all", None)
    if isinstance(cfg_all, str):
        cfg_all = [cfg_all]
    if cfg_all:
        return list(cfg_all)

    return None

# --- Helper: expand remove-rule fields for per-field blocks in debug logs ---
def _iter_remove_rule_fields(per: Dict[str, Any], cfg: Any) -> list[str]:
    """Return the list of fields for which we should render a separate
    virtual 'field remove' rule block in the debug markdown.
    """
    fields = _effective_fields_for_remove_rule(per, cfg)
    if not fields:
        # No specific fields → treat as global remove rule (single block)
        return []
    # Normalize and deduplicate
    norm: list[str] = []
    seen: set[str] = set()
    for f in fields:
        s = str(f).strip()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            norm.append(s)
    return norm


def _build_remove_query_and_search_preview(
    per: Dict[str, Any],
    cfg: Any,
) -> tuple[str, str]:
    """Build query + search previews for TXT-based remove rules.

    Each line in a remove TXT file is treated as acting on each configured
    field separately, so we represent it as a field-aware OR clause such as:
      "Field1:re:<pattern>" OR "Field2:re:<pattern>" ...

    Returns (query_preview, search_preview).
    """
    pattern = str(per.get("pattern", "") or "")
    if not pattern:
        # Fall back to whatever the engine recorded
        q = str(per.get("query", "") or "")
        s = str(per.get("search", "") or "")
        return q, s

    fields = _effective_fields_for_remove_rule(per, cfg)
    base = f"re:{pattern}"
    preview = build_field_or_query_preview(base, fields or [])
    # For remove-only rules, Browser search should mirror the same field-aware clause
    return preview, preview


def build_field_or_query_preview(pattern: str, fields: list[str] | None) -> str:
    """
    $ PREVIEW: Human-friendly line for ACFR/logs.
      - Global → re:<pattern> after whitespace token scrubbing
      - Fielded → ( "Field:re:<pattern>" OR ... ) with outer quotes for each clause
    """
    pat = str(pattern or "")
    if pat.startswith("re:"):
        pat = pat[3:]
    # Show \s*, \s+, etc. as ' *', ' +' for readability
    display_pat = _scrub_whitespace_tokens_global("re:" + pat)[3:]

    norm: list[str] = []
    if fields:
        for f in fields:
            s = str(f).strip()
            if s:
                norm.append(s)
    if not norm or any(f.lower() == "all" for f in norm):
        return f"re:{display_pat}"
    seen = set()
    uniq: list[str] = []
    for f in norm:
        if f not in seen:
            uniq.append(f); seen.add(f)
    clauses = [format_field_re_clause_preview(f, display_pat) for f in uniq]
    if len(clauses) == 1:
        # Single field (preview): show bare clause without outer parentheses
        return clauses[0]
    return "(" + " OR ".join(clauses) + ")"


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
    rules_root: Path | None,
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
            raw_src = per.get("source_file") or per.get("file") or ""
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

                # Keep markdown tables intact by escaping pipes in the content
                before_disp = before_disp.replace("|", "\\|")
                after_disp = after_disp.replace("|", "\\|")
                fld_disp = str(fld).replace("|", "\\|")

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
    debug_cfg: Dict[str, Any] | None = None,
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

        rules_files_used = report.get("rules_files_used")
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

                raw_src = rule.get("__source_file") or ""
                _, fname, label = _log_rule_group_and_name(raw_src, rules_root)
                if not label:
                    label = "<?>"

                err_disp = _format_error_html(err, escape_pipes=True)
                pat_disp = str(pat).replace("|", "\\|")
                rep_disp = str(rep).replace("|", "\\|")
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
                raw_src = per.get("source_file") or per.get("file") or ""
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
                    lines.append("| # | fields | flags | loop | matched | would_change | subs | guard_skips | rm_field_subs | rm_loop | rm_loops_used | rm_max_loops |")
                else:
                    lines.append("| # | fields | flags | loop | matched | changed | subs | guard_skips | rm_field_subs | rm_loop | rm_loops_used | rm_max_loops |")
                lines.append("|---:|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|")

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
                    rm_loops_used = per.get("remove_loops_used", 0)
                    rm_max_loops = per.get("remove_max_loops", 0)

                    if dry:
                        lines.append(
                            f"| {idx} | `{fields_disp}` | `{flags}` | {loop} | {matched} | {would_change} | {subs} | {guard_skips} | {rm_field_subs} | {rm_loop} | {rm_loops_used} | {rm_max_loops} |"
                        )
                    else:
                        lines.append(
                            f"| {idx} | `{fields_disp}` | `{flags}` | {loop} | {matched} | {changed} | {subs} | {guard_skips} | {rm_field_subs} | {rm_loop} | {rm_loops_used} | {rm_max_loops} |"
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

                raw_src = per.get("source_file") or per.get("file") or ""
                _, fname, label = _log_rule_group_and_name(raw_src, rules_root)
                if not label:
                    label = "<?>"

                # Escape pipes so the Markdown table doesn't break
                err_disp = _format_error_html(err, escape_pipes=True)
                pat_disp = str(pat).replace("|", "\\|")
                rep_disp = str(rep).replace("|", "\\|")
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

            # TXT-based remove rules: render one block per field
            if _is_remove_rule(per, cfg):
                pattern = str(per.get("pattern", "") or "")
                exclude = per.get("exclude", "")
                # Determine which fields should get their own "virtual" rule block
                fields_for_blocks = _iter_remove_rule_fields(per, cfg)
                if not fields_for_blocks:
                    # No specific fields → single generic remove block
                    fields_for_blocks = [None]

                for field_name in fields_for_blocks:
                    lines.append("")
                    if field_name:
                        lines.append(f"### *{field_name}* field remove")
                    else:
                        lines.append(f"### Rule {idx} (remove)")
                    lines.append("")

                    field_prefix = f"{field_name}:" if field_name else ""
                    query = f"{field_prefix}re:{pattern}" if pattern else str(per.get("query", "") or "")
                    lines.append(f"- query: `{query}`")
                    lines.append(f"- exclude: `{exclude}`")
                    # For remove-only rules, Browser search mirrors the same field-specific query
                    lines.append(f"- search (Browser): `{query}`")

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

                    # Only show examples for this field in this block (or all if field_name is None)
                    for ex in examples:
                        fld = str(ex.get("field", ""))
                        if field_name and fld != field_name:
                            continue
                        before_raw = str(ex.get("before", ""))
                        after_raw = str(ex.get("after", ""))
                        if dry:
                            before_disp, after_disp = _highlight_diff_snippet(
                                before_raw, after_raw, max_len=240
                            )
                        else:
                            before_disp, after_disp = before_raw, after_raw
                        lines.append(f"| `{fld}` | `{before_disp}` | `{after_disp}` |")

            else:
                # Normal rule → keep existing behavior
                lines.append("")
                lines.append(f"### Rule {idx}")
                lines.append("")
                lines.append(f"- query: `{per.get('query', '')}`")
                lines.append(f"- exclude: `{per.get('exclude', '')}`")
                if has_search:
                    lines.append(f"- search (Browser): `{per.get('search', '')}`")
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
                    lines.append(f"| `{fld}` | `{before_disp}` | `{after_disp}` |")

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

        # * Clean up old log files after writing a new debug log
        try:
            # ! New signature: cleanup is count-based; we just pass the base_dir and disable dry_run
            delete_old_anki_log_files(
                base_dir=out_dir,
                dry_run=False,
            )
        except Exception as e:
            print(f"[batch_FR] Log cleanup failed: {e}", file=sys.stderr)

        return out_path

    except Exception as e:  # pragma: no cover
        print(f"[batch_FR] Failed to write debug markdown: {e}", file=sys.stderr)
        return None


def write_regex_debug(
    report: Dict[str, Any],
    cfg: Any,
    debug_cfg: Dict[str, Any] | None = None,
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
        rule_files_used = report.get("rules_files_used") or []
        lines.append(f"- Rule files: {len(rule_files_used)}")
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
            return label

        # Valid regex rules
        for per in regex_rules:
            idx = per.get("index", "?")
            raw_src = per.get("file") or per.get("source_file") or ""
            src = _rule_source_name(raw_src)
            err = str(per.get("error") or "").strip()
            compile_status = "error" if err else "ok"
            matches = int(per.get("notes_matched") or 0)
            pat = str(per.get("pattern") or "")
            rep = str(per.get("replacement") or "")

            err_disp = _format_error_html(err, escape_pipes=True)
            pat_disp = pat.replace("|", "\\|")
            rep_disp = rep.replace("|", "\\|")

            lines.append(
                f"| {idx} | `{src}` | {compile_status} | {matches} | {err_disp or ''} | `{pat_disp}` | `{rep_disp}` |"
            )

        # Invalid regex rules (compile-time errors)
        for item in regex_invalids:
            rule = item.get("rule") or {}
            idx = rule.get("__rule_index", "?")
            raw_src = rule.get("__source_file") or ""
            src = _rule_source_name(raw_src)
            err = str(item.get("error") or "").strip()
            pat = str(rule.get("pattern") or "")
            rep = str(rule.get("replacement") or "")

            err_disp = _format_error_html(err, escape_pipes=True)
            pat_disp = pat.replace("|", "\\|")
            rep_disp = rep.replace("|", "\\|")

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
                # TXT-based remove rule → one block per field
                pattern = str(per.get("pattern", "") or "")
                exclude = per.get("exclude", "")
                fields_for_blocks = _iter_remove_rule_fields(per, cfg)
                if not fields_for_blocks:
                    fields_for_blocks = [None]

                for field_name in fields_for_blocks:
                    lines.append("")
                    if field_name:
                        lines.append(f"### *{field_name}* field remove")
                    else:
                        lines.append(f"### Rule {idx} (remove)")
                    lines.append("")

                    field_prefix = f"{field_name}:" if field_name else ""
                    query = f"{field_prefix}re:{pattern}" if pattern else str(per.get("query", "") or "")
                    lines.append(f"- query: `{query}`")
                    lines.append(f"- exclude: `{exclude}`")
                    # For remove-only rules, Browser search mirrors the same field-specific query
                    lines.append(f"- search (Browser): `{query}`")

                    if has_error:
                        err_html = _format_error_html(per.get("error", ""))
                        lines.append(f"- error: {err_html}")
                    lines.append("")
                    lines.append("| field | BEFORE | AFTER |")
                    lines.append("|---|---|---|")

                    for ex in examples:
                        fld = str(ex.get("field", ""))
                        if field_name and fld != field_name:
                            continue
                        before_raw = str(ex.get("before", ""))
                        after_raw = str(ex.get("after", ""))
                        if dry:
                            before_disp, after_disp = _highlight_diff_snippet(
                                before_raw, after_raw, max_len=240
                            )
                        else:
                            before_disp, after_disp = before_raw, after_raw
                        lines.append(f"| `{fld}` | `{before_disp}` | `{after_disp}` |")
            else:
                lines.append("")
                lines.append(f"### Rule {idx}")
                lines.append("")
                lines.append(f"- query: `{per.get('query', '')}`")
                lines.append(f"- exclude: `{per.get('exclude', '')}`")
                if has_search:
                    lines.append(f"- search (Browser): `{per.get('search', '')}`")
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
                    lines.append(f"| `{fld}` | `{before_disp}` | `{after_disp}` |")

        if not any_examples:
            lines.append("")
            lines.append("_No examples were recorded for regex rules in this run._")

        out_text = "\n".join(lines) + "\n"
        out_path.write_text(out_text, encoding="utf-8")

        # Clean up old log files after writing a new regex debug log
        try:
            # ! New signature: cleanup is count-based; we just pass the base_dir and disable dry_run
            delete_old_anki_log_files(
                base_dir=out_dir,
                dry_run=False,
            )
        except Exception as e:
            print(f"[batch_FR] Regex log cleanup failed: {e}", file=sys.stderr)

        return out_path

    except Exception as e:  # pragma: no cover
        print(f"[batch_FR] Failed to write regex debug markdown: {e}", file=sys.stderr)
        return None

