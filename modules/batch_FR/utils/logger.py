import re
import sys
import json
import csv
from html import unescape
from pathlib import Path
from datetime import datetime
import time
from typing import Optional, Iterable, List, Dict, Any

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


# --- Batch Find & Replace debug writer --------------------------------------


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

        log_dir = getattr(cfg, "log_dir", None) or report.get("log_dir") or "."
        out_dir = Path(log_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

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
        lines.append(f"- DRY_RUN (this run): {dry}")
        lines.append(f"- log_dir: `{log_dir}`")
        rules_path = getattr(cfg, "rules_path", "")
        lines.append(f"- rules_path: `{rules_path}`")
        rules_files_used = report.get("rules_files_used")
        if isinstance(rules_files_used, (list, tuple)) and rules_files_used:
            lines.append(f"- rule_files_used ({len(rules_files_used)}):")
            for rf in rules_files_used:
                try:
                    lines.append(f"  - `{str(rf)}`")
                except Exception:
                    lines.append(f"  - `{rf}`")
        else:
            lines.append("- rule_files_used: (all discovered under rules_path)")
        lines.append(f"- ts_format: `{ts_fmt}`")
        lines.append(f"- log_mode: `{getattr(cfg, 'log_mode', '')}`")
        lines.append(f"- include_unchanged: {getattr(cfg, 'include_unchanged', False)}")
        lines.append(f"- max_loops: {getattr(cfg, 'max_loops', 0)}")
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
            lines.append("| # | error | pattern | replacement |")
            lines.append("|---:|---|---|---|")
            for idx, item in enumerate(invalid_rules, start=1):
                rule = item.get("rule") or {}
                err = str(item.get("error") or "")
                pat = str(rule.get("pattern", ""))
                rep = str(rule.get("replacement", ""))
                lines.append(f"| {idx} | `{err}` | `{pat}` | `{rep}` |")
        lines.append("")

        # Per-rule details table
        lines.append("## Per-rule details")
        if not per_rules:
            lines.append("_No rules were executed._")
        else:
            # Table 1: core numeric stats
            lines.append("")
            if dry:
                lines.append("| # | fields | flags | loop | matched | would_change | subs | guard_skips | rm_field_subs |")
            else:
                lines.append("| # | fields | flags | loop | matched | changed | subs | guard_skips | rm_field_subs |")
            lines.append("|---:|---|---|---|---:|---:|---:|---:|---:|")
            for per in per_rules:
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
                if dry:
                    lines.append(
                        f"| {idx} | `{fields_disp}` | `{flags}` | {loop} | {matched} | {would_change} | {subs} | {guard_skips} | {rm_field_subs} |"
                    )
                else:
                    lines.append(
                        f"| {idx} | `{fields_disp}` | `{flags}` | {loop} | {matched} | {changed} | {subs} | {guard_skips} | {rm_field_subs} |"
                    )

            # Table 2: error / pattern / replacement
            lines.append("")
            lines.append("| # | error | pattern | replacement |")
            lines.append("|---:|---|---|---|")
            for per in per_rules:
                idx = per.get("index", "?")
                err = str(per.get("error", "") or "")
                pat = per.get("pattern", "")
                rep = per.get("replacement", "")
                # Escape pipes so the Markdown table doesn't break
                err_disp = err.replace("|", "\\|")
                pat_disp = str(pat).replace("|", "\\|")
                rep_disp = str(rep).replace("|", "\\|")
                lines.append(
                    f"| {idx} | `{err_disp}` | `{pat_disp}` | `{rep_disp}` |"
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
            lines.append("")
            lines.append(f"### Rule {idx}")
            lines.append("")
            lines.append(f"- query: `{per.get('query', '')}`")
            lines.append(f"- exclude: `{per.get('exclude', '')}`")
            if has_search:
                lines.append(f"- search (Browser): `{per.get('search', '')}`")
            if has_error:
                lines.append(f"- error: `{per.get('error', '')}`")
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
                    before_disp, after_disp = _highlight_diff_snippet(before_raw, after_raw, max_len=240)
                else:
                    before_disp, after_disp = before_raw, after_raw
                lines.append(f"| `{fld}` | `{before_disp}` | `{after_disp}` |")

        if not any_examples:
            lines.append("")
            lines.append("_No examples were recorded for this run._")

        out_text = "\n".join(lines) + "\n"
        out_path.write_text(out_text, encoding="utf-8")
        return out_path

    except Exception as e:  # pragma: no cover
        print(f"[batch_FR] Failed to write debug markdown: {e}", file=sys.stderr)
        return None