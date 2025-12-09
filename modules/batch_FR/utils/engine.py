from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
import re

# * Anki/Qt import guarded for testability
try:
    from aqt import mw
except Exception:
    mw = None 

from .rules_io import (
    load_rules_from_file,
    load_rules_from_config,
    load_remove_sets_from_config,
    normalize_rule,
)
from .regex_utils import (
    apply_rule_defaults,
    validate_regex_replacement,
    subn_until_stable,
    deletion_exceeds_limit,
    ensure_dir,
    ensure_parent,
    flags_from_str,
    apply_substitution,
    basic_html_cloze_balance_ok,
)
from .text_utils import safe_truncate
from .logger import write_batch_fr_debug, write_regex_debug
import json
from datetime import datetime

__all__ = ["run_batch_find_replace"]

from .FR_global_utils import (
    Rule, RunConfig,
    TS_FORMAT,
    _coerce_int,
    _norm_path,
    
)

# =========================
# Public entrypoint
# =========================
def run_batch_find_replace(
    mw_ref,
    *,
    rulesets: List[Union[str, Path, Dict[str, Any]]],
    config_snapshot: Dict[str, Any],
    remove_rules: Optional[Union[str, Path]] = None,
    field_remove_rules: Optional[Union[str, Path]] = None,
    dry_run: Optional[bool] = None,
    show_progress: bool = True,
    notes_limit: Optional[int] = None,
    rules_files: Optional[Sequence[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """\
    * Orchestrate: load rules, search notes, apply, and log (pure in-Anki).
    - Returns a summary report dict (file paths, counters, timings).

    Note: `show_progress` is currently a placeholder; progress UI is not yet implemented.
    """
    cfg = _coerce_run_config(config_snapshot)
    dry = bool(dry_run) if dry_run is not None else False
    # * Extensive debugging: optional heavy logging mode controlled by UI/config
    extensive_debug = bool(config_snapshot.get("extensive_debug", False))
    try:
        extensive_debug_max_examples = int(config_snapshot.get("extensive_debug_max_examples", 60))
    except Exception:
        extensive_debug_max_examples = 60

    # ! Dedicated loop cap for remove rules (can be overridden via remove_config.max_loops)
    remove_cfg = getattr(cfg, "remove_config", {}) or {}
    try:
        remove_max_loops = int(remove_cfg.get("max_loops", cfg.max_loops))
    except Exception:
        remove_max_loops = cfg.max_loops
    # Global on/off switch for remove-rule looping
    remove_global_loop = bool(remove_cfg.get("loop", True))

    # 1) Discover + load rules (deterministic; honors order_preference, Defaults)
    cfg_dict: Dict[str, Any] = dict(config_snapshot)
    rules: List[Dict[str, Any]] = []

    if rules_files is not None:
        # * When a subset of rule files is provided (e.g. from the toolbar UI),
        # * restrict loading to just those paths, but skip remove-rule files
        remove_suffix = cfg_dict.get("remove_rules_suffix") or ""
        field_remove_name = cfg_dict.get("field_remove_rules_name") or ""

        for rf in rules_files:
            try:
                name = Path(rf).name
            except Exception:
                name = str(rf)

            # Skip known remove-rule files here; they are handled via load_remove_sets_from_config
            if field_remove_name and name == field_remove_name:
                continue
            if remove_suffix and name.endswith(remove_suffix):
                continue

            try:
                rules.extend(
                    load_rules_from_file(
                        rf,
                        defaults=cfg.defaults,
                        fields_all=cfg.fields_all,
                    )
                )
            except Exception:
                # ignore bad paths; they will be surfaced via report if needed
                pass
    else:
        # * Default behavior: load according to config (rules_path, order_preference, etc.)
        rules.extend(load_rules_from_config(cfg_dict))

    # Accept any in-memory rule dicts (normalize for safety)
    rules.extend([normalize_rule(r) for r in rulesets if isinstance(r, dict)])

    # Also accept rule file paths passed in rulesets
    for rs in rulesets:
        if isinstance(rs, (str, Path)):
            try:
                rules.extend(
                    load_rules_from_file(
                        rs,
                        defaults=cfg.defaults,
                        fields_all=cfg.fields_all,
                    )
                )
            except Exception:
                # ignore bad paths; they will be surfaced via report if needed
                pass

    # 2) Normalize + defaults per rule, then pre-validate replacements
    ready: List[Rule] = []
    invalid_rules: List[Dict[str, Any]] = []
    for r in rules:
        # light-touch defaults + normalization
        r = apply_rule_defaults(r)
        r = normalize_rule(r)
        ok, msg = validate_regex_replacement(
            r.get("pattern", ""),
            r.get("replacement", ""),
            r.get("flags", "m"),
        )
        if not ok:
            invalid_rules.append({"rule": r, "error": msg})
            continue
        ready.append(_as_rule(r))

    # 3) Optional remove sets shaped as rules
    #    Allow function args to override config paths when provided.
    if remove_rules is not None:
        cfg_dict["remove_path"] = str(remove_rules)
    if field_remove_rules is not None:
        cfg_dict["field_remove_path"] = str(field_remove_rules)

    remove_sets = load_remove_sets_from_config(cfg_dict)
    remove_ruleset: List[Dict[str, Any]] = remove_sets.get("remove", [])
    field_remove_ruleset: List[Dict[str, Any]] = remove_sets.get("field_remove", [])

    # 4) Init report and carry invalid rules / dry-run flag
    report: Dict[str, Any] = _init_report(cfg)
    if rules_files is not None:
        report["rules_files_used"] = [str(Path(p)) for p in rules_files]
    else:
        report["rules_files_used"] = None
    report["invalid_rules"] = invalid_rules
    report["dry_run"] = dry
    # * Surface extensive-debug settings in the in-memory report for downstream loggers
    report["extensive_debug"] = extensive_debug
    report["extensive_debug_max_examples"] = extensive_debug_max_examples

    for idx, rule in enumerate(ready, start=1):
        per = _init_per_rule(rule, idx)
        # * Record the configured remove loop cap so it shows up in logs
        per["remove_max_loops"] = remove_max_loops
        # ! Translate $1-style backrefs into Python-compatible replacement once per rule
        py_repl = _coerce_repl_for_python(rule.replacement, rule.regex)
        try:
            search_str = _compose_search(rule)
            per["search"] = search_str  # ! store actual Browser search text for logging
            nids = mw_ref.col.find_notes(search_str)
            per["notes_matched"] = len(nids)
            if notes_limit:
                nids = nids[:notes_limit]

            for nid in nids:
                note = mw_ref.col.get_note(nid)
                changed_this_note = False
                for field in _resolve_fields(note, rule.fields, cfg.fields_all):
                    before = note[field]
                    working = before

                    # 4a) Apply global remove patterns (from remove.txt) first
                    for rr in remove_ruleset:
                        patt = rr.get("pattern", "")
                        if not patt:
                            continue
                        repl = rr.get("replacement", "")  # TXT-based remove rules will use "" here

                        # Per-remove-rule flag
                        rr_loop_flag = bool(rr.get("loop", True))
                        # Effective behavior: must satisfy both per-rule and global toggle
                        effective_loop = rr_loop_flag and remove_global_loop
                        loops_cap = remove_max_loops if effective_loop else 1

                        working, rm_n, loops_used = apply_substitution(
                            patt,
                            repl,
                            working,
                            is_regex=bool(rr.get("regex", True)),
                            flags=rr.get("flags", "ms"),
                            max_loops=loops_cap,
                        )
                        if rm_n:
                            per["remove_field_subs"] += rm_n
                        if loops_used:
                            per["remove_loops_used"] += loops_used
                            if effective_loop:
                                per["remove_loop"] = True

                    # 4b) Apply field-remove patterns (from remove_fields.txt) next (replace with "")
                    for rr in field_remove_ruleset:
                        patt = rr.get("pattern", "")
                        if not patt:
                            continue

                        rr_loop_flag = bool(rr.get("loop", True))
                        effective_loop = rr_loop_flag and remove_global_loop
                        loops_cap = remove_max_loops if effective_loop else 1

                        working, rm_n, loops_used = apply_substitution(
                            patt,
                            "",
                            working,
                            is_regex=bool(rr.get("regex", True)),
                            flags=rr.get("flags", "ms"),
                            max_loops=loops_cap,
                        )
                        if rm_n:
                            per["remove_field_subs"] += rm_n
                        if loops_used:
                            per["remove_loops_used"] += loops_used
                            if effective_loop:
                                per["remove_loop"] = True

                    # 4c) Apply main rule (supports pattern list + literal/regex)
                    patterns: List[str] = rule.pattern if isinstance(rule.pattern, list) else [str(rule.pattern)]
                    loops_cap = cfg.max_loops if rule.loop else 1

                    after = working
                    total_subs_this_field = 0
                    for patt in patterns:
                        after, subs, loops_used = apply_substitution(
                            patt,
                            py_repl,
                            after,
                            is_regex=rule.regex,
                            flags=rule.flags,
                            max_loops=loops_cap,
                        )
                        total_subs_this_field += subs

                    # 4d) Guard against deletions using original before and final after
                    if _guard_exceeded(rule, before, after):
                        per["guard_skips"] += 1
                        continue

                    # 4e) Guard against broken HTML/cloze structure when it was valid before
                    if not basic_html_cloze_balance_ok(before, after):
                        per["guard_skips"] += 1
                        continue

                    if after != working:
                        changed_this_note = True
                        per["total_subs"] += total_subs_this_field
                        # capture up to 2 examples
                        if len(per["examples"]) < 2:
                            per["examples"].append({
                                "field": field,
                                "before": safe_truncate(before, 500, count_spaces=True),
                                "after": safe_truncate(after, 500, count_spaces=True),
                            })
                        # assign but defer update_note until after all fields processed
                        if not dry:
                            note[field] = after

                if changed_this_note:
                    # This note WOULD change under this rule
                    per["notes_would_change"] += 1
                    # Only count as actually changed and persist when not DRY_RUN
                    if not dry:
                        per["notes_changed"] += 1
                        mw_ref.col.update_note(note)

            _append_rule_summary(report, per)

        except Exception as e:
            per["error"] = str(e)
            _append_rule_summary(report, per)

    # 5) Commit once at end
    if not dry:
        mw_ref.col.save()

    # 6) Build in-memory summary (no JSON/TXT files written)
    _write_reports(report, cfg)

    # 7) Optional markdown debug files
    debug_cfg = dict(config_snapshot.get("batch_fr_debug", {}) or {})
    if extensive_debug:
        # * In extensive-debug mode, allow more examples per rule (default 60)
        debug_cfg.setdefault("max_examples_per_rule", extensive_debug_max_examples)
    debug_path = write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
    if debug_path is not None:
        report.setdefault("report_paths", {})["debug_markdown"] = str(debug_path)

    regex_debug_path = write_regex_debug(report, cfg, debug_cfg=debug_cfg)
    if regex_debug_path is not None:
        report.setdefault("report_paths", {})["regex_debug_markdown"] = str(regex_debug_path)

    return report

# =========================
# Internals
# =========================
def _coerce_run_config(d: Dict[str, Any]) -> RunConfig:
    """
    * Coerce a plain dict snapshot into a RunConfig.
    - Normalizes log_dir so it can safely be a Path or string.
    """
    raw_log_dir = d.get("log_dir", "")
    if isinstance(raw_log_dir, Path):
        log_dir_val = raw_log_dir
    else:
        # * Allow downstream helpers (and config) to use either a raw string
        # * or a normalized path; empty stays empty.
        log_dir_val = _norm_path(raw_log_dir) if raw_log_dir else ""

    return RunConfig(
        ts_format=d.get("ts_format", TS_FORMAT),
        log_dir=log_dir_val,
        rules_path=d.get("rules_path", ""),
        fields_all=list(d.get("fields_all", [])),
        defaults=dict(d.get("defaults", {})),
        remove_config=dict(d.get("remove_config", {})),
        log_mode=d.get("log_mode", "diff"),
        include_unchanged=bool(d.get("include_unchanged", False)),
        max_loops=int(d.get("max_loops", 30)),
        order_preference=dict(d.get("order_preference", {})),
    )

def _as_rule(r: Dict[str, Any]) -> Rule:
    return Rule(
        query=r.get("query", ""),
        exclude_query=r.get("exclude_query"),
        pattern=r.get("pattern", ""),
        replacement=r.get("replacement", ""),
        regex=bool(r.get("regex", True)),
        flags=r.get("flags", "m"),
        fields=list(r.get("fields", ["ALL"])),
        loop=bool(r.get("loop", False)),
        delete_chars=dict(r.get("delete_chars", {"max_chars": 0, "count_spaces": True})),
        source_file=r.get("__source_file"),
        source_index=r.get("__source_index"),
    )

def _compose_search(rule: Rule) -> str:
    """
    * Build Browser search text from rule.query/exclude_query.
    - String or list[str] (AND-join); excludes prefixed with -("...")
    - Quote clauses that contain whitespace.
    """
    def _q(s: str) -> str:
        """
        * Normalize a single search clause for the Browser.
        - Always quote regex-based clauses (re:...), even if they have no spaces.
        - Quote other clauses only when they contain whitespace.
        - Avoid double-quoting if the clause is already wrapped in quotes.
        """
        s = s.strip()
        if not s:
            return s

        # If already quoted, leave as-is
        if len(s) >= 2 and s[0] == s[-1] == '"':
            return s

        # ! For regex searches, Anki expects the whole clause quoted so that
        # ! backslashes (\\w, \\n, \\{, \\}, etc.) are passed through to the
        # ! regex engine instead of being interpreted by the outer search parser.
        if s.lstrip().startswith("re:"):
            return f'"{s}"'

        # Otherwise, only quote when there is whitespace
        return f'"{s}"' if any(ch.isspace() for ch in s) else s

    parts: List[str] = []

    # Use effective query (explicit query or derived from pattern)
    eff_q = _effective_query(rule)
    if isinstance(eff_q, list):
        parts.extend([_q(s) for s in eff_q if str(s).strip()])
    elif isinstance(eff_q, str) and eff_q.strip():
        parts.append(_q(eff_q))

    ex = rule.exclude_query
    if isinstance(ex, list):
        parts.extend([f'-({_q(s)})' for s in ex if str(s).strip()])
    elif isinstance(ex, str) and ex.strip():
        parts.append(f'-({_q(ex)})')

    # If we somehow still have nothing, fall back to deck:*
    return " ".join(parts) if parts else "deck:*"

def _resolve_fields(note, fields_spec: List[str], fields_all: List[str]) -> List[str]:
    """
    * Expand ["ALL"] to fields_all; filter to fields present on the note's model.
    """
    wanted = fields_all if (fields_spec == ["ALL"] and fields_all) else (list(note.keys()) if fields_spec == ["ALL"] else fields_spec)
    model_fields = set(note.keys())
    return [f for f in wanted if f in model_fields]

def _pattern_of(rule: Rule) -> str:
    """
    * If pattern is a list, choose a primary; engine may iterate lists later.
    """
    return rule.pattern[0] if isinstance(rule.pattern, list) else str(rule.pattern)

# --- Insert: _effective_query helper
def _effective_query(rule: Rule) -> Union[str, List[str], None]:
    """
    * Resolve the query that will actually be used:
      - If the rule has an explicit query, return it (string or filtered list).
      - Otherwise, derive a regex/literal clause from the rule pattern.
    """
    q = rule.query

    # Normalize explicit query, if present
    if isinstance(q, str):
        qs = q.strip()
        if qs:
            return qs
    elif isinstance(q, list):
        cleaned = [str(s).strip() for s in q if str(s).strip()]
        if cleaned:
            return cleaned

    # No explicit query → derive from pattern
    pat = _pattern_of(rule).strip()
    if not pat:
        return None

    clause = f"re:{pat}" if rule.regex else pat
    return clause

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

def _guard_exceeded(rule: Rule, before: str, after: str) -> bool:
    limit = int(rule.delete_chars.get("max_chars", 0))
    count_spaces = bool(rule.delete_chars.get("count_spaces", True))
    exceeded, _deleted = deletion_exceeds_limit(before, after, limit, count_spaces=count_spaces)
    return exceeded

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

def _init_per_rule(rule: Rule, idx: int) -> Dict[str, Any]:
    raw_src = getattr(rule, "source_file", None) or ""
    try:
        file_name = Path(str(raw_src)).name if raw_src else ""
    except Exception:
        file_name = str(raw_src) if raw_src else ""
    return {
        "index": idx,
        # * Short name for backward-compatible displays
        "file": file_name,
        # * Full source path preserved for group-aware logging
        "source_file": str(raw_src) if raw_src else "",
        "source_index": getattr(rule, "source_index", None),
        "query": _effective_query(rule),
        "exclude": rule.exclude_query,
        "pattern": rule.pattern if isinstance(rule.pattern, str) else rule.pattern[:1],
        "flags": rule.flags,
        "fields": rule.fields,
        "loop": rule.loop,
        # --- remove-loop logging additions:
        "remove_loop": False,          # any remove rule actually looped?
        "remove_max_loops": 0,         # configured cap for remove rules
        "remove_loops_used": 0,        # total passes used by remove rules
        "replacement": rule.replacement,
        "notes_matched": 0,
        "notes_changed": 0,         # actual commits
        "notes_would_change": 0,    # simulated changes
        "total_subs": 0,
        "guard_skips": 0,
        "remove_field_subs": 0,
        "examples": [],
        "search": "",   # ! actual Browser search string (set in run loop)
        "error": "",    # ! runtime error string, if any
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
        rm_loops_used = per.get("remove_loops_used", 0)

        if dry:
            lines.append(
                f"  matched={matched} "
                f"would_change={would_change} "
                f"subs={subs} "
                f"guard_skips={guard_skips} "
                f"rm_field_subs={rm_field_subs} "
                f"rm_loop={rm_loop} "
                f"rm_loops_used={rm_loops_used} "
                f"rm_max_loops={rm_max_loops}"
            )
        else:
            lines.append(
                f"  matched={matched} "
                f"changed={changed} "
                f"subs={subs} "
                f"guard_skips={guard_skips} "
                f"rm_field_subs={rm_field_subs} "
                f"rm_loop={rm_loop} "
                f"rm_loops_used={rm_loops_used} "
                f"rm_max_loops={rm_max_loops}"
            )
        ex = per.get("examples", [])
        for i, e in enumerate(ex, 1):
            lines.append(f"  ex{i} [{e.get('field','?')}]: BEFORE: {e.get('before','')}")
            lines.append(f"  ex{i} [{e.get('field','?')}]: AFTER : {e.get('after','')}")
        lines.append("")

    # Store the text summary in the report (no files written here)
    details_txt = "\n".join(lines)
    report["details_txt"] = details_txt