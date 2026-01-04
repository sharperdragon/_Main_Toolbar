from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union, Set
import re
import json

# * Anki/Qt import guarded for testability
try:
    from aqt import mw
except Exception:
    mw = None 

from ..utils.rules_io import (
    load_rules_from_file,
    load_rules_from_config,
    normalize_rule,
)
from ..utils.regex_utils import (
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
from ..utils.text_utils import safe_truncate
from ..utils.logger import write_batch_fr_debug, write_regex_debug
from datetime import datetime

from ...log_cleanup import delete_old_anki_log_files, LOGS_ROOT

__all__ = ["run_batch_find_replace"]

from ..utils.data_defs import (Rule, RunConfig)

from ..utils.FR_global_utils import (
    TS_FORMAT,
    _coerce_int,
    _norm_path,
)

from ..utils.remove_runner import run_remove_for_field, build_remove_context, maybe_write_remove_debug_for_selection


# ---------------------------------------------------------------------
# Loop-safe main-rule application (engine-level)
# ---------------------------------------------------------------------

def _compiled_can_match_empty(patt: str, flags: str) -> bool:
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
    flags: str,
    loops_cap: int,
    per: Dict[str, Any],
) -> tuple[str, int, int, str]:
    """Apply the rule's pattern list with deterministic looping.

    A "loop" here means: apply ALL patterns once (in order) = 1 pass.

    Break conditions:
    - 0 substitutions in a pass OR no net change -> stable
    - output repeats a prior state -> cycle
    - pass cap reached -> cap

    Returns (final_text, total_subs, passes_used, break_reason)
    break_reason in {'stable','cycle','cap'}
    """
    if loops_cap < 1:
        loops_cap = 1

    # If looping is enabled and ANY pattern can match empty, force single-pass.
    # Empty-matchable regexes are a classic source of runaway looping.
    if is_regex and loops_cap > 1:
        try:
            for p in patterns:
                if _compiled_can_match_empty(p, flags):
                    per["fr_empty_match_forced_single"] = per.get("fr_empty_match_forced_single", 0) + 1
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
            return working, total_subs, passes_used, "stable"

        # Cycle guard: output repeats prior state.
        if working in seen:
            return working, total_subs, passes_used, "cycle"
        seen.add(working)

    return working, total_subs, passes_used, "cap"

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
    remove_only_query: Optional[str] = None,
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
    # * Always run log cleanup at the end of a run (independent of debug/dry_run).
    #   Prefer the configured log_dir if present; otherwise fall back to the module default.
    cleanup_root = cfg.log_dir if getattr(cfg, "log_dir", None) else LOGS_ROOT

    try:
        # Remove settings now handled by remove_engine.RemoveContext

        # 1) Discover + load rules (deterministic; honors order_preference, Defaults)
        cfg_dict: Dict[str, Any] = dict(config_snapshot)
        rules: List[Dict[str, Any]] = []
        # Selected rule files from UI (used to decide whether to write Remove_FR_Debug)
        selected_files: List[Any] = list(rules_files) if rules_files is not None else []

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

        # 2a) Filter out any rules that are not backed by JSON/JSONL.
        #    TXT-based remove rules (including field_remove_rules.txt and *_remove_rules.txt)
        #    are owned exclusively by remove_runner.py and must not be processed here.
        def _is_json_backed_rule(d: Dict[str, Any]) -> bool:
            src = d.get("__source_file")
            if not src:
                # In-memory/adhoc rules are treated as JSON-equivalent
                return True
            try:
                ext = Path(str(src)).suffix.lower()
            except Exception:
                # If we can't parse the path, do not block the rule
                return True
            return ext in (".json", ".jsonl")

        rules = [r for r in rules if _is_json_backed_rule(r)]

        # 2b) Normalize + defaults per rule, then pre-validate replacements
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

        # Allow explicit remove paths passed into this function to override config.
        # This ensures remove_runner sees the same effective paths as the UI and
        # debug-console wrappers (remove_rules, field_remove_rules).
        if remove_rules is not None:
            cfg_dict["remove_path"] = str(remove_rules)
        if field_remove_rules is not None:
            cfg_dict["field_remove_path"] = str(field_remove_rules)

        # 3) Lazy remove context holder; it will be constructed on first
        #    run_remove_for_field() call inside the per-note/per-field loop.
        remove_ctx = None  # created on-demand by remove_runner

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

        # --- Remove-only mode: when there are no JSON rules but TXT remove rules exist.
        # If the UI supplies a dedicated remove-only query, use it.
        # If the UI selected only *_remove_rules.txt files (remove-only selection), we run a
        # per-remove-rule query loop (derived from each remove rule pattern), mirroring how
        # JSON rules build their Browser query.
        remove_only_query = remove_only_query or cfg_dict.get("remove_only_query")
        has_remove_cfg = bool(cfg_dict.get("remove_config") or cfg.remove_config)
        has_explicit_remove = remove_rules is not None or field_remove_rules is not None
        remove_suffix = cfg_dict.get("remove_rules_suffix") or ""
        field_remove_name = cfg_dict.get("field_remove_rules_name") or ""

        # Treat the selection as "remove-only" if the chosen files are ONLY:
        # - one or more *_remove_rules.txt files (by suffix)
        # - and/or the single field_remove_rules.txt file (by exact name)
        # This fixes the case where the UI includes the field-remove file alongside
        # remove-rule files, which previously prevented remove-only mode and caused
        # "0 notes would change across 0 rules".
        only_txt_selected = False
        if rules_files:
            names = []
            for p in rules_files:
                try:
                    names.append(Path(p).name)
                except Exception:
                    names.append(str(p))

            if remove_suffix:
                allowed = []
                for nm in names:
                    if field_remove_name and nm == field_remove_name:
                        allowed.append(True)
                    else:
                        allowed.append(nm.endswith(remove_suffix))
                only_txt_selected = all(allowed)

        if not ready and (has_remove_cfg or has_explicit_remove or only_txt_selected):
            if remove_only_query:
                return _run_remove_only_batch(
                    mw_ref=mw_ref,
                    cfg=cfg,
                    cfg_snapshot=cfg_dict,
                    report=report,
                    search_str=str(remove_only_query),
                    remove_rules=remove_rules,
                    field_remove_rules=field_remove_rules,
                    dry=dry,
                    notes_limit=notes_limit,
                    selected_files=selected_files,
                )

            # No global remove-only query supplied; if the selection is remove-only,
            # mirror JSON-rule behavior by deriving a per-rule Browser query from each
            # remove TXT rule pattern and scanning only matching notes per remove rule.
            if only_txt_selected:
                return _run_remove_rules_only_batch(
                    mw_ref=mw_ref,
                    cfg=cfg,
                    cfg_snapshot=cfg_dict,
                    report=report,
                    remove_rules=remove_rules,
                    field_remove_rules=field_remove_rules,
                    dry=dry,
                    notes_limit=notes_limit,
                    selected_files=selected_files,
                )

        for idx, rule in enumerate(ready, start=1):
            per = _init_per_rule(rule, idx)
            # * Initialize remove loop cap (will be filled after the first remove run)
            per["remove_max_loops"] = 0
            # ! Translate $1-style backrefs into Python-compatible replacement once per rule
            py_repl = _coerce_repl_for_python(rule.replacement, rule.regex)
            try:
                search_str = _compose_search(rule)
                per["search"] = search_str  # ! store actual Browser search text for logging
                per["search_repr"] = repr(search_str)
                nids = mw_ref.col.find_notes(search_str)
                per["notes_matched"] = len(nids)
                if notes_limit:
                    nids = nids[:notes_limit]

                for nid in nids:
                    note = mw_ref.col.get_note(nid)
                    changed_this_note = False
                    for field in _resolve_fields(note, rule.fields, cfg.fields_all):
                        before = note[field]
                        # 4a/4b) Apply the unified remove pipeline (global remove + field-remove) to this field
                        working, remove_ctx = run_remove_for_field(
                            text=before,
                            field_name=field,
                            cfg=cfg,
                            cfg_snapshot=cfg_dict,
                            per=per,
                            ctx=remove_ctx,
                            remove_rules=remove_rules,
                            field_remove_rules=field_remove_rules,
                            log_dir=cfg.log_dir,
                        )
                        # After/remove runs: record the configured remove loop cap for logging
                        if remove_ctx is not None:
                            per["remove_max_loops"] = getattr(remove_ctx, "remove_max_loops", per.get("remove_max_loops", 0))

                        # 4c) Apply main rule (supports pattern list + literal/regex)
                        patterns: List[str] = rule.pattern if isinstance(rule.pattern, list) else [str(rule.pattern)]
                        loops_cap = cfg.max_loops if rule.loop else 1

                        after, total_subs_this_field, passes_used, break_reason = _apply_patterns_loop_safe(
                            patterns=patterns,
                            repl=py_repl,
                            text=working,
                            is_regex=rule.regex,
                            flags=rule.flags,
                            loops_cap=loops_cap,
                            per=per,
                        )

                        # ! Track main-rule looping diagnostics (separate from remove_runner)
                        if passes_used > 1:
                            per["fr_loop"] = True
                            per["fr_loops_used"] = per.get("fr_loops_used", 0) + passes_used
                        br_key = f"fr_break_{break_reason}"
                        per[br_key] = per.get(br_key, 0) + 1

                        # 4d) Guard against deletions using original before and final after
                        if _guard_exceeded(rule, before, after):
                            per["guard_skips"] += 1
                            continue

                        # 4e) Guard against broken HTML/cloze structure when it was valid before
                        if not basic_html_cloze_balance_ok(before, after):
                            per["guard_skips"] += 1
                            continue

                        if after != before:
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
        debug_enabled = bool(debug_cfg.get("enabled")) or extensive_debug

        if extensive_debug:
            # * In extensive-debug mode, allow more examples per rule (default 60)
            debug_cfg.setdefault("max_examples_per_rule", extensive_debug_max_examples)

        if debug_enabled:
            debug_path = write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
            if debug_path is not None:
                report.setdefault("report_paths", {})["debug_markdown"] = str(debug_path)

            regex_debug_path = write_regex_debug(report, cfg, debug_cfg=debug_cfg)
            if regex_debug_path is not None:
                report.setdefault("report_paths", {})["regex_debug_markdown"] = str(regex_debug_path)

        # Write dedicated remove debug log once per run when a remove-rule TXT file was selected.
        if selected_files:
            # If remove_ctx was never created (e.g., no notes/fields processed), build it so the log can still be written.
            if remove_ctx is None:
                try:
                    remove_ctx = build_remove_context(
                        cfg=cfg,
                        cfg_snapshot=cfg_dict,
                        remove_rules=remove_rules,
                        field_remove_rules=field_remove_rules,
                    )
                except Exception:
                    remove_ctx = None

            if remove_ctx is not None:
                _ = maybe_write_remove_debug_for_selection(
                    remove_ctx,
                    selected_files=selected_files,
                    log_dir=cfg.log_dir or cfg_dict.get("log_dir"),
                )

        return report
    finally:
        # ! Never allow cleanup failures to break a run
        try:
            delete_old_anki_log_files(
                base_dir=cleanup_root,
                dry_run=False,
            )
        except Exception:
            pass


def _run_remove_only_batch(
    *,
    mw_ref,
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    report: Dict[str, Any],
    search_str: str,
    remove_rules: Optional[Union[str, Path]],
    field_remove_rules: Optional[Union[str, Path]],
    dry: bool,
    notes_limit: Optional[int],
    selected_files: Optional[Sequence[Any]],
) -> Dict[str, Any]:
    """Run a remove-only batch over notes matching ``search_str``.

    This path is used when there are no JSON-backed FR rules but TXT/field
    remove rules are configured. It mirrors the per-note/per-field remove
    pipeline used in the main engine loop, but without any main pattern
    replacement step.
    """
    # Synthetic rule used only for logging and per-rule stats.
    dummy_rule = Rule(
        query=search_str,
        exclude_query=None,
        pattern="",  # no main FR pattern in remove-only mode
        replacement="",
        regex=True,
        flags="m",
        fields=["ALL"],
        loop=True,
        delete_chars={"max_chars": 0, "count_spaces": True},
        source_file=None,
        source_index=None,
    )
    per = _init_per_rule(dummy_rule, idx=1)
    per["search"] = search_str
    per["search_repr"] = repr(search_str)

    # --- Remove rule query audit (per line of *_remove_rules.txt)
    # --- Local helpers: mirror _compose_search() quoting/sanitization
    def _sanitize_browser_clause(s: str) -> str:
        """Convert literal newlines/tabs into visible sequences for Anki search."""
        if not s:
            return s
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = s.replace("\n", r"\\n")
        s = s.replace("\t", r"\\t")
        return s

    def _q(s: str) -> str:
        """Quote Browser clauses consistently (regex clauses always quoted)."""
        s = (s or "").strip()
        if not s:
            return s
        s = _sanitize_browser_clause(s)
        if len(s) >= 2 and s[0] == s[-1] == '"':
            return s
        if s.lstrip().startswith("re:"):
            return f'"{s}"'
        return f'"{s}"' if any(ch.isspace() for ch in s) else s
    # This does NOT search per rule; it only logs the exact Browser query you could type.
    try:
        audit_ctx = build_remove_context(
            cfg=cfg,
            cfg_snapshot=cfg_snapshot,
            remove_rules=remove_rules,
            field_remove_rules=field_remove_rules,
        )
        rrset = getattr(audit_ctx, "remove_ruleset", None)
        if isinstance(rrset, list):
            report["remove_rules_loaded"] = len(rrset)
            audit_rows = []
            for i, rd in enumerate(rrset, 1):
                if not isinstance(rd, dict):
                    continue

                # Prefer explicit query if present; otherwise derive from pattern like JSON rules.
                qv = rd.get("query")
                if isinstance(qv, str) and qv.strip():
                    clauses = [qv.strip()]
                    qsrc = "explicit_query"
                elif isinstance(qv, list) and [str(x).strip() for x in qv if str(x).strip()]:
                    clauses = [str(x).strip() for x in qv if str(x).strip()]
                    qsrc = "explicit_query"
                else:
                    pat = str(rd.get("pattern") or "").strip()
                    is_regex = bool(rd.get("regex", True))
                    base = f"re:{pat}" if is_regex else pat
                    fields = rd.get("fields") or ["ALL"]
                    if isinstance(fields, list) and len(fields) == 1 and str(fields[0]).upper() == "ALL":
                        clauses = [base]
                    elif isinstance(fields, list) and fields:
                        clauses = [f"{f}:{base}" for f in fields]
                    else:
                        clauses = [base]
                    qsrc = "derived_from_pattern"

                # Mirror _compose_search joining/quoting behavior
                search = " ".join(_q(c) for c in clauses if str(c).strip()) or "deck:*"
                audit_rows.append(
                    {
                        "index": i,
                        "pattern": rd.get("pattern"),
                        "flags": rd.get("flags"),
                        "fields": rd.get("fields"),
                        "query": rd.get("query"),
                        "exclude_query": rd.get("exclude_query"),
                        "query_source": qsrc,
                        "derived_search": search,
                        "derived_search_repr": repr(search),
                    }
                )
            report["remove_query_audit"] = audit_rows
    except Exception as _e:
        report["remove_query_audit_error"] = str(_e)

    remove_ctx = None

    try:
        nids = mw_ref.col.find_notes(search_str)
        per["notes_matched"] = len(nids)
        if notes_limit:
            nids = nids[:notes_limit]

        for nid in nids:
            note = mw_ref.col.get_note(nid)
            changed_this_note = False

            # In remove-only mode, respect cfg.fields_all when present;
            # otherwise, operate on all fields of the note. If none of the
            # configured fields exist on this note, fall back to all fields.
            if cfg.fields_all:
                fields = [f for f in cfg.fields_all if f in note]
                if not fields:
                    fields = list(note.keys())
            else:
                fields = list(note.keys())

            for field in fields:
                before = note[field]

                working, remove_ctx = run_remove_for_field(
                    text=before,
                    field_name=field,
                    cfg=cfg,
                    cfg_snapshot=cfg_snapshot,
                    per=per,
                    ctx=remove_ctx,
                    remove_rules=remove_rules,
                    field_remove_rules=field_remove_rules,
                    log_dir=cfg.log_dir,
                )

                # After/remove runs: record the configured remove loop cap for logging
                if remove_ctx is not None:
                    per["remove_max_loops"] = getattr(remove_ctx, "remove_max_loops", per.get("remove_max_loops", 0))

                if working != before:
                    changed_this_note = True
                    # We treat remove-only modifications as examples, but leave
                    # total_subs to be driven by remove_runner's own counters.
                    if len(per["examples"]) < 2:
                        per["examples"].append(
                            {
                                "field": field,
                                "before": safe_truncate(before, 500, count_spaces=True),
                                "after": safe_truncate(working, 500, count_spaces=True),
                            }
                        )

                    if not dry:
                        note[field] = working

            if changed_this_note:
                per["notes_would_change"] += 1
                if not dry:
                    per["notes_changed"] += 1
                    mw_ref.col.update_note(note)

        _append_rule_summary(report, per)

    except Exception as e:
        per["error"] = str(e)
        _append_rule_summary(report, per)

    # Commit once at end for remove-only mode
    if not dry:
        mw_ref.col.save()

    # Build in-memory summary and debug logs, mirroring the main path
    _write_reports(report, cfg)

    debug_cfg = dict(cfg_snapshot.get("batch_fr_debug", {}) or {})
    extensive_debug = bool(report.get("extensive_debug", False))
    debug_enabled = bool(debug_cfg.get("enabled")) or extensive_debug

    if extensive_debug:
        debug_cfg.setdefault(
            "max_examples_per_rule",
            int(report.get("extensive_debug_max_examples", 60)),
        )

    if debug_enabled:
        debug_path = write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
        if debug_path is not None:
            report.setdefault("report_paths", {})["debug_markdown"] = str(debug_path)

        regex_debug_path = write_regex_debug(report, cfg, debug_cfg=debug_cfg)
        if regex_debug_path is not None:
            report.setdefault("report_paths", {})["regex_debug_markdown"] = str(regex_debug_path)

    # Write dedicated remove debug log once per run when a remove-rule TXT file was selected.
    if selected_files:
        if remove_ctx is None:
            try:
                remove_ctx = build_remove_context(
                    cfg=cfg,
                    cfg_snapshot=cfg_snapshot,
                    remove_rules=remove_rules,
                    field_remove_rules=field_remove_rules,
                )
            except Exception:
                remove_ctx = None

        if remove_ctx is not None:
            _ = maybe_write_remove_debug_for_selection(
                remove_ctx,
                selected_files=list(selected_files),
                log_dir=cfg.log_dir or cfg_snapshot.get("log_dir"),
            )

    return report


# --- New helper: _run_remove_rules_only_batch
def _run_remove_rules_only_batch(
    *,
    mw_ref,
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    report: Dict[str, Any],
    remove_rules: Optional[Union[str, Path]],
    field_remove_rules: Optional[Union[str, Path]],
    dry: bool,
    notes_limit: Optional[int],
    selected_files: Optional[Sequence[Any]],
) -> Dict[str, Any]:
    """
    Run a remove-only batch driven by the selected TXT remove rules.

    This mirrors how JSON rules work:
    - For each remove rule line (pattern), derive a Browser query (re:pattern ...)
      using the same quoting logic as _compose_search().
    - Find candidate notes for that rule.
    - Apply the unified remove pipeline to matching notes/fields.

    Note: The actual removal is still executed by remove_runner.run_remove_for_field(),
    which applies the loaded remove ruleset. The per-rule query loop here is primarily
    to ensure the engine searches candidates the same way JSON rules do (and logs it).
    """
    # Build remove context once (loads *_remove_rules.txt and field remove patterns if enabled)
    try:
        remove_ctx = build_remove_context(
            cfg=cfg,
            cfg_snapshot=cfg_snapshot,
            remove_rules=remove_rules,
            field_remove_rules=field_remove_rules,
        )
    except Exception as e:
        # Surface as a single per-rule error in the report
        dummy_rule = Rule(
            query="deck:*",
            exclude_query=None,
            pattern="",
            replacement="",
            regex=True,
            flags="m",
            fields=["ALL"],
            loop=True,
            delete_chars={"max_chars": 0, "count_spaces": True},
            source_file=None,
            source_index=None,
        )
        per = _init_per_rule(dummy_rule, idx=1)
        per["search"] = ""
        per["error"] = f"build_remove_context failed: {e}"
        _append_rule_summary(report, per)
        _write_reports(report, cfg)
        debug_cfg = dict(cfg_snapshot.get("batch_fr_debug", {}) or {})
        debug_path = write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
        if debug_path is not None:
            report.setdefault("report_paths", {})["debug_markdown"] = str(debug_path)
        regex_debug_path = write_regex_debug(report, cfg, debug_cfg=debug_cfg)
        if regex_debug_path is not None:
            report.setdefault("report_paths", {})["regex_debug_markdown"] = str(regex_debug_path)
        return report

    # If there are no remove rules loaded, log and return (this is the symptom you saw).
    if not getattr(remove_ctx, "remove_ruleset", None):
        dummy_rule = Rule(
            query="deck:*",
            exclude_query=None,
            pattern="",
            replacement="",
            regex=True,
            flags="m",
            fields=["ALL"],
            loop=True,
            delete_chars={"max_chars": 0, "count_spaces": True},
            source_file=None,
            source_index=None,
        )
        per = _init_per_rule(dummy_rule, idx=1)
        per["search"] = ""
        per["error"] = "remove_ruleset is empty (0 remove TXT rules loaded)"
        _append_rule_summary(report, per)

        _write_reports(report, cfg)
        debug_cfg = dict(cfg_snapshot.get("batch_fr_debug", {}) or {})
        debug_path = write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
        if debug_path is not None:
            report.setdefault("report_paths", {})["debug_markdown"] = str(debug_path)
        regex_debug_path = write_regex_debug(report, cfg, debug_cfg=debug_cfg)
        if regex_debug_path is not None:
            report.setdefault("report_paths", {})["regex_debug_markdown"] = str(regex_debug_path)
        return report

    # Drive a per-remove-rule loop so the search query is derived per line (like JSON rules)
    # while still using the unified remove pipeline for actual transformations.
    for idx, rr in enumerate(list(remove_ctx.remove_ruleset), start=1):
        # Create a synthetic "Rule" object so we can reuse _effective_query/_compose_search
        # (including the regex quoting behavior you highlighted).
        try:
            rr_pat = str((rr or {}).get("pattern", "")).strip()
        except Exception:
            rr_pat = ""

        rr_regex = bool((rr or {}).get("regex", True))
        rr_flags = str((rr or {}).get("flags", "m") or "m")
        rr_fields = list((rr or {}).get("fields", ["ALL"]) or ["ALL"])
        rr_query = (rr or {}).get("query", "")
        rr_ex = (rr or {}).get("exclude_query", None)

        synthetic = Rule(
            query=rr_query,
            exclude_query=rr_ex,
            pattern=rr_pat,
            replacement="",
            regex=rr_regex,
            flags=rr_flags,
            fields=rr_fields,
            loop=True,
            delete_chars={"max_chars": 0, "count_spaces": True},
            source_file=(rr or {}).get("__source_file"),
            source_index=(rr or {}).get("__source_index"),
        )

        per = _init_per_rule(synthetic, idx)
        per["search"] = _compose_search(synthetic)

        try:
            nids = mw_ref.col.find_notes(per["search"])
            per["notes_matched"] = len(nids)
            if notes_limit:
                nids = nids[:notes_limit]

            for nid in nids:
                note = mw_ref.col.get_note(nid)
                changed_this_note = False

                for field in _resolve_fields(note, synthetic.fields, cfg.fields_all):
                    before = note[field]

                    working, _ctx = run_remove_for_field(
                        text=before,
                        field_name=field,
                        cfg=cfg,
                        cfg_snapshot=cfg_snapshot,
                        per=per,
                        ctx=remove_ctx,  # keep one context across the run
                        remove_rules=remove_rules,
                        field_remove_rules=field_remove_rules,
                        log_dir=cfg.log_dir,
                    )
                    # The remove_runner may return the same ctx; keep reference stable
                    remove_ctx = _ctx

                    if remove_ctx is not None:
                        per["remove_max_loops"] = getattr(remove_ctx, "remove_max_loops", per.get("remove_max_loops", 0))

                    if working != before:
                        changed_this_note = True
                        if len(per["examples"]) < 2:
                            per["examples"].append(
                                {
                                    "field": field,
                                    "before": safe_truncate(before, 500, count_spaces=True),
                                    "after": safe_truncate(working, 500, count_spaces=True),
                                }
                            )
                        if not dry:
                            note[field] = working

                if changed_this_note:
                    per["notes_would_change"] += 1
                    if not dry:
                        per["notes_changed"] += 1
                        mw_ref.col.update_note(note)

            _append_rule_summary(report, per)

        except Exception as e:
            per["error"] = str(e)
            _append_rule_summary(report, per)

    if not dry:
        mw_ref.col.save()

    _write_reports(report, cfg)

    debug_cfg = dict(cfg_snapshot.get("batch_fr_debug", {}) or {})
    extensive_debug = bool(report.get("extensive_debug", False))
    debug_enabled = bool(debug_cfg.get("enabled")) or extensive_debug

    if extensive_debug:
        debug_cfg.setdefault(
            "max_examples_per_rule",
            int(report.get("extensive_debug_max_examples", 60)),
        )

    if debug_enabled:
        debug_path = write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
        if debug_path is not None:
            report.setdefault("report_paths", {})["debug_markdown"] = str(debug_path)

        regex_debug_path = write_regex_debug(report, cfg, debug_cfg=debug_cfg)
        if regex_debug_path is not None:
            report.setdefault("report_paths", {})["regex_debug_markdown"] = str(regex_debug_path)

    # Write dedicated remove debug log once per run when a remove-rule TXT file was selected.
    if selected_files and remove_ctx is not None:
        _ = maybe_write_remove_debug_for_selection(
            remove_ctx,
            selected_files=list(selected_files),
            log_dir=cfg.log_dir or cfg_snapshot.get("log_dir"),
        )

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
    def _sanitize_browser_clause(s: str) -> str:
        """\
        Convert literal control characters into visible two-character sequences
        so Anki's search parser doesn't get a multi-line query.

        - Converts literal newlines/tabs to \\n / \\t
        - Leaves existing backslashes alone (so patterns containing \\n remain \\n)
        """
        if not s:
            return s
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = s.replace("\n", r"\\n")
        s = s.replace("\t", r"\\t")
        return s

    def _q(s: str) -> str:
        """\
        Normalize a single search clause for the Browser.

        - Always quote regex-based clauses (re:...), even if they have no spaces.
        - Quote other clauses only when they contain whitespace.
        - Avoid double-quoting if the clause is already wrapped in quotes.
        - Ensure the clause does not contain literal newlines/tabs.
        """
        s = (s or "").strip()
        if not s:
            return s
        s = _sanitize_browser_clause(s)
        if len(s) >= 2 and s[0] == s[-1] == '"':
            return s
        if s.lstrip().startswith("re:"):
            return f'"{s}"'
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
    wanted = fields_all if (fields_spec == ["ALL"] and fields_all) else (list(note.keys()) if fields_spec == ["ALL"] else fields_spec)
    model_fields = set(note.keys())
    return [f for f in wanted if f in model_fields]

def _pattern_of(rule: Rule) -> str:
    return rule.pattern[0] if isinstance(rule.pattern, list) else str(rule.pattern)

# --- Insert: _effective_query helper
def _effective_query(rule: Rule) -> Union[str, List[str], None]:
    q = rule.query

    # 1) Explicit query wins
    if isinstance(q, str):
        qs = q.strip()
        if qs:
            return qs
    elif isinstance(q, list):
        cleaned = [str(s).strip() for s in q if str(s).strip()]
        if cleaned:
            return cleaned

    # 2) No explicit query → derive from pattern
    pat = _pattern_of(rule).strip()
    if not pat:
        return None

    base_clause = f"re:{pat}" if rule.regex else pat

    # 3) Respect fields when present
    fields = rule.fields or ["ALL"]
    # Global rule: keep old behavior for ["ALL"]
    if len(fields) == 1 and str(fields[0]).upper() == "ALL":
        return base_clause

    # Field-scoped rule: one clause per field
    return [f"{field}:{base_clause}" for field in fields]

def _coerce_repl_for_python(raw: str, is_regex: bool) -> str:
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
        "remove_loop": False,              # any remove rule actually looped?
        "remove_max_loops": 0,             # configured cap for remove rules
        "remove_loops_used": 0,            # legacy/back-compat: SUM of passes (same as remove_loops_used_sum)
        "remove_loops_used_sum": 0,        # total passes used by remove rules (SUM)
        "remove_loops_used_max": 0,        # worst-case passes used in a single field application (MAX)
        "remove_fields_looped": 0,         # number of field applications that required >1 pass
        "remove_cap_hits": 0,              # number of times remove loop stopped due to cap
        "remove_cycle_hits": 0,            # number of times remove loop stopped due to cycle
        "remove_empty_match_forced_single": 0,  # number of times empty-match forced single-pass
        # --- main-rule (JSON) loop logging additions:
        "fr_loop": False,              # any main rule pass actually looped?
        "fr_loops_used": 0,            # total passes used by main rules
        "replacement": rule.replacement,
        "notes_matched": 0,
        "notes_changed": 0,         # actual commits
        "notes_would_change": 0,    # simulated changes
        "total_subs": 0,
        "guard_skips": 0,
        "remove_field_subs": 0,
        "examples": [],
        "search": "",   # ! actual Browser search string (set in run loop)
        "search_repr": "",  # ! repr(search) to reveal hidden characters
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