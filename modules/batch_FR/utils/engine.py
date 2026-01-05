from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
import json

# * Anki import guarded for import/test safety
try:
    from aqt import mw  # type: ignore
except Exception:
    mw = None  # type: ignore

from .data_defs import Rule, RunConfig
from .rules_io import (
    load_rules_from_config,
    load_rules_from_file,
    to_rule,
    discover_from_config,
    discover_rule_files,
    resolve_rules_root,
)
from .anki_query_utils import compose_search, effective_query
from .regex_utils import (
    apply_rule_to_text,
    deletion_exceeds_limit,
    basic_html_cloze_balance_ok,
)
from .remove_runner import (
    run_remove_for_field,
    maybe_write_remove_debug_for_selection,
    build_remove_context,
    write_remove_debug_md,
)
from .config_utils import normalize_modules_snapshot
from .logger import write_batch_fr_debug, write_regex_debug

# * Optional log cleanup (keep engine resilient if module not present)
try:
    from ...log_cleanup import delete_old_anki_log_files, LOGS_ROOT  # type: ignore
except Exception:
    delete_old_anki_log_files = None  # type: ignore
    LOGS_ROOT = None  # type: ignore


__all__ = ["run_batch_find_replace"]

TS_FORMAT = "%H-%M_%m-%d"

# ! Debug log example capture limits (keep logs readable)
MAX_EXAMPLES_PER_RULE = 3
MAX_EXAMPLE_CHARS = 240


def _preview_snip(s: str, limit: int = MAX_EXAMPLE_CHARS) -> str:
    """Return a short, log-friendly preview of text.

    - Normalizes newlines to literal `\\n` so markdown tables stay intact.
    - Truncates long content to avoid huge logs.
    """
    try:
        t = "" if s is None else str(s)
    except Exception:
        t = ""

    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = t.replace("\n", "\\n")

    if len(t) > int(limit):
        return t[: int(limit)] + "…"
    return t

# =========================
# Config shaping
# =========================
def _coerce_run_config(cfg_snapshot: Dict[str, Any]) -> RunConfig:
    """Coerce the UI/config snapshot into a RunConfig dataclass.

    Keep this conservative: preserve existing keys and defaults.
    """
    defaults = dict(cfg_snapshot.get("Defaults") or cfg_snapshot.get("defaults") or {})
    # modules_config.json uses "Defaults" and "Remove_Config" style keys
    remove_cfg = dict(cfg_snapshot.get("Remove_Config") or cfg_snapshot.get("remove_config") or {})
    order_pref = dict(cfg_snapshot.get("order_preference") or {})

    fields_all = list(cfg_snapshot.get("fields_all") or cfg_snapshot.get("Fields_All") or [])
    rules_path = str(cfg_snapshot.get("rules_path") or cfg_snapshot.get("Rules_Path") or "")

    return RunConfig(
        ts_format=str(cfg_snapshot.get("ts_format") or cfg_snapshot.get("TS_FORMAT") or TS_FORMAT),
        log_dir=str(cfg_snapshot.get("log_dir") or cfg_snapshot.get("LOG_DIR") or ""),
        rules_path=rules_path,
        fields_all=fields_all,
        defaults=defaults,
        remove_config=remove_cfg,
        log_mode=str(cfg_snapshot.get("log_mode") or cfg_snapshot.get("LOG_MODE") or "auto"),
        include_unchanged=bool(cfg_snapshot.get("include_unchanged", False)),
        max_loops=int(cfg_snapshot.get("max_loops") or cfg_snapshot.get("MAX_LOOPS") or 50),
        order_preference=order_pref,
    )


# =========================
# Engine helpers
# =========================
def _as_path(x: Union[str, Path]) -> Path:
    return x if isinstance(x, Path) else Path(str(x))

def _resolve_rule_input_path(x: Union[str, Path]) -> Path:
    """Resolve rule file/dir inputs deterministically.

    UI often sends absolute paths (best). Config may send relative paths like:
      - batch_FR/rules/...
      - modules/batch_FR/rules/...

    We resolve relative paths against the add-on root + modules/.
    """
    p = _as_path(x).expanduser()

    # Absolute paths are already unambiguous
    try:
        if p.is_absolute():
            return p.resolve()
    except Exception:
        pass

    parts = p.parts
    addon_root = _modules_dir_from_engine().parent  # .../_Main_Toolbar

    # Support paths that start with "modules/..." relative to add-on root
    if parts and parts[0] == "modules":
        return (addon_root / p).resolve()

    # Default: relative to modules/
    return (_modules_dir_from_engine() / p).resolve()

def _expand_ruleset_inputs(
    raw: Optional[Sequence[Union[str, Path]]],
    cfg: RunConfig,
) -> List[Path]:
    """Expand a mixed list of file/dir inputs into concrete rule FILE paths.

    The UI can present folders (e.g., 'Main', 'zBeta/_Top') as selectable items.
    If a folder is selected, we expand it into the rule files it contains.
    """
    if not raw:
        return []

    out: List[Path] = []
    order_pref = dict(getattr(cfg, "order_preference", {}) or {})

    for item in raw:
        p = _resolve_rule_input_path(item)
        try:
            if p.exists() and p.is_dir():
                # Prefer the same discovery logic used by config-based discovery.
                try:
                    discovered = discover_from_config(str(p), order_pref)
                    out.extend([Path(x) for x in discovered])
                except Exception:
                    # Fallback to direct recursive glob.
                    out.extend(discover_rule_files(p))
            else:
                out.append(p)
        except Exception:
            out.append(p)

    # De-dupe while preserving order
    seen: set[str] = set()
    uniq: List[Path] = []
    for p in out:
        s = str(p)
        if s in seen:
            continue
        seen.add(s)
        uniq.append(p)
    return uniq

def _guard_exceeded(rule: Rule, before: str, after: str) -> bool:
    """Deletion guard for main rules (JSON/JSONL)."""
    try:
        limit = int((rule.delete_chars or {}).get("max_chars", 0))
        count_spaces = bool((rule.delete_chars or {}).get("count_spaces", True))
    except Exception:
        limit, count_spaces = 0, True

    exceeded, _deleted = deletion_exceeds_limit(before, after, limit, count_spaces=count_spaces)
    return exceeded


def _remove_guard_exceeded(cfg: RunConfig, before: str, after: str) -> bool:
    """Deletion guard for remove rules (uses cfg.remove_config.delete_chars)."""
    try:
        dc = (cfg.remove_config or {}).get("delete_chars", {})
        limit = int(dc.get("max_chars", 0))
        count_spaces = bool(dc.get("count_spaces", True))
    except Exception:
        limit, count_spaces = 0, True

    # Convention: negative max_chars means "no limit"
    if limit < 0:
        return False

    exceeded, _deleted = deletion_exceeds_limit(before, after, limit, count_spaces=count_spaces)
    return exceeded


def _resolve_target_fields(note: Any, rule_fields: List[str], fields_all: List[str]) -> List[str]:
    """Resolve fields to process for a given note.

    - If rule_fields == ['ALL'] -> use fields_all
    - Else use rule_fields
    - Filter to fields that exist on the note
    """
    wanted = rule_fields or ["ALL"]
    if len(wanted) == 1 and str(wanted[0]).upper() == "ALL":
        wanted = list(fields_all)

    present = []
    for f in wanted:
        fs = str(f).strip()
        if not fs:
            continue
        try:
            # Note supports __contains__ for field names
            if fs in note:
                present.append(fs)
        except Exception:
            # Fallback: try fields dict
            try:
                _ = note[fs]
                present.append(fs)
            except Exception:
                continue
    return present


def _init_report(cfg: RunConfig, *, dry_run: bool) -> Dict[str, Any]:
    return {
        "dry_run": bool(dry_run),
        "errors": [],
        "ts_format": cfg.ts_format or TS_FORMAT,
        "log_dir": cfg.log_dir,
        "rules": 0,
        # Canonical name used by logger
        "notes_touched": 0,
        # Back-compat alias (mirrors notes_touched)
        "notes_matched": 0,
        "notes_would_change": 0,
        "notes_changed": 0,
        "total_subs": 0,
        "guard_skips": 0,
        "invalid_rules": [],
        "per_rule": [],  # logger expects `per_rule`
    }
def _maybe_write_debug_logs(
    report: Dict[str, Any],
    cfg: RunConfig,
    *,
    snap: Dict[str, Any],
    debug_cfg: Dict[str, Any],
    regex_debug_cfg: Dict[str, Any],
    anki_regex_check: bool,
) -> None:
    """Best-effort debug log writing.

    Key goal: avoid the UI showing a silent '0 notes / 0 rules' run with no logs.
    """
    debug_enabled = bool(debug_cfg.get("enabled", True))

    try:
        if debug_enabled:
            write_batch_fr_debug(report, cfg, debug_cfg=debug_cfg)
    except Exception as e:
        report["log_error"] = str(e)

    try:
        if "regex_debug" in snap:
            regex_enabled = bool(regex_debug_cfg.get("enabled", False))
        else:
            regex_enabled = debug_enabled

        if anki_regex_check or regex_enabled:
            effective_regex_cfg = dict(debug_cfg)
            effective_regex_cfg.update(regex_debug_cfg)
            write_regex_debug(report, cfg, debug_cfg=effective_regex_cfg)
    except Exception as e:
        report["regex_log_error"] = str(e)


def _init_per_rule(rule: Rule, idx: int) -> Dict[str, Any]:
    """Per-rule stats record (stable keys for logger + remove_runner)."""
    patt_disp = rule.pattern if isinstance(rule.pattern, str) else (rule.pattern[:1] if rule.pattern else "")

    # Raw query inputs (often empty; rules_io normalizes missing query to [])
    include_input: List[str] = []
    if isinstance(rule.query, list):
        include_input = [str(x) for x in rule.query]
    elif isinstance(rule.query, str) and rule.query.strip():
        include_input = [rule.query.strip()]

    # Effective include clauses actually used by compose_search:
    # - if include_input is empty, this derives from pattern/fields (e.g., Text:re:...)
    try:
        include_effective = [str(x) for x in (effective_query(rule) or [])]
    except Exception:
        include_effective = list(include_input)

    exclude_clauses: List[str] = []
    if isinstance(rule.exclude_query, list):
        exclude_clauses = [str(x) for x in rule.exclude_query]
    elif isinstance(rule.exclude_query, str) and rule.exclude_query.strip():
        exclude_clauses = [rule.exclude_query.strip()]

    return {
        "index": idx,
        "file": getattr(rule, "source_file", "") or "",
        "source_file": getattr(rule, "source_file", "") or "",
        "source_path": getattr(rule, "source_path", "") or "",
        "source_index": rule.source_index,
        # `query` is what the engine effectively uses (derived when input is empty)
        "query": include_effective,
        # `query_input` is what the user/rule file explicitly provided (often empty)
        "query_input": include_input,
        "exclude": exclude_clauses,
        "exclude_input": exclude_clauses,
        "pattern": patt_disp,
        "flags": rule.flags,
        "fields": rule.fields,
        "loop": rule.loop,
        "replacement": rule.replacement,
        # Search string (precomputed)
        "search": "",
        "search_repr": "",
        # Note counters
        "notes_matched": 0,
        "notes_would_change": 0,
        "notes_changed": 0,
        "total_subs": 0,
        "guard_skips": 0,
        # Loop accounting (JSON rules)
        "fr_loop": False,
        "fr_loops_used": 0,
        "fr_break_stable": 0,
        "fr_break_cap": 0,
        "fr_break_cycle": 0,
        "fr_empty_match_forced_single": 0,
        # Remove accounting (remove_runner updates these)
        "remove_loop": False,
        "remove_max_loops": 0,
        "remove_loops_used": 0,
        "remove_loops_used_sum": 0,
        "remove_loops_used_max": 0,
        "remove_fields_looped": 0,
        "remove_cap_hits": 0,
        "remove_cycle_hits": 0,
        "remove_empty_match_forced_single": 0,
        "remove_field_subs": 0,
        # Examples
        "examples": [],
        "error": "",
    }


def _append_rule_summary(report: Dict[str, Any], per: Dict[str, Any]) -> None:
    report["rules"] += 1

    # * Engine-side compatibility aliases for older UI/JS renderers
    #   Some UI tables expect shorter keys like `would_change` instead of `notes_would_change`.
    try:
        per.setdefault("matched", int(per.get("notes_matched", 0) or 0))
        per.setdefault("would_change", int(per.get("notes_would_change", 0) or 0))
        per.setdefault("changed", int(per.get("notes_changed", 0) or 0))
        per.setdefault("subs", int(per.get("total_subs", 0) or 0))

        # Remove pipeline convenience aliases (optional)
        per.setdefault("rm_subs", int(per.get("remove_field_subs", 0) or 0))
        per.setdefault("rm_loops", int(per.get("remove_loops_used_sum", 0) or 0))
    except Exception:
        pass
    inc = int(per.get("notes_matched", 0) or 0)
    report["notes_touched"] += inc
    report["notes_matched"] += inc  # alias
    report["notes_would_change"] += int(per.get("notes_would_change", 0) or 0)
    report["notes_changed"] += int(per.get("notes_changed", 0) or 0)
    report["total_subs"] += int(per.get("total_subs", 0) or 0)
    report["guard_skips"] += int(per.get("guard_skips", 0) or 0)
    report["per_rule"].append(per)

def _run_remove_only_batch(
    mw_work: Any,
    *,
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    report: Dict[str, Any],
    query: str,
    dry: bool,
    notes_limit: Optional[int],
    remove_rules: Optional[Union[str, Path]],
) -> Any:
    """Execute only the remove pipeline across notes matching `query`.

    Restores legacy behavior where remove rules can run even if no JSON rules loaded.
    """
    per: Dict[str, Any] = {
        "index": int(len(report.get("per_rule") or [])) + 1,
        "file": "(remove-only)",
        "source_file": "(remove-only)",
        "source_path": "(remove-only)",
        "source_index": 0,
        "query": [query],
        "exclude": [],
        "pattern": "(remove-only)",
        "flags": "",
        "fields": ["ALL"],
        "loop": True,
        "replacement": "",
        "search": query,
        "search_repr": repr(query),
        "notes_matched": 0,
        "notes_would_change": 0,
        "notes_changed": 0,
        "total_subs": 0,
        "guard_skips": 0,
        # Remove accounting (run_remove_for_field updates these when present)
        "remove_loop": False,
        "remove_max_loops": 0,
        "remove_loops_used": 0,
        "remove_loops_used_sum": 0,
        "remove_loops_used_max": 0,
        "remove_fields_looped": 0,
        "remove_cap_hits": 0,
        "remove_cycle_hits": 0,
        "remove_empty_match_forced_single": 0,
        "remove_field_subs": 0,
        "examples": [],
        "error": "",
    }

    # Find notes
    try:
        nids = mw_work.col.find_notes(query)
    except Exception as e:
        per["error"] = str(e)
        _append_rule_summary(report, per)
        return None

    if notes_limit is not None:
        try:
            nids = nids[: int(notes_limit)]
        except Exception:
            pass

    per["notes_matched"] = len(nids)

    # Remove context is run-wide
    remove_ctx = None

    for nid in nids:
        note = mw_work.col.get_note(nid)
        changed_this_note = False

        # Fields: prefer cfg.fields_all; if empty, fall back to all note keys
        try:
            target_fields = list(cfg.fields_all or [])
        except Exception:
            target_fields = []
        if not target_fields:
            try:
                target_fields = list(note.keys())
            except Exception:
                target_fields = []

        for field in target_fields:
            try:
                before = note.get(field, "") if hasattr(note, "get") else note[field]
            except Exception:
                continue

            working_candidate, remove_ctx = run_remove_for_field(
                text=before,
                field_name=str(field),
                cfg=cfg,
                cfg_snapshot=cfg_snapshot,
                per=per,
                ctx=remove_ctx,
                remove_rules=remove_rules,
                field_remove_rules=None,
                log_dir=cfg.log_dir,
            )

            # Apply guards to remove delta only
            working = before
            if working_candidate != before:
                if not basic_html_cloze_balance_ok(before, working_candidate):
                    per["guard_skips"] += 1
                    working = before
                elif _remove_guard_exceeded(cfg, before, working_candidate):
                    per["guard_skips"] += 1
                    working = before
                else:
                    working = working_candidate

            if working == before:
                continue

            changed_this_note = True

            # * Capture a small before/after example for logs (cap per run-record)
            try:
                if len(per.get("examples") or []) < MAX_EXAMPLES_PER_RULE:
                    per.setdefault("examples", []).append(
                        {
                            "field": str(field),
                            "before": _preview_snip(before),
                            "after": _preview_snip(working),
                        }
                    )
            except Exception:
                pass

            if not dry:
                note[str(field)] = working

        if changed_this_note:
            per["notes_would_change"] += 1
            if not dry:
                per["notes_changed"] += 1
                mw_work.col.update_note(note)

    # Prefer remove_runner's internal subs counter if present; otherwise keep total_subs as-is.
    try:
        per["total_subs"] = int(per.get("remove_field_subs", 0) or 0)
    except Exception:
        pass

    _append_rule_summary(report, per)

    return remove_ctx

# =========================
# Public entrypoint
# =========================

def _normalize_config_snapshot(config_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either batch_FR_config dict OR full modules_config.json dict.

    Returns a merged, mostly-flat dict where global_config overrides batch keys.
    """
    if not isinstance(config_snapshot, dict):
        return {}

    # If full modules_config.json was passed
    if "batch_FR_config" in config_snapshot:
        base = dict(config_snapshot.get("batch_FR_config") or {})
        glob = dict(config_snapshot.get("global_config") or {})
        base.update(glob)
        return base

    # Otherwise assume batch_FR_config already
    return dict(config_snapshot)


def _maybe_load_full_modules_config(mw_ref: Any, cfg_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """If caller passed only batch_FR_config (missing global_config), attempt to load full modules_config.json.

    This prevents UI callsites from accidentally dropping log_dir / ts_format and other global settings.
    """
    try:
        if not isinstance(cfg_snapshot, dict):
            return {}

        # Already a full snapshot (or at least has wrappers)
        if "batch_FR_config" in cfg_snapshot or "global_config" in cfg_snapshot:
            return cfg_snapshot

        # Caller likely passed batch_FR_config only; load full file from disk
        if mw_ref is None:
            return cfg_snapshot

        # 1) Primary: use Anki's addons folder (works when mw_ref is the real mw)
        cfg_path = None
        try:
            modules_dir = Path(mw_ref.addonManager.addonsFolder()) / "_Main_Toolbar" / "modules"
            cand = modules_dir / "modules_config.json"
            if cand.exists():
                cfg_path = cand
        except Exception:
            cfg_path = None

        # 2) Fallback: derive from engine file location (works even if mw_ref is not real mw)
        if cfg_path is None:
            cand2 = _modules_dir_from_engine() / "modules_config.json"
            if cand2.exists():
                cfg_path = cand2

        if cfg_path is None or not cfg_path.exists():
            return cfg_snapshot

        full = json.loads(cfg_path.read_text(encoding="utf-8"))
        if isinstance(full, dict) and "batch_FR_config" in full:
            return full
    except Exception:
        pass

    return cfg_snapshot


def _modules_dir_from_engine() -> Path:
    """Return the `_Main_Toolbar/modules` directory based on this file location."""
    # engine.py -> utils/ -> batch_FR/ -> modules/
    return Path(__file__).resolve().parents[2]

def run_batch_find_replace(
    mw_ref,
    *,
    rulesets: Optional[List[Union[str, Path, Dict[str, Any]]]] = None,
    config_snapshot: Dict[str, Any],
    remove_rules: Optional[Union[str, Path]] = None,
    dry_run: Optional[bool] = None,
    show_progress: bool = True,
    notes_limit: Optional[int] = None,
    rules_files: Optional[Sequence[Union[str, Path]]] = None,
    remove_only_query: Optional[str] = None,
) -> Dict[str, Any]:
    """\
    Orchestrate: load rules, search notes, apply remove + main rules, and log.

    - Keeps legacy semantics for search construction via anki_query_utils.compose_search()
    - Applies text changes via regex_utils.apply_rule_to_text()
    - Leaves remove_runner behavior unchanged (called per-field)
    """
    _ = show_progress  # placeholder (kept for API compatibility)

    # Prefer explicit mw_ref, but fall back to global `aqt.mw`.
    mw_work = mw_ref or mw
    if mw_work is None:
        raise RuntimeError("Anki mw not available (run inside Anki).")

    # If the UI passed something that's not the real mw (missing .col), fall back.
    if getattr(mw_work, "col", None) is None and mw is not None:
        mw_work = mw

    # * Self-heal: if UI passed only batch_FR_config, reload full modules_config.json
    config_snapshot = _maybe_load_full_modules_config(mw_work, config_snapshot)

    snap = normalize_modules_snapshot(config_snapshot)
    cfg = _coerce_run_config(snap)
    dry = bool(dry_run) if dry_run is not None else False
    
    # * Ensure a deterministic log_dir so logs can't "disappear" due to an empty or relative path.
    #   Priority: cfg.log_dir -> LOGS_ROOT -> ~/Desktop/anki_logs/Main_toolbar
    try:
        if not str(cfg.log_dir or "").strip():
            if LOGS_ROOT:
                cfg.log_dir = str(Path(str(LOGS_ROOT)).expanduser())
            else:
                cfg.log_dir = str(Path("~/Desktop/anki_logs/Main_toolbar").expanduser())

        # Normalize + create directory
        _ld = Path(str(cfg.log_dir)).expanduser()
        _ld.mkdir(parents=True, exist_ok=True)
        cfg.log_dir = str(_ld)
    except Exception:
        # Keep engine resilient; errors are surfaced later via logger failure / report fields.
        pass

    # * Auto-discover rule files ONLY when caller provided neither rulesets nor explicit rules_files.
    if (not rulesets) and (not (rules_files or [])):
        try:
            # cfg.rules_path may be:
            #   - 'batch_FR/rules' (relative to modules/)
            #   - 'modules/batch_FR/rules' (relative to add-on root)
            #   - absolute
            if not str(cfg.rules_path or "").strip():
                rulesets = []
            else:
                rules_root = resolve_rules_root(str(cfg.rules_path))
                discovered = discover_from_config(str(rules_root), cfg.order_preference)
                rulesets = [str(p) for p in discovered]
        except Exception:
            rulesets = []

    # * Debug config blocks (robust to normalize_modules_snapshot dropping unknown keys)
    def _pick_cfg_block(key: str) -> Dict[str, Any]:
        # 1) Prefer normalized snapshot
        block = snap.get(key)
        if isinstance(block, dict):
            return dict(block)

        # 2) Fallback to raw snapshot (full modules_config.json)
        if isinstance(config_snapshot, dict) and "batch_FR_config" in config_snapshot:
            bc = config_snapshot.get("batch_FR_config") or {}
            if isinstance(bc, dict) and isinstance(bc.get(key), dict):
                return dict(bc.get(key) or {})

        # 3) Fallback to raw snapshot (batch-only dict)
        if isinstance(config_snapshot, dict) and isinstance(config_snapshot.get(key), dict):
            return dict(config_snapshot.get(key) or {})

        return {}

    debug_cfg = _pick_cfg_block("batch_fr_debug")
    regex_debug_cfg = _pick_cfg_block("regex_debug")
    anki_regex_check = bool(snap.get("anki_regex_check", False) or (isinstance(config_snapshot, dict) and config_snapshot.get("anki_regex_check", False)))

    # * Always run log cleanup at the end of a run (independent of debug/dry_run).
    #   Prefer the configured log_dir if present; otherwise fall back to the module default.
    cleanup_root = cfg.log_dir if getattr(cfg, "log_dir", None) else LOGS_ROOT

    def _finalize(_report: Dict[str, Any]) -> Dict[str, Any]:
        # ! Never allow cleanup failures to break a run
        try:
            if delete_old_anki_log_files:
                delete_old_anki_log_files(
                    base_dir=cleanup_root,
                    dry_run=False,
                )
        except Exception:
            pass
        return _report

    report = _init_report(cfg, dry_run=dry)
    # * Provenance breadcrumbs to make UI/console debugging less opaque
    report["engine_file"] = __file__
    report["rulesets_in"] = [str(x) for x in (rulesets or [])]
    report["rules_files_in"] = [str(x) for x in (rules_files or [])]

    # ! Canonical keys used by logger/debug writers
    #   - rules_files_selected: raw UI selection inputs
    #   - rules_files_used: the concrete file list after expansion
    report["rules_files_selected"] = list(report.get("rules_files_in") or [])
    report["rules_files_used"] = []  # set later once expansion happens

    # * Normalize report log_dir for downstream checks / tooling
    try:
        if report.get("log_dir"):
            report["log_dir"] = str(Path(str(report["log_dir"])).expanduser())
    except Exception:
        pass

    # * Run-wide config snapshot passed into remove_runner / remove-only
    cfg_dict = dict(snap)

    # ! If there is no collection, do not proceed (otherwise the UI can look like a silent no-op).
    if getattr(mw_work, "col", None) is None:
        report["errors"].append("No collection loaded (mw.col is None).")
        _maybe_write_debug_logs(
            report,
            cfg,
            snap=snap,
            debug_cfg=debug_cfg,
            regex_debug_cfg=regex_debug_cfg,
            anki_regex_check=anki_regex_check,
        )
        return _finalize(report)

    # -------------------------
    # 1) Load rules (dicts) -> normalize -> dataclasses
    # -------------------------
    raw_rules: List[Dict[str, Any]] = []

    # If the UI passed explicit rules_files, expand any directories into the rule files they contain.
    selected_files: List[Path] = _expand_ruleset_inputs(rules_files, cfg)

    # ? UI can pass TXT remove-rule files through `rules_files`. Treat them as `remove_rules`
    # ? and do NOT try to parse them as JSON rule files.
    selected_remove_txt: List[Path] = []
    for p in list(selected_files):
        try:
            name = p.name.lower()
        except Exception:
            name = str(p).lower()

        if name.endswith("remove_rule.txt") or name.endswith("remove_rules.txt"):
            selected_remove_txt.append(p)

    # Prefer an explicit `remove_rules=` argument, but fall back to the first selected TXT.
    if remove_rules is None and selected_remove_txt:
        remove_rules = selected_remove_txt[0]

    # Prevent TXT remove rules from being fed into JSON rule parsing.
    if selected_remove_txt:
        selected_files = [p for p in selected_files if p not in selected_remove_txt]

    # Expand any directory selections in rulesets (but keep dict-based rulesets intact).
    _ruleset_dicts: List[Dict[str, Any]] = []
    _ruleset_paths: List[Union[str, Path]] = []
    for rs in rulesets or []:
        if isinstance(rs, dict):
            _ruleset_dicts.append(rs)
        else:
            _ruleset_paths.append(rs)

    expanded_ruleset_paths = _expand_ruleset_inputs(_ruleset_paths, cfg)
    rulesets = list(_ruleset_dicts) + [str(p) for p in expanded_ruleset_paths]
    report["rulesets_expanded"] = [str(x) for x in (rulesets or [])]
    report["rules_files_expanded"] = [str(p) for p in selected_files]

    # Keep a stable key for loggers (some loggers look for `rules_files_used`)
    report["rules_files_used"] = list(report.get("rules_files_expanded") or [])

    # Load from rulesets (paths or dict configs)
    for rs in rulesets or []:
        try:
            if isinstance(rs, dict):
                raw_rules.extend(load_rules_from_config(rs))
            else:
                p = _resolve_rule_input_path(rs)
                raw_rules.extend(
                    load_rules_from_file(
                        p,
                        defaults=cfg.defaults,
                        fields_all=cfg.fields_all,
                    )
                )
        except Exception as e:
            report["invalid_rules"].append({"source": str(rs), "error": str(e)})

    # Extra selected files (UI filter)
    for p in selected_files:
        try:
            raw_rules.extend(
                load_rules_from_file(
                    p,
                    defaults=cfg.defaults,
                    fields_all=cfg.fields_all,
                )
            )
        except Exception as e:
            report["invalid_rules"].append({"source": str(p), "error": str(e)})

    # Filter out non-JSON/JSONL rules (TXT remove rules are owned by remove_runner)
    ready_dicts: List[Dict[str, Any]] = []
    for r in raw_rules:
        src = str(r.get("source_path") or r.get("_source_path") or r.get("source_file") or r.get("_source_file") or "")
        if src.lower().endswith((".json", ".jsonl")):
            ready_dicts.append(r)

    # Convert to Rule dataclasses
    ready_rules: List[Rule] = []
    for d in ready_dicts:
        try:
            ready_rules.append(to_rule(d))
        except Exception as e:
            report["invalid_rules"].append(
                {"source": d.get("source_path") or d.get("source_file") or "unknown", "error": str(e)}
            )

    # ? If nothing loaded, surface a deterministic error so the UI doesn't just show
    # ? "0 notes would change across 0 rules" with no explanation.
    if not ready_rules:
        # * Restore legacy behavior: allow remove-only runs even when no JSON rules were loaded.
        q = str(remove_only_query or "").strip()
        if cfg.remove_config and q:
            try:
                _run_remove_only_batch(
                    mw_work,
                    cfg=cfg,
                    cfg_snapshot=cfg_dict,
                    report=report,
                    query=q,
                    dry=dry,
                    notes_limit=notes_limit,
                    remove_rules=remove_rules,
                )
            except Exception as e:
                report["errors"].append(f"Remove-only run failed: {e}")
                report["error"] = "Remove-only run failed. See report['errors'] for details."
        else:
            report["error"] = "No JSON rules loaded. Provide a remove-only query (or select JSON rules) to run. See invalid_rules for path/parse errors."

        _maybe_write_debug_logs(
            report,
            cfg,
            snap=snap,
            debug_cfg=debug_cfg,
            regex_debug_cfg=regex_debug_cfg,
            anki_regex_check=anki_regex_check,
        )
        return _finalize(report)

    # -------------------------
    # 2) Apply rules
    # -------------------------
    remove_ctx = None  # remove_runner context is run-wide but built lazily

    for idx, rule in enumerate(ready_rules, start=1):
        per = _init_per_rule(rule, idx)

        try:
            # 2a) Compose Browser search (engine-compatible; escape-safe)
            search_str = compose_search(rule)
            per["search"] = search_str
            per["search_repr"] = repr(search_str)

            if not search_str:
                _append_rule_summary(report, per)
                continue

            # Optional: allow remove-only run restricted by a user query
            if remove_only_query:
                # AND the two queries together (legacy behavior: space => AND)
                search_str = f"{search_str} {remove_only_query}".strip()
                per["search"] = search_str
                per["search_repr"] = repr(search_str)

            # 2b) Find matching notes (treat search parse errors as per-rule errors, not invalid rules)
            try:
                nids = mw_work.col.find_notes(search_str)
            except Exception as e:
                per["error"] = str(e)
                _append_rule_summary(report, per)
                continue

            if notes_limit is not None:
                try:
                    nids = nids[: int(notes_limit)]
                except Exception:
                    pass

            per["notes_matched"] = len(nids)

            # 2c) Per-note execution
            for nid in nids:
                note = mw_work.col.get_note(nid)
                changed_this_note = False

                target_fields = _resolve_target_fields(note, rule.fields, cfg.fields_all)

                for field in target_fields:
                    before = note.get(field, "") if hasattr(note, "get") else note[field]

                    # 3) Remove pipeline (unchanged; remove_runner owns its own search/looping)
                    working = before
                    if cfg.remove_config:
                        working_candidate, remove_ctx = run_remove_for_field(
                            text=before,
                            field_name=field,
                            cfg=cfg,
                            cfg_snapshot=cfg_dict,
                            per=per,
                            ctx=remove_ctx,
                            remove_rules=remove_rules,
                            field_remove_rules=None,  # remove_runner reads config-driven suffixes
                            log_dir=cfg.log_dir,
                        )

                        # Keep remove loop cap in per for logging (best-effort)
                        try:
                            per["remove_max_loops"] = getattr(remove_ctx, "remove_max_loops", per.get("remove_max_loops", 0))
                        except Exception:
                            pass

                        # Apply guards to remove delta only
                        if working_candidate != before:
                            if not basic_html_cloze_balance_ok(before, working_candidate):
                                per["guard_skips"] += 1
                                working = before
                            elif _remove_guard_exceeded(cfg, before, working_candidate):
                                per["guard_skips"] += 1
                                working = before
                            else:
                                working = working_candidate

                    # 4) Main rule application (new API)
                    after, meta = apply_rule_to_text(
                        patterns=rule.pattern,
                        replacement=rule.replacement,
                        text=working,
                        is_regex=rule.regex,
                        flags=rule.flags,
                        loop=rule.loop,
                        loops_cap=int(cfg.max_loops),
                    )

                    # Update counters from meta (loop/cap/cycle)
                    subs = int(meta.get("subs_total", 0) or 0)
                    per["total_subs"] += subs

                    passes_used = int(meta.get("passes_used", 0) or 0)
                    if passes_used > 1:
                        per["fr_loop"] = True
                        per["fr_loops_used"] += passes_used

                    br = str(meta.get("break_reason") or "")
                    if br == "stable":
                        per["fr_break_stable"] += 1
                    elif br == "cap":
                        per["fr_break_cap"] += 1
                    elif br == "cycle":
                        per["fr_break_cycle"] += 1

                    if bool(meta.get("empty_match_forced_single", False)):
                        per["fr_empty_match_forced_single"] += 1

                    # No net change (neither remove nor FR changed anything)
                    if after == before:
                        continue

                    # If FR changed the text (working -> after), apply FR guards on that delta only.
                    final_text = after
                    if after != working:
                        # ! Guard: keep cloze/html structurally safe (FR delta)
                        if not basic_html_cloze_balance_ok(working, after):
                            per["guard_skips"] += 1
                            final_text = working
                        # ! Guard: deletion cap (FR delta)
                        elif _guard_exceeded(rule, working, after):
                            per["guard_skips"] += 1
                            final_text = working

                    # If guards reverted FR, and remove also didn't change, skip.
                    if final_text == before:
                        continue

                    changed_this_note = True

                    # * Capture a small before/after example for logs (cap per rule)
                    try:
                        if len(per.get("examples") or []) < MAX_EXAMPLES_PER_RULE:
                            per.setdefault("examples", []).append(
                                {
                                    "field": str(field),
                                    "before": _preview_snip(before),
                                    "after": _preview_snip(final_text),
                                }
                            )
                    except Exception:
                        pass

                    if not dry:
                        note[field] = final_text

                if changed_this_note:
                    per["notes_would_change"] += 1
                    if not dry:
                        per["notes_changed"] += 1
                        mw_work.col.update_note(note)

            _append_rule_summary(report, per)

        except Exception as e:
            per["error"] = str(e)
            _append_rule_summary(report, per)

    # ! Auto-trigger remove-only if a remove TXT file was selected but JSON rules matched no notes.
    #   This prevents "candidates exist" (from remove audit) but "applied_subs = 0" when no JSON rule matched.
    try:
        remove_txt_selected = remove_rules is not None
        notes_matched_total = int(report.get("notes_matched", 0) or 0)

        if remove_txt_selected and bool(cfg.remove_config) and notes_matched_total == 0:
            q = str(remove_only_query or "").strip()
            # If no explicit query was provided, an empty Anki search string matches all notes.
            # This is intentional: user selected a remove file and expects remove to run.
            remove_ctx = _run_remove_only_batch(
                mw_work,
                cfg=cfg,
                cfg_snapshot=cfg_dict,
                report=report,
                query=q,
                dry=dry,
                notes_limit=notes_limit,
                remove_rules=remove_rules,
            )
            report.setdefault("remove_only_auto", {})
            report["remove_only_auto"]["triggered"] = True
            report["remove_only_auto"]["query"] = q
    except Exception as e:
        report.setdefault("remove_only_auto", {})
        report["remove_only_auto"]["error"] = f"{type(e).__name__}: {e}"

    # -------------------------
    # 3) Optional debug output
    # -------------------------
    # ! If a remove-rule TXT was selected, write a dedicated Remove_FR debug log once per run.
    try:
        # If a remove-rule TXT was selected but the remove pipeline never ran (e.g., 0 notes matched),
        # remove_ctx will still be None. Build it anyway so we can write Remove_FR_Debug for auditing.
        if remove_ctx is None and remove_rules is not None:
            remove_ctx = build_remove_context(
                cfg=cfg,
                cfg_snapshot=cfg_dict,
                remove_rules=remove_rules,
                field_remove_rules=None,
            )

        if remove_ctx is not None:
            selected_for_remove_debug: List[Any] = []

            # Include UI-selected files (original input list) for detection.
            try:
                selected_for_remove_debug.extend(report.get("rules_files_in") or [])
            except Exception:
                pass

            # Ensure the active remove_rules path is included.
            if remove_rules is not None:
                selected_for_remove_debug.append(str(remove_rules))

            # ! Force-write a dedicated remove log whenever a remove-rule TXT was selected.
            #   This avoids silent skips due to selection-trigger logic.
            remove_md = None
            try:
                if remove_rules is not None:
                    # Ensure consistent path handling with the other logs.
                    remove_md = write_remove_debug_md(remove_ctx, Path(str(cfg.log_dir)).expanduser())
                else:
                    # Fallback: keep the previous selection-trigger behavior.
                    remove_md = maybe_write_remove_debug_for_selection(
                        remove_ctx,
                        selected_files=selected_for_remove_debug,
                        log_dir=Path(str(cfg.log_dir)).expanduser(),
                    )
            except Exception as e:
                report["remove_log_error"] = f"{type(e).__name__}: {e}"

            # Record outcome for debugging
            report.setdefault("remove_debug", {})
            report["remove_debug"]["attempted"] = True
            report["remove_debug"]["remove_rules"] = str(remove_rules) if remove_rules is not None else ""
            report["remove_debug"]["log_dir"] = str(Path(str(cfg.log_dir)).expanduser())
            report["remove_debug"]["written"] = bool(remove_md)

            if remove_md:
                report.setdefault("report_paths", {})["remove_markdown"] = str(remove_md)
    except Exception as e:
        report["remove_log_error"] = str(e)

    _maybe_write_debug_logs(
        report,
        cfg,
        snap=snap,
        debug_cfg=debug_cfg,
        regex_debug_cfg=regex_debug_cfg,
        anki_regex_check=anki_regex_check,
    )

    return _finalize(report)