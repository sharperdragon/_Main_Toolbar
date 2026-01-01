from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Pattern

from datetime import datetime
from collections import defaultdict
import re

from .rules_io import load_remove_sets_from_config, load_remove_patterns, shape_remove_patterns_to_rules

from .regex_utils import apply_substitution, flags_from_str


# ---------------------------------------------------------------------
# Loop-safe substitution helpers
# ---------------------------------------------------------------------

def _regex_can_match_empty(pat: Pattern[str]) -> bool:
    """Return True if the compiled regex can match the empty string.

    This is a common source of runaway looping: if a pattern can match "" and
    looping is enabled, some engines can keep re-matching forever.
    """
    try:
        return pat.search("") is not None
    except Exception:
        return False


def _loop_substitution_with_cycle_guard(
    patt: str,
    repl: str,
    text: str,
    *,
    is_regex: bool,
    flags: str,
    max_loops: int,
) -> tuple[str, int, int, str]:
    """Apply ONE-pass substitutions repeatedly until stable (or capped).

    Break conditions (in order):
    - 0 substitutions in a pass  -> stable
    - output equals input         -> stable
    - output repeats a prior state -> cycle
    - loop cap reached            -> cap

    Returns: (final_text, total_subs, loops_used, break_reason)
    break_reason is one of: 'stable', 'cycle', 'cap'
    """
    if max_loops < 1:
        max_loops = 1

    working = text
    total_subs = 0
    loops_used = 0
    seen: set[str] = {working}

    for _ in range(max_loops):
        # One pass only. We purposely do NOT rely on apply_substitution's internal
        # looping so our loop accounting and break reasons are deterministic.
        after, subs, _loops_used_ignored = apply_substitution(
            patt,
            repl,
            working,
            is_regex=is_regex,
            flags=flags,
            max_loops=1,
        )
        loops_used += 1
        if subs:
            total_subs += subs

        # Stable: nothing changed / no subs
        if subs == 0 or after == working:
            return after, total_subs, loops_used, "stable"

        # Cycle guard: output repeats a previous state
        if after in seen:
            return after, total_subs, loops_used, "cycle"
        seen.add(after)

        working = after

    return working, total_subs, loops_used, "cap"

from .FR_global_utils import RunConfig, load_field_remove_rules, md_inline, md_table_cell, anki_query_escape_controls

# Optional: used only for query-audit logging (safe fallback if unavailable)
try:
    from aqt import mw  # type: ignore
except Exception:  # pragma: no cover
    mw = None  # type: ignore



def _anki_txt_rule_unescape(pattern: str) -> str:
    """Normalize TXT remove-rule patterns for *execution* and *query building*.

    IMPORTANT (fix for `\\n+` stalling / tainted queries):
    - Do NOT convert sequences like `\\n`, `\\t`, `\\r` into real control characters.
      Python regex already interprets `\\n` as a newline correctly at execution time,
      and embedding literal newlines into Anki Browser queries can corrupt the query
      and dramatically increase candidates (stall/rainbow wheel).

    What we *do* normalize:
    - Keep a light unescape for `\\"` -> `"` for convenience when users write patterns
      targeting HTML attributes.

    If you truly need a literal backslash + n in the regex, keep it double-escaped in the
    TXT file (e.g., `\\\\n`).
    """
    if not pattern:
        return pattern

    s = pattern

    # 1) Turn \" into " (only when not double-escaped)
    #    If the user wrote \\" (literal backslash + quote), it will be \\\\" in Python;
    #    the negative lookbehind ensures we only unescape single-escaped quotes.
    s = re.sub(r'(?<!\\)\\"', '"', s)

    # NOTE: We intentionally DO NOT convert \\n / \\t / \\r into real control characters.
    return s


def _derive_effective_query_from_rule(rule: Dict[str, Any]) -> Union[str, List[str], None]:
    """
    Derive an effective Anki Browser query for a TXT-based remove rule.

    IMPORTANT:
    - TXT patterns are used verbatim for query building (\\n stays as two characters).
    - Derived regex queries are always quoted as a whole clause:
        "re:<pattern>"
      which matches what you paste into the Browser.
    """
    q = rule.get("query")
    if q:
        # Canonical safety: explicit queries must never contain literal control chars.
        if isinstance(q, list):
            return [anki_query_escape_controls(x) for x in q if str(x).strip()]
        return anki_query_escape_controls(q)

    raw_pattern = (rule.get("pattern") or "").strip()
    if not raw_pattern:
        return None

    # IMPORTANT: Keep patterns verbatim for Browser/find_notes query building.
    # `\\n+` must remain `\\n+` (two characters) inside the query clause.
    pattern = anki_query_escape_controls(raw_pattern)

    is_regex = bool(rule.get("regex", True))
    fields = rule.get("fields") or []

    # Base clause (unscoped)
    base_clause = f"re:{pattern}" if is_regex else pattern

    # Unscoped (ALL fields)
    if not fields or fields == ["ALL"]:
        return _anki_quote_clause(base_clause) if is_regex else (_anki_quote_clause(base_clause) if any(ch.isspace() for ch in base_clause) else base_clause)

    # Field-scoped clauses
    out: List[str] = []
    for field in fields:
        field = str(field).strip()
        if not field:
            continue
        clause = f"{field}:re:{pattern}" if is_regex else f"{field}:{pattern}"
        if is_regex:
            out.append(_anki_quote_clause(clause))
        else:
            out.append(_anki_quote_clause(clause) if any(ch.isspace() for ch in clause) else clause)

    return out or (_anki_quote_clause(base_clause) if is_regex else base_clause)


def _anki_quote_clause(clause: str) -> str:
    """
    Wrap a clause in quotes exactly like you'd paste into Anki's Browser.

    Inside the quotes:
    - Escape only quotes that are not already escaped.
    """
    escaped = re.sub(r'(?<!\\)"', r'\\"', clause)
    return f'"{escaped}"'


# Helper: Normalize queries for mw.col.find_notes()
from typing import Union, List, Optional
def _as_find_notes_query(q: Union[str, List[str], None]) -> Optional[str]:
    """
    Normalize derived queries into a single string suitable for mw.col.find_notes().

    - If q is a list of clauses, join with ` OR ` (each clause should already be properly quoted).
    - If q is a string, return as-is.
    - If q is None/empty, return None.
    """
    if not q:
        return None
    if isinstance(q, list):
        parts = [str(x).strip() for x in q if str(x).strip()]
        return anki_query_escape_controls(" OR ".join(parts)) if parts else None
    s = str(q).strip()
    return anki_query_escape_controls(s) or None



# ? Core data structures -----------------------------------------------------
@dataclass
class RemoveRuleDef:
    idx: int
    source_file: str
    pattern: str
    flags: str
    is_regex: bool
    max_loops: int


@dataclass(frozen=True)
class RemoveFieldRuleKey:
    """Key for per-field stats: (rule index, source file, field name)."""
    rule_idx: int
    source_file: str
    field_name: str

@dataclass
class RemoveRuleStats:
    """Per-field stats for a virtual remove rule."""
    rule: RemoveRuleDef
    field_name: str
    notes_seen: int = 0
    notes_matched: int = 0
    subs: int = 0
    loops_used: int = 0
    rm_field_subs: int = 0
    examples: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class RemoveRunContext:
    """Run-wide context just for remove rules."""
    cfg_snapshot: Dict[str, Any]
    remove_cfg: Dict[str, Any]
    remove_rules: List[RemoveRuleDef]
    field_rules_stats: Dict[RemoveFieldRuleKey, RemoveRuleStats]
    remove_max_loops: int
    timestamp_str: str
    field_source_file: str
    field_target_fields: List[str]


@dataclass
class RemoveContext:
    """Context used during a batch_FR run for all remove-related work."""
    remove_cfg: Dict[str, Any]
    remove_ruleset: List[Dict[str, Any]]
    field_remove_patterns: List[Pattern[str]]
    remove_max_loops: int
    field_remove_fields: Optional[List[str]]
    run_ctx: Optional[RemoveRunContext] = None


# ? Helpers for resolving paths / fields ------------------------------------


def _resolve_field_remove_path(
    cfg_snapshot: Dict[str, Any],
    field_remove_rules: Optional[Union[str, Path]] = None,
) -> Optional[Path]:
    """Resolve the path to the field-remove rules file.

    Precedence:
    1) explicit argument `field_remove_rules`
    2) cfg_snapshot["field_remove_path"]
    3) cfg_snapshot["rules_path"] + cfg_snapshot["field_remove_rules_name"]
    """
    field_remove_path: Optional[Path] = None
    if field_remove_rules is not None:
        try:
            field_remove_path = Path(field_remove_rules)
        except Exception:
            field_remove_path = None

    # 2) explicit config value for field_remove_path
    if field_remove_path is None:
        frp = cfg_snapshot.get("field_remove_path", "")
        if frp:
            try:
                field_remove_path = Path(frp)
            except Exception:
                field_remove_path = None

    # 3) rules_path + field_remove_rules_name fallback
    if field_remove_path is None:
        field_remove_name = cfg_snapshot.get("field_remove_rules_name") or ""
        rules_base = cfg_snapshot.get("rules_path") or ""
        if field_remove_name and rules_base:
            try:
                field_remove_path = Path(rules_base) / field_remove_name
            except Exception:
                field_remove_path = None

    return field_remove_path


def _normalize_fields(value: Any) -> List[str]:
    """Normalize any field container into a clean list[str]."""
    if isinstance(value, str):
        value = [value]
    if isinstance(value, (list, tuple)):
        out = [str(v).strip() for v in value if str(v).strip()]
        return out
    return []


def _infer_target_fields(
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    remove_cfg: Dict[str, Any],
) -> List[str]:
    """Infer which fields field_remove_rules.txt should apply to.

    Precedence:
    1) remove_cfg["field_remove_fields"]
    2) cfg_snapshot["fields_all"] or cfg.fields_all
    3) cfg_snapshot["fields"] or cfg.fields
    4) static default list as a fallback
    """
    # 1) explicit in remove_config
    fr_fields = _normalize_fields(remove_cfg.get("field_remove_fields"))
    if fr_fields:
        return fr_fields

    # 2) cfg_snapshot fields_all / cfg.fields_all
    snap_all = _normalize_fields(cfg_snapshot.get("fields_all"))
    if snap_all:
        return snap_all

    cfg_all = _normalize_fields(getattr(cfg, "fields_all", None))
    if cfg_all:
        return cfg_all

    # 3) cfg_snapshot fields / cfg.fields
    snap_fields = _normalize_fields(cfg_snapshot.get("fields"))
    if snap_fields:
        return snap_fields

    cfg_fields = _normalize_fields(getattr(cfg, "fields", None))
    if cfg_fields:
        return cfg_fields

    # 4) hard-coded default as last resort
    return [
        "Text",
        "Extra",
        "Extra2",
        "Extra3",
        "Extra4",
        "Extra5",
        "Extra6",
        "Extra7",
        "Button",
    ]


# ? Context builder ---------------------------------------------------------
def build_remove_context(
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    remove_rules: Optional[Union[str, Path]] = None,
    field_remove_rules: Optional[Union[str, Path]] = None,
) -> RemoveContext:
    """Build a RemoveContext for a batch_FR run.

    This now also initializes a dedicated RemoveRunContext, which:
      - Treats each pattern in field_remove_rules.txt as many per-field virtual rules
      - Tracks per-field stats for logging into a separate MD file
    """

    remove_cfg: Dict[str, Any] = getattr(cfg, "remove_config", {}) or {}

    # Dedicated loop cap for remove rules (TXT-based remove always loops up to this)
    try:
        remove_max_loops = int(remove_cfg.get("max_loops", getattr(cfg, "max_loops", 30)))
    except Exception:
        remove_max_loops = getattr(cfg, "max_loops", 30)

    if remove_max_loops < 1:
        remove_max_loops = 30

    # Load generic remove ruleset from config snapshot (uno_remove_rules, etc.)
    # This reads any TXT-based remove files discovered via rules_path + remove_rules_suffix,
    # and any explicit remove_path / field_remove_path entries in the snapshot.
    remove_sets = load_remove_sets_from_config(cfg_snapshot)
    remove_ruleset: List[Dict[str, Any]] = remove_sets.get("remove", [])

    # --- Merge in any explicit remove rules passed from engine.py ---
    # `remove_rules` can be:
    #   - None: use only what load_remove_sets_from_config() discovered
    #   - str / Path: path to a TXT file with one pattern per line
    #   - List[dict]: already-normalized rule dicts (rare, but supported)
    #   - List[str | Path]: multiple TXT files
    if remove_rules is not None:
        # Prepare defaults consistent with load_remove_sets_from_config so TXT files
        # behave the same whether they come from config or from this explicit arg.
        defaults = (cfg_snapshot.get("remove_config") or {}).copy()
        if "flags" not in defaults or not defaults.get("flags"):
            defaults["flags"] = "ms"  # multiline + dotall for remove
        if "loop" not in defaults:
            defaults["loop"] = True
        if "delete_chars" not in defaults or not isinstance(defaults.get("delete_chars"), dict):
            defaults["delete_chars"] = {"max_chars": 0, "count_spaces": True}

        fields_all = cfg_snapshot.get("fields_all", [])

        extra_rules: List[Dict[str, Any]] = []

        def _add_remove_file(p: Union[str, Path]) -> None:
            try:
                pats = load_remove_patterns(p)
            except Exception:
                return
            extra_rules.extend(
                shape_remove_patterns_to_rules(pats, defaults, fields_all)
            )

        # Single path or list-like container
        if isinstance(remove_rules, (str, Path)):
            _add_remove_file(remove_rules)
        elif isinstance(remove_rules, list):
            for item in remove_rules:
                if isinstance(item, dict):
                    # Assume already-normalized rule dict
                    extra_rules.append(item)
                elif isinstance(item, (str, Path)):
                    _add_remove_file(item)
        elif isinstance(remove_rules, dict):
            # Single in-memory rule dict
            extra_rules.append(remove_rules)

        if extra_rules:
            remove_ruleset = list(remove_ruleset) + extra_rules

    # Resolve and load field-remove rules (compiled regex patterns)
    field_remove_path = _resolve_field_remove_path(cfg_snapshot, field_remove_rules)
    field_remove_enabled = bool(remove_cfg.get("field_remove_enable", True))
    if field_remove_enabled:
        field_remove_patterns: List[Pattern[str]] = (
            load_field_remove_rules(field_remove_path)
            if field_remove_path is not None
            else load_field_remove_rules()
        )
    else:
        field_remove_patterns = []

    # Normalize optional list of fields that field-remove rules should apply to
    fr_fields_raw = remove_cfg.get("field_remove_fields")
    if isinstance(fr_fields_raw, str):
        fr_fields = [fr_fields_raw]
    elif isinstance(fr_fields_raw, (list, tuple)):
        fr_fields = [str(f) for f in fr_fields_raw]
    else:
        fr_fields = None

    # --- Build remove-run context for logging ---
    timestamp_str = datetime.now().strftime("%H-%M_%m-%d")
    field_source_file = (
        field_remove_path.name
        if field_remove_path is not None
        else (cfg_snapshot.get("field_remove_rules_name") or "field_remove_rules.txt")
    )

    # Determine which fields field_remove_rules.txt should conceptually apply to
    target_fields = _infer_target_fields(cfg, cfg_snapshot, remove_cfg)

    remove_defs: List[RemoveRuleDef] = []
    field_rules_stats: Dict[RemoveFieldRuleKey, RemoveRuleStats] = {}

    # Build RemoveRuleDef entries for field_remove_rules patterns
    for idx, pat in enumerate(field_remove_patterns, start=1):
        rdef = RemoveRuleDef(
            idx=idx,
            source_file=field_source_file,
            pattern=pat.pattern,
            flags="m",  # treat as multiline by default; adjust if you later add flags
            is_regex=True,
            max_loops=remove_max_loops,
        )
        remove_defs.append(rdef)

        # For each pattern, create a virtual rule per target field
        for fname in target_fields:
            key = RemoveFieldRuleKey(rule_idx=rdef.idx, source_file=rdef.source_file, field_name=fname)
            field_rules_stats[key] = RemoveRuleStats(rule=rdef, field_name=fname)

    run_ctx = RemoveRunContext(
        cfg_snapshot=cfg_snapshot,
        remove_cfg=remove_cfg,
        remove_rules=remove_defs,
        field_rules_stats=field_rules_stats,
        remove_max_loops=remove_max_loops,
        timestamp_str=timestamp_str,
        field_source_file=field_source_file,
        field_target_fields=target_fields,
    )

    # --- Derive effective queries for TXT-based remove rules ---
    for rr in remove_ruleset:
        if not isinstance(rr, dict):
            continue

        eff_q = _derive_effective_query_from_rule(rr)

        # Canonical safety: never store literal control characters in queries.
        if isinstance(eff_q, list):
            safe_eff_q: Union[str, List[str], None] = [anki_query_escape_controls(x) for x in eff_q if str(x).strip()]
        elif isinstance(eff_q, str):
            safe_eff_q = anki_query_escape_controls(eff_q)
        else:
            safe_eff_q = None

        # Store the Browser-pasteable query (string or list of clauses)
        rr["_browser_query"] = safe_eff_q

        # Store a backend query STRING suitable for find_notes()
        rr["_find_notes_query"] = _as_find_notes_query(safe_eff_q)

        # Backward-compat for any older debug/engine code
        rr["_effective_query"] = rr["_browser_query"]
        rr["_query_source"] = "explicit" if rr.get("query") else "derived_from_pattern"

    return RemoveContext(
        remove_cfg=remove_cfg,
        remove_ruleset=remove_ruleset,
        field_remove_patterns=field_remove_patterns,
        remove_max_loops=remove_max_loops,
        field_remove_fields=fr_fields,
        run_ctx=run_ctx,
    )


# High-level wrapper for engine.py to call as the single entrypoint for remove rules
def run_remove_for_field(
    text: str,
    field_name: Optional[str],
    *,
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    per: Dict[str, Any],
    ctx: Optional[RemoveContext] = None,
    remove_rules: Optional[Union[str, Path]] = None,
    field_remove_rules: Optional[Union[str, Path]] = None,
    log_dir: Optional[Union[str, Path]] = None,
) -> tuple[str, RemoveContext]:


    # Build context on first use if not provided
    if ctx is None:
        ctx = build_remove_context(
            cfg=cfg,
            cfg_snapshot=cfg_snapshot,
            remove_rules=remove_rules,
            field_remove_rules=field_remove_rules,
        )

    # Apply the existing pipeline to this field
    new_text = apply_remove_pipeline_to_field(
        text=text,
        field_name=field_name,
        ctx=ctx,
        per=per,
    )

    # Write remove-only debug when extensive debug is enabled (or batch_fr_debug),
    # even if engine/UI didn't pass log_dir explicitly.
    effective_log_dir = log_dir
    if effective_log_dir is None:
        if per.get("extensive_debug") or cfg_snapshot.get("batch_fr_debug"):
            effective_log_dir = cfg_snapshot.get("log_dir")

    if effective_log_dir is not None:
        try:
            write_remove_debug_md(ctx, effective_log_dir)
        except Exception:
            # Logging must never break the main pipeline
            pass

    return new_text, ctx



# ? Core execution API ------------------------------------------------------

def apply_remove_pipeline_to_field(
    text: str,
    field_name: Optional[str],
    ctx: RemoveContext,
    per: Dict[str, Any],
) -> str:

    working = text

    # 1) Generic remove ruleset (pattern/replacement), always looping up to remove_max_loops.
    #    We keep generic behavior here but do not currently log these into the dedicated
    #    remove MD file (that can be added later if desired).
    for rr in ctx.remove_ruleset:
        patt_raw = rr.get("pattern", "")
        if not patt_raw:
            continue

        # TXT remove rules: keep patterns verbatim.
        # Python `re` already interprets `\\n` as newline at execution time.
        # Converting `\\n` into a real newline here can also make debug/query-audit misleading.
        patt = _anki_txt_rule_unescape(patt_raw) if bool(rr.get("regex", True)) else patt_raw
        # NOTE: _anki_txt_rule_unescape() no longer converts \\n/\\t/\\r into control chars.
        # If you ever need to support literal-newline execution patterns, do it ONLY at
        # execution time and NEVER in query construction.
        if not patt:
            continue

        repl = rr.get("replacement", "")
        loops_cap = ctx.remove_max_loops
        is_regex = bool(rr.get("regex", True))
        flags = rr.get("flags", "ms")

        # ! Loop-safe remove: repeat single-pass substitutions until stable/cycle/cap.
        #   This prevents long stalls when patterns keep "matching" without converging.
        final_text = working
        total_subs = 0
        loops_used = 0
        break_reason = "stable"

        if is_regex:
            # If the regex can match empty-string, force single-pass to avoid runaway.
            # Use the same flag parsing as the rest of the engine.
            try:
                compiled = re.compile(patt, flags_from_str(flags))
                if _regex_can_match_empty(compiled) and loops_cap > 1:
                    loops_cap = 1
                    per["remove_empty_match_forced_single"] = per.get("remove_empty_match_forced_single", 0) + 1
            except Exception:
                # If compile fails here, apply_substitution will handle it (and logging elsewhere).
                pass

        final_text, total_subs, loops_used, break_reason = _loop_substitution_with_cycle_guard(
            patt,
            repl,
            working,
            is_regex=is_regex,
            flags=flags,
            max_loops=loops_cap,
        )

        working = final_text

        if total_subs:
            per["remove_field_subs"] = per.get("remove_field_subs", 0) + total_subs

        # Loop accounting: track both SUM and MAX so "cap=10" doesn't look violated.
        per["remove_loops_used_sum"] = per.get("remove_loops_used_sum", 0) + loops_used
        per["remove_loops_used_max"] = max(per.get("remove_loops_used_max", 0), loops_used)

        if loops_used > 1:
            per["remove_fields_looped"] = per.get("remove_fields_looped", 0) + 1
            per["remove_loop"] = True

        # Legacy/back-compat: keep remove_loops_used as the SUM
        per["remove_loops_used"] = per.get("remove_loops_used_sum", 0)

        # Optional: record why we stopped looping (useful for debugging stalls)
        br_key = f"remove_break_{break_reason}"
        per[br_key] = per.get(br_key, 0) + 1
        if break_reason == "cap":
            per["remove_cap_hits"] = per.get("remove_cap_hits", 0) + 1
        elif break_reason == "cycle":
            per["remove_cycle_hits"] = per.get("remove_cycle_hits", 0) + 1

    # 2) Field-remove patterns (from field_remove_rules.txt), applied as pure deletions.
    #    Optionally restricted to a subset of fields via remove_config.field_remove_fields.
    if ctx.field_remove_patterns and field_name:
        allowed_fields = ctx.field_remove_fields
        if allowed_fields is not None and field_name not in allowed_fields:
            # This field is not configured for field-remove behavior.
            return working

        # Access run-context if available
        run_ctx = ctx.run_ctx

        for idx, pat in enumerate(ctx.field_remove_patterns, start=1):
            before = working

            # Loop deletions until stable (or capped). This makes field-remove consistent
            # with ctx.remove_max_loops instead of being single-pass.
            rm_n_total = 0
            loops_used_here = 0
            prev = working
            for _ in range(max(ctx.remove_max_loops, 1)):
                working, rm_n = pat.subn("", working)
                loops_used_here += 1
                if rm_n:
                    rm_n_total += rm_n
                # stable: nothing removed or no net change
                if rm_n == 0 or working == prev:
                    break
                prev = working

            # Update stats if we have a run context and a stats entry for this (rule, field)
            if run_ctx is not None:
                key = RemoveFieldRuleKey(
                    rule_idx=idx,
                    source_file=run_ctx.field_source_file,
                    field_name=field_name,
                )
                stats = run_ctx.field_rules_stats.get(key)
                if stats is not None:
                    # Each call to apply_remove_pipeline_to_field is one "note seen" for this field
                    stats.notes_seen += 1
                    if rm_n_total:
                        stats.notes_matched += 1
                        stats.subs += rm_n_total
                        stats.rm_field_subs += rm_n_total
                        # Record up to a few examples
                        if len(stats.examples) < 3:
                            stats.examples.append(
                                {
                                    "field": field_name,
                                    "before": before,
                                    "after": working,
                                }
                            )
                        # Treat field-remove as looping-capable
                        if ctx.remove_max_loops > 1:
                            stats.loops_used = max(stats.loops_used, loops_used_here)

            # Maintain the legacy per-dict counters as well
            if rm_n_total:
                per["remove_field_subs"] = per.get("remove_field_subs", 0) + rm_n_total

            # Track field-remove loop usage as part of overall remove accounting.
            per["remove_loops_used_sum"] = per.get("remove_loops_used_sum", 0) + loops_used_here
            per["remove_loops_used_max"] = max(per.get("remove_loops_used_max", 0), loops_used_here)
            if loops_used_here > 1:
                per["remove_fields_looped"] = per.get("remove_fields_looped", 0) + 1
                per["remove_loop"] = True
            per["remove_loops_used"] = per.get("remove_loops_used_sum", 0)

        # Nothing to do here anymore: we update remove_loop/remove_loops_used_* per pattern above.
        if ctx.remove_max_loops > 1 and ctx.field_remove_patterns:
            pass

    return working


# ? Dedicated Markdown logger for remove rules ------------------------------
def write_remove_debug_md(
    ctx: RemoveContext,
    log_dir: Union[str, Path],
) -> Optional[Path]:
    """Write a dedicated Markdown debug log for remove rules.

    This file is separate from the main Batch_FR/Regex debug logs and only
    considers TXT-based remove behavior (especially field_remove_rules.txt).

    DESIGN:
    - Compact header with:
        - timestamp
        - field_remove_source
        - remove_max_loops
        - total number of fields
        - list of all fields
    - Then one section per (rule, field) in the examples area:

        ### *FieldName* field remove (rule X from `field_remove_rules.txt`)

        - query: "FieldName:re:<pattern>"
        - matches: <notes_matched>
        - search (Browser): "FieldName:re:<pattern>"

      The BEFORE/AFTER table is only rendered if we actually have examples.
    """

    run_ctx = ctx.run_ctx
    if run_ctx is None:
        return None

    log_dir_path = Path(log_dir)
    try:
        log_dir_path.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If we can't create the directory, bail out silently.
        return None

    log_name = f"Remove_FR_Debug__{run_ctx.timestamp_str}.md"
    log_path = log_dir_path / log_name

    lines: List[str] = []

    def _append_codeblock(val: Any) -> None:
        """Append a fenced markdown code block with safe, visible content.

        - Converts real control characters to visible sequences via md_inline
        - Never writes raw strings directly (prevents accidental multiline rendering)
        - Accepts str, list[str], or None
        """
        lines.append("```")
        if val is None:
            lines.append("")
        elif isinstance(val, list):
            joined = "\n".join("" if v is None else str(v) for v in val)
            for ln in joined.splitlines() or [joined]:
                lines.append(md_inline(ln))
        else:
            s = str(val)
            for ln in s.splitlines() or [s]:
                lines.append(md_inline(ln))
        lines.append("```")

    # Header ---------------------------------------------------------------
    lines.append("# Remove Rules Debug Log")
    lines.append("")
    lines.append(f"- timestamp: `{md_inline(run_ctx.timestamp_str)}`")
    lines.append(f"- field_remove_source: `{md_inline(run_ctx.field_source_file)}`")
    lines.append(f"- remove_max_loops: `{md_inline(run_ctx.remove_max_loops)}`")
    # Summarize fields once instead of a big per-rule table
    field_names = list(run_ctx.field_target_fields)
    lines.append(f"- Total Number of Fields: `{md_inline(len(field_names))}`")
    all_fields_str = ", ".join(field_names)
    lines.append(f"- All Fields: `{md_inline(all_fields_str)}`")
    lines.append("")
    # TXT remove ruleset (uno_remove_rules, etc.) ---------------------------
    lines.append("## TXT remove ruleset (selected remove_rules files)")
    lines.append("")
    if ctx.remove_ruleset:
        for i, rr in enumerate(ctx.remove_ruleset, 1):
            if not isinstance(rr, dict):
                continue
            raw_pat = rr.get("pattern", "")
            pat = _anki_txt_rule_unescape(raw_pat) if bool(rr.get("regex", True)) else raw_pat

            # This is the exact query string you paste into Browser
            q = rr.get("_effective_query")
            if not q:
                # Derive again defensively (in case context was built before patch reload)
                tmp = dict(rr)
                tmp["pattern"] = raw_pat
                q = _derive_effective_query_from_rule(tmp)

            lines.append(f"### Rule #{i}")
            lines.append(f"- pattern (raw): `{md_inline(raw_pat)}`")
            lines.append(f"- pattern (exec): `{md_inline(pat)}`")
            q_any = rr.get("_browser_query") or rr.get("_effective_query") or q
            if isinstance(q_any, list):
                q_show = "\n".join(str(x) for x in q_any)
            else:
                q_show = "" if q_any is None else str(q_any)

            lines.append("- browser query:")
            _append_codeblock(q_show)
            lines.append("")
    else:
        lines.append("_No TXT remove rules were loaded._")
        lines.append("")

    # Group stats by source_file (e.g. field_remove_rules.txt)
    by_source: Dict[str, List[RemoveRuleStats]] = defaultdict(list)
    for stats in run_ctx.field_rules_stats.values():
        by_source[stats.rule.source_file].append(stats)

    # TXT remove rules audit ------------------------------------------------
    # These come from *_remove_rules.txt style files (one pattern per line).
    lines.append("## TXT remove rules (query audit)")
    lines.append("")
    txt_rules = [r for r in (ctx.remove_ruleset or []) if isinstance(r, dict)]

    if not txt_rules:
        lines.append("_No TXT remove rules loaded._")
        lines.append("")
    else:
        # Show each rule with its derived query exactly as the user would paste it.
        for i, r in enumerate(txt_rules, start=1):
            patt = r.get("pattern", "")
            flags = r.get("flags", "ms")
            fields = r.get("fields", ["ALL"])
            loop = bool(r.get("loop", True))
            src = r.get("source_file") or r.get("_source_file") or Path(str(r.get("source_path") or r.get("_source_path") or "")).name or "unknown_source"

            browser_q = r.get("_browser_query") or r.get("_effective_query")
            find_q = r.get("_find_notes_query")  # normalized string via _as_find_notes_query()
            q_src = r.get("_query_source", "unknown")

            lines.append(f"### Rule {i}")
            lines.append("")
            lines.append(f"- source: `{md_inline(src)}`")
            lines.append(f"- flags: `{md_inline(flags)}`")
            lines.append(f"- fields: `{md_inline(fields)}`")
            lines.append(f"- loop: `{md_inline(loop)}`")
            lines.append(f"- query_source: `{md_inline(q_src)}`")
            lines.append("")
            lines.append(f"- pattern: `{md_inline(patt)}`")
            lines.append("")

            # Browser query: copy/paste friendly; patterns keep \\n as literal backslash+n (no real newlines).
            lines.append("- browser query (paste into Browser):")
            _append_codeblock(browser_q)

            # Backend query + candidate count
            cand = None
            err = None
            if mw is not None and find_q:
                try:
                    cand = len(mw.col.find_notes(find_q))
                except Exception as e:
                    err = str(e)

            if err:
                lines.append(f"- find_notes query error: `{md_inline(err)}`")
            else:
                if cand is not None:
                    lines.append(f"- find_notes candidates: `{md_inline(cand)}`")

            lines.append("")

    # Field-specific examples ---------------------------------------------
    lines.append("## Field-specific examples")
    any_blocks = False

    # One block per (rule, field), even when there were 0 matches (so you still see the query)
    for source_file, stats_list in by_source.items():
        stats_list_sorted = sorted(
            stats_list,
            key=lambda s: (s.rule.idx, s.field_name),
        )

        for s in stats_list_sorted:
            any_blocks = True
            lines.append("")
            lines.append(
                f"### *{s.field_name}* field remove (rule {s.rule.idx} from `{s.rule.source_file}`)"
            )
            lines.append("")

            # Build the field-specific query string
            if s.field_name and s.field_name != "ALL":
                query = f"{s.field_name}:re:{s.rule.pattern}"
            else:
                query = f"re:{s.rule.pattern}"

            matches = s.notes_matched

            # Wrap the whole query in quotes so it's exactly what you paste into the Browser
            lines.append(f'- query: `"{md_inline(query)}"`')
            lines.append(f"- matches: `{md_inline(matches)}`")
            lines.append(f'- search (Browser): `"{md_inline(query)}"`')

            # Only render a table when we actually have recorded examples
            if s.examples:
                lines.append("")
                lines.append("| field | BEFORE | AFTER |")
                lines.append("|---|---|---|")

                for ex in s.examples:
                    fld = ex.get("field", "")
                    before_raw = str(ex.get("before", ""))
                    after_raw = str(ex.get("after", ""))
                    lines.append(
                        f"| `{md_table_cell(fld)}` | `{md_table_cell(before_raw)}` | `{md_table_cell(after_raw)}` |"
                    )
            else:
                # No examples, just leave the bullet list as-is
                lines.append("")
                lines.append("_No examples recorded for this field/rule in this run._")

    if not any_blocks:
        lines.append("")
        lines.append("_No field remove rules were applied in this run._")

    try:
        log_path.write_text("\n".join(lines), encoding="utf-8")
    except Exception:
        return None

    return log_path