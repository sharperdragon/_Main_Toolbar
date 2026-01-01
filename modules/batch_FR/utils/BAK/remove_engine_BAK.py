# file that handles remove rules txt files separately and sends to logger

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from typing import Pattern

from .rules_io import load_remove_sets_from_config
from .regex_utils import apply_substitution
from .FR_global_utils import RunConfig, load_field_remove_rules


# * Context object that holds all remove-related configuration for a run
@dataclass
class RemoveContext:
    remove_cfg: Dict[str, Any]
    remove_ruleset: List[Dict[str, Any]]
    field_remove_patterns: List[Pattern[str]]
    remove_max_loops: int
    field_remove_fields: list[str] | None


def _resolve_field_remove_path(
    cfg_snapshot: Dict[str, Any],
    field_remove_rules: Optional[Union[str, Path]] = None,
) -> Optional[Path]:
    """Resolve the path to the field-remove rules file.

    Precedence:
    1) Explicit function argument `field_remove_rules`.
    2) `cfg_snapshot["field_remove_path"]` if present.
    3) `cfg_snapshot["rules_path"]` + `cfg_snapshot["field_remove_rules_name"]`.
    """

    field_remove_path: Optional[Path] = None

    # 1) explicit argument wins
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


def build_remove_context(
    cfg: RunConfig,
    cfg_snapshot: Dict[str, Any],
    remove_rules: Optional[Union[str, Path]] = None,
    field_remove_rules: Optional[Union[str, Path]] = None,
) -> RemoveContext:
    """Build a RemoveContext for a batch_FR run.

    - Computes loop caps from cfg.remove_config / cfg.max_loops.
    - Loads the generic remove ruleset (e.g. uno_remove_rules.txt).
    - Loads and compiles the field-remove patterns from field_remove_rules.txt.
    """

    remove_cfg: Dict[str, Any] = getattr(cfg, "remove_config", {}) or {}

    # * Dedicated loop cap for remove rules (TXT-based remove always loops up to this)
    try:
        remove_max_loops = int(remove_cfg.get("max_loops", getattr(cfg, "max_loops", 30)))
    except Exception:
        remove_max_loops = getattr(cfg, "max_loops", 30)

    if remove_max_loops < 1:
        remove_max_loops = 30

    # Load generic remove ruleset from config snapshot
    remove_sets = load_remove_sets_from_config(cfg_snapshot)
    remove_ruleset: List[Dict[str, Any]] = remove_sets.get("remove", [])

    # Resolve and load field-remove rules (compiled regex patterns)
    field_remove_path = _resolve_field_remove_path(cfg_snapshot, field_remove_rules)
    field_remove_patterns: List[Pattern[str]]
    field_remove_enabled = bool(remove_cfg.get("field_remove_enable", True))
    if field_remove_enabled:
        # When no explicit path is provided, fall back to the default path in FR_global_utils
        field_remove_patterns = (
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

    return RemoveContext(
        remove_cfg=remove_cfg,
        remove_ruleset=remove_ruleset,
        field_remove_patterns=field_remove_patterns,
        remove_max_loops=remove_max_loops,
        field_remove_fields=fr_fields,
    )


def apply_remove_pipeline_to_field(
    text: str,
    field_name: str | None,
    ctx: RemoveContext,
    per: Dict[str, Any],
) -> str:
    """Apply the full remove pipeline (global remove + field-remove) to a field.

    This function is designed to be called from engine.py per note/field. It
    updates the `per` dict in-place for logging (e.g. remove_field_subs,
    remove_loops_used, remove_loop).
    """

    working = text

    # 1) Generic remove ruleset (pattern/replacement), always looping up to remove_max_loops
    for rr in ctx.remove_ruleset:
        patt = rr.get("pattern", "")
        if not patt:
            continue

        repl = rr.get("replacement", "")

        # All TXT-based remove rules are treated as looping rules.
        loops_cap = ctx.remove_max_loops

        working, rm_n, loops_used = apply_substitution(
            patt,
            repl,
            working,
            is_regex=bool(rr.get("regex", True)),
            flags=rr.get("flags", "ms"),
            max_loops=loops_cap,
        )
        if rm_n:
            per["remove_field_subs"] = per.get("remove_field_subs", 0) + rm_n

            # If we actually did removals and allow multiple passes, treat as looping
            if ctx.remove_max_loops > 1:
                if loops_used:
                    per["remove_loops_used"] = per.get("remove_loops_used", 0) + loops_used
                else:
                    # At least mark one loop for logging if apply_substitution didn't report it
                    per["remove_loops_used"] = max(per.get("remove_loops_used", 0), 1)
                per["remove_loop"] = True

    # 2) Field-remove patterns (from field_remove_rules.txt), applied as pure deletions
    #    Optionally restricted to a subset of fields via remove_config.field_remove_fields.
    if ctx.field_remove_patterns:
        allowed_fields = ctx.field_remove_fields
        if allowed_fields is not None and field_name is not None:
            # Only apply field-remove patterns when this field is explicitly allowed.
            if field_name not in allowed_fields:
                return working

        any_removed = False
        for pat in ctx.field_remove_patterns:
            working, rm_n = pat.subn("", working)
            if rm_n:
                per["remove_field_subs"] = per.get("remove_field_subs", 0) + rm_n
                any_removed = True

        # Treat field-remove rules as looping-capable whenever they are active.
        # This matches the design that all remove rules are "looping" rules
        # bounded by remove_max_loops, even if a particular run finds nothing.
        if ctx.remove_max_loops > 1 and ctx.field_remove_patterns:
            per["remove_loops_used"] = max(per.get("remove_loops_used", 0), 1)
            per["remove_loop"] = True

    return working