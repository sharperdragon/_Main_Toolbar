# data.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    Any, Dict,  Optional, Union, Pattern, List, TypedDict
)


# ? -----------------------------------------------------------------------------------
# ? Main data structures -----------------------------------------------------
@dataclass
class RunConfig:
    ts_format: str
    log_dir: str
    rules_path: str
    fields_all: List[str]
    defaults: Dict[str, Any]
    remove_config: Dict[str, Any]
    log_mode: str
    include_unchanged: bool
    max_loops: int
    order_preference: Dict[str, Any]

@dataclass
class Rule:
    query: Union[str, List[str]]
    exclude_query: Union[str, List[str], None]
    pattern: Union[str, List[str]]
    replacement: str
    regex: bool
    flags: Union[str, int]
    fields: List[str]
    loop: bool
    delete_chars: Dict[str, Any]
    # Provenance fields
    source_file: Optional[str] = None
    source_path: Optional[str] = None
    source_index: Optional[int] = None


class BatchFRConfig(TypedDict, total=False):
    ts_format: str
    log_dir: str
    rules_path: str
    fields_all: list[str]
    defaults: dict
    remove_config: dict
    log_mode: str
    include_unchanged: bool
    max_loops: int
    order_preference: dict
    batch_fr_debug: dict
    anki_regex_check: bool



# ? -----------------------------------------------------------------------------------
# ? Remove_runner data structures -----------------------------------------------------

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
    # ? Guard: ensure we only write Remove_FR_Debug once per run (not per note/field)
    debug_written: bool = False


@dataclass
class RemoveContext:
    """Context used during a batch_FR run for all remove-related work."""
    remove_cfg: Dict[str, Any]
    remove_ruleset: List[Dict[str, Any]]
    field_remove_patterns: List[Pattern[str]]
    remove_max_loops: int
    field_remove_fields: Optional[List[str]]
    run_ctx: Optional[RemoveRunContext] = None