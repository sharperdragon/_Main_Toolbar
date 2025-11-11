# ! data.py — pure data shapes; no runtime imports of project modules
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple, Literal, TYPE_CHECKING

# If you need helper types only for hints, do:
if TYPE_CHECKING:
    from .tag_rename_utils import SomeTypeOnlyHint
    from .ops import OpChanges  # only for type hints

__all__ = ["Pair", "Preflight", "Outcome", "RegexRuleDebug", "ExecResult"]


# =========================
# Internal data structures
# =========================
@dataclass
class Pair:
    old: str
    new: str
    src: str = "unknown"      
    kind: str = "literal"     


@dataclass
class Preflight:
    total_loaded: int
    after_normalize: int
    cycles_blocked: List[Tuple[str, str]]
    valid_pairs: List[Pair]
    skipped_nonexistent: List[Pair]
    regex_no_match: List[Tuple[str, str, str]] | None = None
    regex_hits: Dict[str, int] | None = None
    existing_tags: List[str] | None = None
    regex_debug: List[RegexRuleDebug] | None = None


@dataclass
class Outcome:
    applied: List[Tuple[str, str, int, str]]  
    skipped: List[Tuple[str, str, str]]       
    warnings: List[str]
    total_notes_changed: int


@dataclass
class RegexRuleDebug:
    pattern: str
    replacement: str
    scope: str
    compile_ok: bool
    compile_error: str | None
    pool: str        
    pool_size: int
    matched_count: int
    examples: List[Tuple[str, str]]
    truncated: bool
    # Optional: show original vs normalized regex used in preflight
    orig_pattern: Optional[str] = None
    orig_replacement: Optional[str] = None
    normalized: bool = False

@dataclass
class ExecResult:
    outcome: Outcome
    changes: 'OpChanges'
