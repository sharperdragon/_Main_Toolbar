from __future__ import annotations

# * Standard library
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, TypedDict
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict,  List, Optional, Union


__ALL__ = [
    "TS_FORMAT",
    "DESKTOP_PATH",
    "MODULES_CONFIG_PATH",
    "now_stamp",
]

TS_FORMAT: str = "%H-%M_%m-%d"  
DESKTOP_PATH: Path = Path("/Users/claytongoddard/Desktop")

# Hard-coded rules path override
RULES_PATH: Path = "/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/modules/batch_FR/rules"
MODULES_CONFIG_PATH: Path = "/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/modules/modules_config.json"

@dataclass
class RunConfig:
    # NOTE: rules_path will be overridden globally by RULES_PATH in top_helper during config load.
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


def _coerce_int(val, fallback: int) -> int:
    try:
        return int(val)
    except Exception:
        return fallback

def _norm_path(p: str | None) -> Path | None:
    if not p:
        return None
    try:
        return Path(os.path.expanduser(p)).resolve()
    except Exception:
        return None

def now_stamp() -> str:
    return datetime.now().strftime(TS_FORMAT)
