from __future__ import annotations

# * Standard library
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, TypedDict
import json
import os

#from ..gui.ui_dialog import prompt_batch_fr_run_options as _prompt_batch_fr_run_options


__all__ = [
    "TS_FORMAT",
    "DESKTOP",
    "MODULES_CONFIG_PATH",
    "now_stamp",
    "BatchFRConfig",
    "load_batch_fr_config",
    "_get_rules_root",
    "_discover_rule_files",
    "_group_rule_files_by_folder",
    "_get_alias_file_path",
    "_load_rule_aliases",
    "_pretty_rule_file_label",
    "_prompt_batch_fr_run_options",
    "_prompt_batch_fr_mode",
]

# ! User-tunable constants (overridden by modules_config.json if present)
TS_FORMAT: str = "%H-%M_%m-%d"  # 24-hour-minute_month-day
DESKTOP: Path = Path("/Users/claytongoddard/Desktop")

# ? Default config path for this module (relative to the modules folder)
MODULES_CONFIG_PATH: Path = Path(__file__).resolve().parent.parent / "modules_config.json"

# ? Utility: timestamp maker used by reports/logs
def now_stamp() -> str:
    return datetime.now().strftime(TS_FORMAT)

# ------------------------------
# Config loading & normalization
# ------------------------------
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

def load_batch_fr_config(config_path: Path | str | None = None) -> BatchFRConfig:
    """Load + normalize batch F&R config from modules_config.json; apply safe fallbacks."""
    cfg_path = Path(config_path) if config_path else MODULES_CONFIG_PATH
    data: Dict[str, Any] = {}
    try:
        text = cfg_path.read_text(encoding="utf-8")
        data = json.loads(text)
    except Exception:
        data = {}

    g = data.get("global_config", {}) or {}
    b = data.get("batch_FR_config", {}) or {}

    ts_fmt = g.get("ts_format") or TS_FORMAT
    log_dir_path = _norm_path(g.get("log_dir")) or DESKTOP

    # normalize types / names
    max_loops = _coerce_int(b.get("max_loops", 30), 30)

    # Resolve rules_path; treat relative paths as relative to the config file directory
    raw_rules_path = b.get("rules_path")
    rules_path: Path | None = None
    if raw_rules_path:
        candidate = Path(os.path.expanduser(raw_rules_path))
        if candidate.is_absolute():
            rules_path = candidate.resolve()
        else:
            base_dir = cfg_path.parent
            rules_path = (base_dir / candidate).resolve()

    fields_all = b.get("fields_all") or []
    defaults = b.get("Defaults") or {}
    remove_cfg = b.get("remove_config") or {}
    log_mode = (b.get("log_mode") or "diff").lower()
    include_unchanged = bool(b.get("include_unchanged", False))

    # Support both the correct and legacy misspelled key for order preference
    order_pref = b.get("order_preference")
    if order_pref is None:
        order_pref = b.get("order_prefernce") or {}

    # Optional: per-module debug configuration and Anki regex checking toggle
    batch_debug_cfg = b.get("batch_FR_debug") or b.get("batch_fr_debug") or {}
    if not isinstance(batch_debug_cfg, dict):
        batch_debug_cfg = {}
    anki_regex_check_val = b.get("anki_regex_check", True)

    # Update top-level constants so timestamps/tooltips match config
    globals()["TS_FORMAT"] = ts_fmt
    globals()["DESKTOP"] = log_dir_path

    # build engine-facing snapshot
    snapshot: BatchFRConfig = {
        "ts_format": ts_fmt,
        "log_dir": str(log_dir_path),
        "rules_path": str(rules_path) if rules_path else "",
        "fields_all": fields_all,
        "defaults": defaults,
        "remove_config": remove_cfg,
        "log_mode": log_mode,
        "include_unchanged": include_unchanged,
        "max_loops": max_loops,
        "order_preference": order_pref,
        "batch_fr_debug": batch_debug_cfg,
        "anki_regex_check": bool(anki_regex_check_val),
    }
    return snapshot


# --------------------------------------
# Helper: Get rules root directory
# --------------------------------------
def _get_rules_root(cfg: BatchFRConfig) -> Path | None:
    """
    Derive the 'rules root' directory from the normalized config.

    - If cfg["rules_path"] is empty or invalid, returns None.
    - If rules_path points to a file, we treat its parent as the root.
    """
    rules_path_str = cfg.get("rules_path") or ""
    if not rules_path_str:
        return None
    try:
        p = Path(os.path.expanduser(rules_path_str)).resolve()
    except Exception:
        return None
    # * If they configured a file path by mistake, use its parent as the root
    return p.parent if p.is_file() else p



# ------------------------------
# Public API wrappers
# ------------------------------

def _discover_rule_files(cfg: BatchFRConfig) -> List[Path]:
    """Discover candidate rule files from the configured rules_path.

    Uses the shared rules_io helpers so we include .json/.jsonl/.txt
    and respect any order_preference in the config.
    """
    # Lazy import so top-level import of this module remains robust even if
    # utils/rules_io.py has issues (e.g., during testing).
    try:
        from .rules_io import discover_rule_files, sort_paths_by_preference  # type: ignore
    except Exception:
        return []

    rules_path_str = cfg.get("rules_path") or ""
    if not rules_path_str:
        return []

    # Discover files under the configured rules_path
    try:
        paths = discover_rule_files(rules_path_str)
    except Exception:
        return []

    # Apply optional ordering preferences if provided
    order_pref = cfg.get("order_preference") or cfg.get("order_prefernce") or {}
    try:
        paths = sort_paths_by_preference(list(paths), order_pref)  # type: ignore[arg-type]
    except Exception:
        # Fallback: sort by filename only
        try:
            paths = sorted(paths, key=lambda p: p.name.lower())
        except Exception:
            pass

    # De-duplicate while preserving order
    seen = set()
    unique_files: List[Path] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_files.append(p)

    return unique_files


# --------------------------------------
# Helper: Group rule files by folders
# --------------------------------------
def _group_rule_files_by_folder(
    rule_files: List[Path],
    rules_root: Path | None,
) -> tuple[list[str], dict[str, list[Path]]]:
    """
    Group rule files by their first folder under rules_root.

    Examples (assuming rules_root = /.../rules):
      /rules/Main/acid-base_rules.json -> group "Main"
      /rules/Beta/acid-base_rules.json -> group "Beta"

    Files outside rules_root (or when rules_root is None) are placed into "<Top>".
    """
    from collections import defaultdict

    group_to_files: dict[str, list[Path]] = defaultdict(list)

    for p in rule_files:
        group = "<Top>"
        if rules_root is not None:
            try:
                rel = p.resolve().relative_to(rules_root)
                parts = rel.parts
                if len(parts) > 1:
                    group = parts[0]
            except Exception:
                # Best-effort only: if relative_to fails, keep as "<Top>"
                pass
        group_to_files[group].append(p)

    groups = sorted(group_to_files.keys())

    # * If there are multiple groups, add a synthetic "All" group at the top
    if len(groups) > 1:
        all_files = sorted(rule_files, key=lambda p: p.name.lower())
        group_to_files["All"] = all_files
        groups.insert(0, "All")

    return groups, group_to_files


# ------------------------------
# Rule alias helpers
# ------------------------------
def _get_alias_file_path() -> Path:
    """
    Return the path to the rule alias file, kept under this module's utils folder.
    """
    base_dir = Path(__file__).resolve().parent  # .../batch_FR
    return base_dir / "utils" / "rule_aliases.json"


def _load_rule_aliases(rule_files: List[Path]) -> Dict[str, str]:
    """
    Load or initialize rule aliases for the given rule files.

    The alias file is a JSON dict mapping:
        { "filename.json": "Nice label", ... }

    Any missing filenames will be added with an empty string so the user
    can fill them in later.
    """
    alias_path = _get_alias_file_path()
    aliases: Dict[str, str] = {}

    # Load existing file if present
    if alias_path.exists():
        try:
            text = alias_path.read_text(encoding="utf-8")
            data = json.loads(text)
            if isinstance(data, dict):
                # ensure all keys/values are strings
                aliases = {str(k): str(v) for k, v in data.items()}
        except Exception:
            aliases = {}

    # Ensure each rule file has an entry
    changed = False
    for rf in rule_files:
        key = rf.name  # filename only
        if key not in aliases:
            aliases[key] = ""   # stub for user to fill in
            changed = True

    # If we added any keys or the file doesn't exist yet, write a sorted JSON
    if changed or not alias_path.exists():
        try:
            sorted_aliases = {k: aliases[k] for k in sorted(aliases.keys())}
            alias_path.write_text(
                json.dumps(sorted_aliases, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            aliases = sorted_aliases
        except Exception:
            # best-effort only; if write fails, we just keep in-memory aliases
            pass

    return aliases


def _pretty_rule_file_label(path: Path, aliases: Dict[str, str] | None = None) -> str:
    """
    Generate a human-friendly label for a rule file:
    - if an alias is defined in rule_aliases.json, use that
    - otherwise, strip common suffixes and replace underscores with spaces
    """
    if aliases:
        alias = aliases.get(path.name)
        if alias:
            return alias

    name = path.name

    # Strip common suffixes
    for suf in ("_rules.json", "_rule.json", ".json"):
        if name.endswith(suf):
            name = name[: -len(suf)]
            break

    # Turn underscores into spaces for readability
    name = name.replace("_", " ")

    return name or path.name


def _prompt_batch_fr_mode(parent) -> Optional[bool]:
    """
    Show a modal dialog asking how to run Batch Find & Replace.

    Returns:
        True  -> Dry run (no changes)
        False -> Apply changes (live)
        None  -> User cancelled
    """
    try:
        from aqt.qt import QMessageBox  # type: ignore
    except Exception:
        # If Qt is not available for some reason, fall back to cancel.
        return None

    box = QMessageBox(parent)
    box.setWindowTitle("Batch Find & Replace — Choose Mode")
    box.setText("How would you like to run Batch Find & Replace?")

    dry_btn = box.addButton("Dry Run (no changes)", QMessageBox.AcceptRole)
    live_btn = box.addButton("Apply Changes", QMessageBox.DestructiveRole)
    cancel_btn = box.addButton(QMessageBox.Cancel)

    box.exec()
    clicked = box.clickedButton()

    if clicked is cancel_btn:
        return None
    if clicked is dry_btn:
        return True
    if clicked is live_btn:
        return False

    # Fallback: treat anything unexpected as cancel.
    return None
