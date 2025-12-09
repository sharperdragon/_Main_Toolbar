from __future__ import annotations

# * Standard library
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, TypedDict, Set
import json
import os


from .FR_global_utils import (
    TS_FORMAT,
    DESKTOP_PATH,
    MODULES_CONFIG_PATH, 
    BatchFRConfig,
    now_stamp, 
    _coerce_int, 
    _norm_path,
    RULES_PATH,
)



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
    # Resolve log directory:
    # - Prefer global_config["log_dir"] if present
    # - Normalize/expand it
    # - Ensure the directory exists
    # - Fall back to DESKTOP_PATH only on failure
    raw_log_dir = g.get("log_dir")
    if raw_log_dir:
        tmp_log_dir = _norm_path(raw_log_dir) or DESKTOP_PATH
    else:
        tmp_log_dir = DESKTOP_PATH

    try:
        # Ensure we have a concrete Path and that it exists on disk.
        log_dir_path = Path(tmp_log_dir).expanduser().resolve()
        log_dir_path.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Hard fallback: use the Desktop path if anything goes wrong.
        log_dir_path = DESKTOP_PATH
        try:
            log_dir_path.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Last-resort: leave as-is; logging will best-effort.
            pass

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

    rules_path = RULES_PATH

    # build engine-facing snapshot
    snapshot: BatchFRConfig = {
        "ts_format": ts_fmt,
        "log_dir": str(log_dir_path),
        "rules_path": str(rules_path),
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

# NOTE: Ensure modules_config.json uses the correct key "rules_path" so discovery works.
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


# ------------------------------
# Rule alias helpers
# ------------------------------
def _get_alias_file_path() -> Path:
    """
    Return the path to the rule alias file, kept under this module's utils folder.
    """
    base_dir = Path(__file__).resolve().parent 
    return base_dir / "rule_aliases.json"


def _load_rule_aliases(rule_files: List[Path]) -> Dict[str, str]:
    """
    Load or initialize rule aliases for the given rule files.

    On disk, aliases are stored grouped by rule-folder, e.g.:

        {
          "Main": {
            "acid-base_rules.json": "Acid–base",
            "electrolytes_rules.json": "Electrolytes"
          },
    At runtime, this function returns a flat mapping keyed by filename:

        { "acid-base_rules.json": "Acid–base", ... }

    Any missing filenames will be added with an empty string so the user
    can fill them in later.
    """
    alias_path = _get_alias_file_path()

    # * Internal structure: {group: {filename: alias, ...}, ...}
    group_aliases: Dict[str, Dict[str, str]] = {}
    legacy_flat: Dict[str, str] = {}

    # ? Try to load any existing alias file.
    if alias_path.exists():
        try:
            text = alias_path.read_text(encoding="utf-8")
            data = json.loads(text)
            if isinstance(data, dict):
                # If all values are dicts, assume grouped schema;
                # otherwise treat as legacy flat {filename: alias}.
                if data and all(isinstance(v, dict) for v in data.values()):
                    for g, mapping in data.items():
                        if isinstance(mapping, dict):
                            group_aliases[str(g)] = {
                                str(k): str(v) for k, v in mapping.items()
                            }
                else:
                    legacy_flat = {str(k): str(v) for k, v in data.items()}
        except Exception:
            group_aliases = {}
            legacy_flat = {}

    # Figure out rules_root from the shared RULES_PATH constant
    rules_root: Path | None = None
    try:
        rules_root = Path(RULES_PATH).expanduser().resolve()
    except Exception:
        rules_root = None

    changed = False

    # * Upgrade legacy flat mapping into grouped form if present.
    if legacy_flat:
        changed = True  # force rewrite in grouped schema
        files_by_name: Dict[str, Path] = {p.name: p for p in rule_files}

        for fname, alias in legacy_flat.items():
            path = files_by_name.get(fname)
            if path is not None:
                group, file_name, _ = _rule_group_and_name(path, rules_root)
                if not group:
                    group = "<Top>"
            else:
                # If we can't map this filename to a current rule file, keep it in "<Top>"
                group = "<Top>"
                file_name = str(fname)

            grp = group_aliases.setdefault(group, {})
            # Don't overwrite an existing alias if grouped data already had it.
            if file_name not in grp:
                grp[file_name] = alias

    # * Ensure every discovered rule file has an entry in the grouped mapping.
    for rf in rule_files:
        group, file_name, _ = _rule_group_and_name(rf, rules_root)
        if not group:
            group = "<Top>"
        grp = group_aliases.setdefault(group, {})
        if file_name not in grp:
            grp[file_name] = ""  # stub for later editing
            changed = True

    # * If something changed (or file didn't exist), write grouped JSON back to disk.
    if changed or not alias_path.exists():
        try:
            alias_path.parent.mkdir(parents=True, exist_ok=True)
            # Sort groups and filenames for stable, readable output.
            out: Dict[str, Dict[str, str]] = {}
            for group in sorted(group_aliases.keys()):
                inner = group_aliases[group]
                out[group] = {k: inner[k] for k in sorted(inner.keys())}
            alias_path.write_text(
                json.dumps(out, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            # Best effort only; if write fails, continue in-memory.
            pass

    # * Build flat mapping keyed by filename, for the rest of the code.
    flat_aliases: Dict[str, str] = {}
    for rf in rule_files:
        group, file_name, _ = _rule_group_and_name(rf, rules_root)
        if not group:
            group = "<Top>"
        alias = group_aliases.get(group, {}).get(file_name, "")
        flat_aliases[file_name] = alias

    return flat_aliases

# ------------------------------
# Rule favorites helpers
# ------------------------------

def _get_favorites_file_path() -> Path:
    """
    Return the path to the rule favorites file, kept under this module's utils folder.

    We store favorites as a simple list of filenames (e.g. "acid-base_rules.json").
    """
    base_dir = Path(__file__).resolve().parent  # .../batch_FR/utils
    return base_dir / "rule_favorites.json"


def _save_rule_favorites(favorites: Set[str]) -> None:
    """
    Persist the favorites set as a sorted JSON list of filenames.

    Favorites are stored by filename only so they can be grouped across
    folders and re-discovered regardless of the active group.
    """
    fav_path = _get_favorites_file_path()
    try:
        fav_path.parent.mkdir(parents=True, exist_ok=True)
        fav_path.write_text(
            json.dumps(sorted(favorites), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        # Favorites are "nice-to-have"; on failure we just skip persisting.
        return


def _load_rule_favorites(rule_files: List[Path]) -> Set[str]:
    """
    Load the set of favorited rule files.

    We store favorites as a JSON list of filenames.
    Any favorites that no longer exist on disk are silently dropped.
    """
    fav_path = _get_favorites_file_path()
    favorites: Set[str] = set()

    if fav_path.exists():
        try:
            raw = fav_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, list):
                favorites = {str(x) for x in data}
            elif isinstance(data, dict) and "favorites" in data:
                # Allow future/legacy dict-based schema
                items = data.get("favorites") or []
                if isinstance(items, list):
                    favorites = {str(x) for x in items}
        except Exception:
            # On any parse error, fall back to an empty favorites set.
            favorites = set()

    # Only keep entries that match an existing rule file by filename
    existing_names = {p.name for p in rule_files}
    filtered = favorites & existing_names

    # If we dropped anything (or file didn't exist), write back the cleaned set
    if filtered != favorites or (not fav_path.exists() and filtered):
        _save_rule_favorites(filtered)

    return filtered


def _rule_group_and_name(raw_src: Any, rules_root: Path | None) -> tuple[str, str, str]:
    """
    Return (group, file_name, display_label) for a rule source.

    - group: first folder under rules_root, or "" if not applicable
    - file_name: basename of the file
    - display_label: "[group] file_name" if group present, else "file_name"
    """
    if not raw_src:
        return "", "", "<?>"

    try:
        p = Path(str(raw_src)).expanduser().resolve()
    except Exception:
        s = str(raw_src)
        s = s or "<?>"
        return "", s, s

    file_name = p.name or "<?>"

    if rules_root is None:
        return "", file_name, file_name

    try:
        rel = p.relative_to(rules_root)
        parts = rel.parts
        if len(parts) > 1:
            group = parts[0]
            return group, file_name, f"[{group}] {file_name}"
    except Exception:
        pass

    return "", file_name, file_name



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


def _pretty_label_for_file(
    path: Path,
    aliases: Dict[str, str],
    rules_root: Path | None,
) -> str:
    """
    Build a display label for the left list:
    - Prefer alias if non-empty.
    - Otherwise use "[group] filename" style from _rule_group_and_name.
    """
    alias = aliases.get(path.name, "").strip()
    if alias:
        return alias

    _, _, label = _rule_group_and_name(path, rules_root)
    return label


# --------------------------------------
# Public wrapper for rule favorites
# --------------------------------------
def load_rule_favorites_for_files(rule_files: List[Path]) -> Set[str]:
    return _load_rule_favorites(rule_files)