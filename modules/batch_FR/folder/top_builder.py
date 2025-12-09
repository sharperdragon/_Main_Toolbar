from __future__ import annotations

# * Standard library
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, TypedDict
import json
import os

from ..gui.ui_dialog import prompt_batch_fr_run_options as _prompt_batch_fr_run_options

from ..utils.FR_global_utils import (
    TS_FORMAT,
    DESKTOP,
    MODULES_CONFIG_PATH,
    now_stamp,
    BatchFRConfig,
    load_batch_fr_config,
    _get_rules_root,
    _discover_rule_files,
    _group_rule_files_by_folder,
)



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


