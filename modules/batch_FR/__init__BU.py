from __future__ import annotations

# * Standard library
from pathlib import Path
from datetime import datetime
from typing import List, Union, Optional, Dict, Any, TypedDict
import json
import os

# * Anki/Qt – optional at import time to keep unit tests simple
try:  # pragma: no cover
    from aqt import mw  # type: ignore
except Exception:  # pragma: no cover
    mw = None  # Allow import outside Anki (e.g., tests)

# * Deferred import of the implementation to avoid hard dependency during load
#   The implementation file lives next to this shim as: engine.py
try:
    from .utils.engine import run_batch_find_replace as _impl_run_batch_find_replace  # type: ignore
except Exception as _e:  # pragma: no cover
    _impl_run_batch_find_replace = None  # type: ignore
    _IMPORT_ERROR = _e
else:
    _IMPORT_ERROR = None


__all__ = [
    "TS_FORMAT",
    "DESKTOP",
    "now_stamp",
    "load_batch_fr_config",
    "run_batch_find_replace",
    "run_from_toolbar",
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
def run_batch_find_replace(
    mw_ref, *,
    rulesets: List[Union[str, Path, Dict[str, Any]]],
    remove_rules: Optional[Union[str, Path]] = None,
    field_remove_rules: Optional[Union[str, Path]] = None,
    config_path: Optional[Union[str, Path]] = None,
    dry_run: Optional[bool] = None,
    show_progress: bool = True,
    notes_limit: Optional[int] = None,
    rules_files: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """
    Public entry point used by host modules.

    - mw_ref: aqt.mw (Anki main window) or a reference providing .col
    - rulesets: list of rule file paths OR already-loaded rule dicts
    - remove_rules / field_remove_rules: optional pattern files
    - config_path: path to modules_config.json; if None, default MODULES_CONFIG_PATH is used
    - dry_run: override DRY_RUN if provided (engine decides default)
    - show_progress: show a cancellable QProgressDialog
    - notes_limit: limit processed notes (useful for quick tests)

    Returns a dict report (paths, counters, summaries).
    """
    cfg = load_batch_fr_config(config_path)

    if _impl_run_batch_find_replace is None:  # pragma: no cover
        # ! Implementation not present – provide actionable guidance
        raise ImportError(
            "batch_FR: missing implementation 'engine.py' (run_batch_find_replace) next to __init__.py.\n"
            f"Original import error: {_IMPORT_ERROR}"
        )

    return _impl_run_batch_find_replace(
        mw_ref,
        rulesets=rulesets,
        remove_rules=remove_rules,
        field_remove_rules=field_remove_rules,
        config_snapshot=cfg,   # pass normalized config
        dry_run=dry_run,
        show_progress=show_progress,
        notes_limit=notes_limit,
        rules_files=rules_files,
    )

def _discover_rule_files(cfg: BatchFRConfig) -> List[Path]:
    """Discover candidate rule files from the configured rules_path.

    Uses the shared rules_io helpers so we include .json/.jsonl/.txt
    and respect any order_preference in the config.
    """
    # Lazy import so top-level import of this module remains robust even if
    # utils/rules_io.py has issues (e.g., during testing).
    try:
        from .utils.rules_io import discover_rule_files, sort_paths_by_preference  # type: ignore
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

def _prompt_batch_fr_run_options(
    parent,
    rule_files: List[Path],
    rules_root: Path | None = None,
) -> Optional[Dict[str, Any]]:
    """
    Show a modal dialog asking:
      1) Which rule files to run (grouped by folder under rules_root)
      2) Whether to run as dry run or live

    Returns:
        {"dry_run": bool, "rules_files": List[Path]} on OK
        None on cancel or error
    """
    if not rule_files:
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip("Batch F&R: no rule files found under 'rules_path' in modules_config.json.", period=5000)
        except Exception:
            pass
        return None

    try:
        from aqt.qt import (  # type: ignore
            QDialog,
            QListWidget,
            QListWidgetItem,
            QVBoxLayout,
            QHBoxLayout,
            QRadioButton,
            QDialogButtonBox,
            QPushButton,
            QLabel,
            QComboBox,
            Qt,
        )
    except Exception:
        # If Qt cannot be imported, bail out gracefully.
        return None

    # Load or initialize aliases for the discovered rule files
    aliases = _load_rule_aliases(rule_files)

    # Group rules by folders under the configured rules_root
    group_names, group_to_files = _group_rule_files_by_folder(rule_files, rules_root)

    dlg = QDialog(parent)
    dlg.setWindowTitle("Batch Find & Replace — Select Rule Files")

    layout = QVBoxLayout(dlg)
    layout.addWidget(QLabel("Select which rule files to run:", dlg))

    # * Optional group selector row (only shown when we have multiple groups)
    group_combo: QComboBox | None = None
    if len(group_names) > 1:
        group_row = QHBoxLayout()
        group_label = QLabel("Rule set:", dlg)
        group_combo = QComboBox(dlg)
        group_combo.addItems(group_names)
        group_row.addWidget(group_label)
        group_row.addWidget(group_combo)
        group_row.addStretch()
        layout.addLayout(group_row)

    # * List of rule files with checkboxes
    list_widget = QListWidget(dlg)
    layout.addWidget(list_widget)

    def populate_list_for_group(group_name: str) -> None:
        """Rebuild the checklist for the selected group."""
        list_widget.clear()
        files = group_to_files.get(group_name, [])
        for path in files:
            label = _pretty_rule_file_label(path, aliases)
            item = QListWidgetItem(label)
            item.setToolTip(str(path))
            # ? Store the full path string so selection logic does not depend on indices
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            # ! Qt6: use ItemFlag enum for user-checkable items
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            # * Qt6: use CheckState enum for checkbox state
            item.setCheckState(Qt.CheckState.Checked)
            list_widget.addItem(item)

    # * Choose default group when dialog opens
    if group_names:
        if "Main" in group_names:
            default_group = "Main"
        elif "All" in group_names:
            default_group = "All"
        else:
            default_group = group_names[0]

        populate_list_for_group(default_group)

        if group_combo is not None:
            idx = group_combo.findText(default_group)
            if idx >= 0:
                group_combo.setCurrentIndex(idx)
            group_combo.currentTextChanged.connect(populate_list_for_group)
    else:
        # Fallback: if grouping somehow produced no groups, just show all rule_files
        for path in rule_files:
            label = _pretty_rule_file_label(path, aliases)
            item = QListWidgetItem(label)
            item.setToolTip(str(path))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            list_widget.addItem(item)

    # * Select all / Select none controls
    btn_row = QHBoxLayout()
    select_all_btn = QPushButton("Select all", dlg)
    select_none_btn = QPushButton("Select none", dlg)
    btn_row.addWidget(select_all_btn)
    btn_row.addWidget(select_none_btn)
    btn_row.addStretch()
    layout.addLayout(btn_row)

    def _select_all() -> None:
        for i in range(list_widget.count()):
            list_widget.item(i).setCheckState(Qt.CheckState.Checked)

    def _select_none() -> None:
        for i in range(list_widget.count()):
            list_widget.item(i).setCheckState(Qt.CheckState.Unchecked)

    select_all_btn.clicked.connect(_select_all)
    select_none_btn.clicked.connect(_select_none)

    # * Mode selection: dry run vs live
    mode_row = QHBoxLayout()
    mode_label = QLabel("Run mode:", dlg)
    dry_radio = QRadioButton("Dry run (no changes)", dlg)
    live_radio = QRadioButton("Apply changes", dlg)
    dry_radio.setChecked(True)
    mode_row.addWidget(mode_label)
    mode_row.addWidget(dry_radio)
    mode_row.addWidget(live_radio)
    mode_row.addStretch()
    layout.addLayout(mode_row)

    # * OK / Cancel buttons
    buttons = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        parent=dlg,
    )
    layout.addWidget(buttons)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    while True:
        result = dlg.exec()
        # ! Qt6: Accepted is now under QDialog.DialogCode
        if result != QDialog.DialogCode.Accepted:
            return None

        # Collect selected rule files
        selected: List[Path] = []
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            if item.checkState() != Qt.CheckState.Checked:
                continue
            path_str = item.data(Qt.ItemDataRole.UserRole)
            if not path_str:
                continue
            try:
                selected.append(Path(str(path_str)))
            except Exception:
                # Skip any malformed entries without breaking the run
                continue

        if not selected:
            # Require at least one rule file
            try:
                from aqt.utils import tooltip  # type: ignore
                tooltip("Batch F&R: please select at least one rule file.", period=3000)
            except Exception:
                pass
            # Loop back to dialog
            continue

        dry_run = bool(dry_radio.isChecked())
        return {
            "dry_run": dry_run,
            "rules_files": selected,
        }

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

def run_from_toolbar() -> None:
    """
    Convenience launcher for wiring to a toolbar/menu action.
    Loads modules_config.json and executes using its paths.
    """
    if mw is None:  # pragma: no cover
        # ! Calling from outside Anki – safe no-op with guidance
        raise RuntimeError("run_from_toolbar() must be called from within Anki (aqt.mw unavailable).")

    cfg = load_batch_fr_config(None)
    debug_cfg = cfg.get("batch_fr_debug", {}) or {}

    # Discover rule files under the configured rules_path
    rules_root = _get_rules_root(cfg)
    rule_files = _discover_rule_files(cfg)
    if not rule_files:
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip("Batch F&R: no rule files found under 'rules_path' in modules_config.json.", period=5000)
        except Exception:
            pass
        return

    # Ask the user which rule files to run and whether to run as dry run or live
    opts = _prompt_batch_fr_run_options(mw, rule_files, rules_root)
    if opts is None:
        # User cancelled
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip(f"Batch F&R cancelled • {now_stamp()}", period=3000)
        except Exception:
            pass
        return

    dry_run = bool(opts.get("dry_run", True))
    selected_files: List[Path] = opts.get("rules_files", []) or []
    if not selected_files:
        # Defensive: nothing selected, treat as cancelled.
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip(f"Batch F&R cancelled (no rule files selected) • {now_stamp()}", period=3000)
        except Exception:
            pass
        return

    report: Dict[str, Any] = {}
    try:
        # * For toolbar runs we don't need extra rulesets; the engine will
        #   load exactly the selected rule files.
        report = run_batch_find_replace(
            mw,
            rulesets=[],
            config_path=None,
            dry_run=dry_run,
            show_progress=True,
            notes_limit=None,
            rules_files=selected_files,
        )
    except Exception:
        # If something went wrong, we still want to show a basic tooltip below.
        report = {}

    # * Optional: notify user; avoid modal spam – a brief tooltip is nice
    try:
        from aqt.utils import tooltip  # type: ignore

        # ! Build a concise summary based on the engine report, if available.
        show_summary = bool(debug_cfg.get("show_summary_tooltip", True))

        mode_label = "dry run" if dry_run else "live"
        ts = now_stamp()

        if not show_summary or not isinstance(report, dict):
            # Fallback: simple completion message.
            tooltip(f"Batch F&R {mode_label} complete • {ts}", period=3000)
        else:
            rules = int(report.get("rules", 0) or 0)
            unique_notes = report.get("unique_notes_touched")
            notes_touched = report.get("notes_touched", 0) or 0
            note_hits = report.get("note_hits")
            guard_skips = int(report.get("guard_skips", 0) or 0)
            changed = int(report.get("notes_changed", 0) or 0)
            would_change = int(report.get("notes_would_change", 0) or 0)

            # Prefer unique note count when available.
            if isinstance(unique_notes, int):
                note_count = unique_notes
            else:
                note_count = notes_touched

            if dry_run:
                # Example: "dry run: 2 notes would change (4 hits) across 1 rule (guard skips: 1)"
                parts = [
                    "Batch F&R dry run:",
                    f"{note_count} note" + ("" if note_count == 1 else "s") + " would change",
                ]
                if isinstance(note_hits, int):
                    parts.append(f"({note_hits} hit" + ("" if note_hits == 1 else "s") + ")")
                parts.append(f"across {rules} rule" + ("" if rules == 1 else "s"))
                if guard_skips:
                    parts.append(f"(guard skips: {guard_skips})")
                msg = " ".join(parts) + f" • {ts}"
            else:
                # Example: "live: 2 notes changed across 1 rule (guard skips: 1)"
                parts = [
                    "Batch F&R live:",
                    f"{changed} note" + ("" if changed == 1 else "s") + " changed",
                    f"across {rules} rule" + ("" if rules == 1 else "s"),
                ]
                if guard_skips:
                    parts.append(f"(guard skips: {guard_skips})")
                msg = " ".join(parts) + f" • {ts}"

            tooltip(msg, period=5000)
    except Exception:
        pass

    try:
        # Optionally open debug Markdown / details TXT after the run.
        from aqt.qt import QDesktopServices, QUrl  # type: ignore

        report_paths = {}
        if isinstance(report, dict):
            report_paths = report.get("report_paths", {}) or {}

        open_md = bool(debug_cfg.get("open_debug_md_after_run", False))
        open_txt = bool(debug_cfg.get("open_details_txt_after_run", False))

        md_path = report_paths.get("debug_markdown")
        txt_path = report_paths.get("details_txt")

        if open_md and md_path:
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(md_path)))
            except Exception:
                pass

        if open_txt and txt_path:
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(txt_path)))
            except Exception:
                pass
    except Exception:
        # Best-effort only; never let this break the main run.
        pass