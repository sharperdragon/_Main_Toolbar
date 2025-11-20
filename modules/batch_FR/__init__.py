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
    )

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
    rules_path_str = cfg.get("rules_path") or ""
    debug_cfg = cfg.get("batch_fr_debug", {}) or {}

    # Prepare rulesets argument; engine decides how to handle dir vs file
    if rules_path_str:
        rp = Path(rules_path_str)
        rules_arg = [rp]
    else:
        # No configured rules path – inform the user and abort
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip("Batch F&R: no 'rules_path' configured in modules_config.json.", period=5000)
        except Exception:
            pass
        return

    # Ask the user whether to run as a dry run or apply changes
    mode = _prompt_batch_fr_mode(mw)
    if mode is None:
        # User cancelled
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip(f"Batch F&R cancelled • {now_stamp()}", period=3000)
        except Exception:
            pass
        return

    dry_run = bool(mode)

    report: Dict[str, Any] = {}
    try:
        report = run_batch_find_replace(
            mw,
            rulesets=rules_arg,
            config_path=None,
            dry_run=dry_run,
            show_progress=True,
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