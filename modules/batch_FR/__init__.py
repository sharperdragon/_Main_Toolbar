from __future__ import annotations

# * Standard library
from pathlib import Path
from typing import List, Union, Optional, Dict, Any

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

# * Shared utilities moved into top_utils.py
from .top_utils import (
    TS_FORMAT,
    DESKTOP,
    now_stamp,
    load_batch_fr_config,
    _get_rules_root,
    _discover_rule_files,
    _prompt_batch_fr_run_options,
)

__all__ = [
    "TS_FORMAT",
    "DESKTOP",
    "now_stamp",
    "load_batch_fr_config",
    "run_batch_find_replace",
    "run_from_toolbar",
]

# -----------------------------
# Public API wrapper (engine)
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
    - config_path: path to modules_config.json; if None, default from top_utils is used
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


# ------------------------------
# Toolbar entrypoint
# ------------------------------
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