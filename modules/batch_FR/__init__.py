from __future__ import annotations
from pathlib import Path
from typing import List, Union, Optional, Dict, Any


try:  # pragma: no cover
    from aqt import mw  # type: ignore
except Exception:  # pragma: no cover
    mw = None  # Allow import outside Anki (e.g., tests)


try:
    from .utils.engine import run_batch_find_replace as _impl_run_batch_find_replace  # type: ignore
except Exception as _e:  # pragma: no cover
    _impl_run_batch_find_replace = None  # type: ignore
    _IMPORT_ERROR = _e
else:
    _IMPORT_ERROR = None


from .utils.top_helper import (
    now_stamp,
    load_batch_fr_config,
    _get_rules_root,
    _discover_rule_files,
)
from .gui.ui_dialog import prompt_batch_fr_run_options as _prompt_batch_fr_run_options

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
    extensive_debug: Optional[bool] = None,
    show_progress: bool = True,
    notes_limit: Optional[int] = None,
    rules_files: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """
    Public entry point used by host modules.
    ...
    """
    # If no config_path is provided, use the main modules_config.json
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "modules_config.json"

    cfg = load_batch_fr_config(config_path)

    if extensive_debug is not None:
        # existing code...
        cfg["extensive_debug"] = bool(extensive_debug)

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
    extensive_debug = bool(opts.get("extensive_debug", False))
    selected_files: List[Path] = opts.get("rules_files", []) or []
    # ? If user selected a remove-rule TXT (ends with remove_rule(s).txt), pass it as remove_rules.
    # ? This ensures the engine/remove_runner treats it as removals and can write a dedicated remove log.
    selected_remove_txt: List[Path] = []
    try:
        for p in selected_files:
            name = p.name.lower()
            if name.endswith("remove_rule.txt") or name.endswith("remove_rules.txt"):
                selected_remove_txt.append(p)
    except Exception:
        selected_remove_txt = []

    remove_rules_sel: Optional[Path] = selected_remove_txt[0] if selected_remove_txt else None

    # ! If multiple remove TXT files were selected, we will use the first one.
    if selected_remove_txt and len(selected_remove_txt) > 1:
        try:
            from aqt.utils import tooltip  # type: ignore
            tooltip(
                f"Batch F&R: multiple remove-rule TXT files selected; using: {remove_rules_sel.name}",
                period=6000,
            )
        except Exception:
            pass

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
            remove_rules=remove_rules_sel,
            config_path=None,
            dry_run=dry_run,
            extensive_debug=extensive_debug,
            show_progress=True,
            notes_limit=None,
            rules_files=selected_files,
        )
    except Exception:
        # ! Do not silently swallow errors; write a crash log so the UI never looks like a no-op.
        import traceback
        from pathlib import Path

        tb = traceback.format_exc()
        crash_path = None

        try:
            log_dir = Path(str(cfg.get("log_dir", "~/Desktop/anki_logs/Main_toolbar"))).expanduser()
            log_dir.mkdir(parents=True, exist_ok=True)
            crash_path = log_dir / f"Batch_FR_Crash__{now_stamp()}.txt"
            crash_path.write_text(
                "\n".join([
                    "Batch_FR toolbar run crashed.",
                    f"dry_run={dry_run}",
                    f"extensive_debug={extensive_debug}",
                    f"selected_files_count={len(selected_files)}",
                    "selected_files (first 20):",
                    *[f"  - {str(p)}" for p in (selected_files[:20] if isinstance(selected_files, list) else [])],
                    "\nTRACEBACK:\n" + tb,
                ]),
                encoding="utf-8",
            )
        except Exception:
            # Best-effort only.
            crash_path = None

        # Provide an error-shaped report so downstream UI can show something meaningful.
        report = {
            "error": "Batch F&R crashed in toolbar wrapper. See crash log for details.",
            "errors": [tb],
            "crash_log": str(crash_path) if crash_path else "",
            "rules": 0,
            "notes_would_change": 0,
            "notes_changed": 0,
        }

        try:
            from aqt.utils import tooltip  # type: ignore
            if crash_path:
                tooltip(f"Batch F&R failed • crash log written: {crash_path.name}", period=8000)
            else:
                tooltip("Batch F&R failed • crash log could not be written (see console)", period=8000)
        except Exception:
            pass

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
            # ! If the run returned an error, show it instead of a misleading 0/0 summary.
            err_msg = ""
            try:
                err_msg = str(report.get("error") or "").strip()
                if not err_msg:
                    errs = report.get("errors") or []
                    if isinstance(errs, list) and errs:
                        err_msg = str(errs[0])[:200].strip()
            except Exception:
                err_msg = ""

            if err_msg:
                tooltip(f"Batch F&R failed: {err_msg} • {ts}", period=8000)
                return

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
        remove_md_path = report_paths.get("remove_markdown")

        if open_md and md_path:
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(md_path)))
            except Exception:
                pass

        if open_md and remove_md_path:
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(remove_md_path)))
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

# 01-46_12-06 – expose batch_FR dialogs for tools like AnkiWebView Inspector
try:
    import types  # type: ignore[import-not-found]
    import aqt  # type: ignore[import-not-found]

    from .gui import ui_dialog as _batch_fr_ui_dialog

    ns = getattr(aqt, "batch_FR", None)
    if ns is None:
        ns = types.SimpleNamespace()
        aqt.batch_FR = ns

    # * Attach the gui.ui_dialog module so tools can reach:
    #   aqt.batch_FR.ui_dialog.BatchFRHtmlDialog, etc.
    ns.ui_dialog = _batch_fr_ui_dialog
except Exception:
    # Best-effort only; never break normal imports if aqt/types are missing.
    pass