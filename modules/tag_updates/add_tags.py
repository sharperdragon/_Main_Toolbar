from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from time import strftime
from typing import Dict, List, Literal, Optional, Sequence, Tuple

import re

from aqt import mw
from aqt.qt import QMessageBox
try:  # pragma: no cover - optional in unit-test stubs
    from aqt.qt import QApplication, QProgressDialog, Qt
except Exception:  # pragma: no cover - fallback when Qt symbols are unavailable
    QApplication = None
    QProgressDialog = None
    Qt = None
from anki.collection import Collection

try:
    from .tag_rename_utils import escape_anki_tag_re
except Exception:  # pragma: no cover - standalone import fallback
    def escape_anki_tag_re(pattern: str) -> str:
        out: list[str] = []
        for i, ch in enumerate(pattern or ""):
            if ch != ":":
                out.append(ch)
                continue
            if i > 0 and pattern[i - 1] in {"\\", "?"}:
                out.append(ch)
                continue
            out.append(r"\:")
        return "".join(out)

try:
    from ..module_config import (
        DEFAULT_LOG_DIR,
        DEFAULT_TS_FORMAT,
        emit_config_warnings,
        get_global_config,
        load_modules_config,
        resolve_path,
        validate_modules_config,
    )
except Exception:  # pragma: no cover
    import sys

    _MODULES_DIR = Path(__file__).resolve().parents[1]
    if str(_MODULES_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULES_DIR))
    from module_config import (  # type: ignore
        DEFAULT_LOG_DIR,
        DEFAULT_TS_FORMAT,
        emit_config_warnings,
        get_global_config,
        load_modules_config,
        resolve_path,
        validate_modules_config,
    )

try:
    from ..filter_scope_prompt import prompt_scope_filter
except Exception:  # pragma: no cover
    import sys

    _MODULES_DIR = Path(__file__).resolve().parents[1]
    if str(_MODULES_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULES_DIR))
    from filter_scope_prompt import prompt_scope_filter  # type: ignore

# * Paths & constants ---------------------------------------------------------

# Folder that holds *_tagging.json files, relative to this module.
BASE_DIR = Path(__file__).resolve().parent
TAG_ADDITIONS_DIR = BASE_DIR / "tag_additions"
TAG_ADDITIONS_GLOB = "*_tagging.json"
DEFAULT_LOAD_ERRORS_FILENAME = "tag_additions_load_errors.txt"
DEFAULT_SEARCH_ERRORS_FILENAME = "tag_additions_search_errors.txt"
# How often to refresh the progress UI while processing notes.
PROGRESS_UPDATE_EVERY_NOTES = 100


def _load_modules_cfg_with_validation() -> Dict[str, object]:
    cfg: Dict[str, object] = load_modules_config()
    emit_config_warnings(validate_modules_config(cfg), cfg)
    return cfg


def _get_global_log_dir() -> Path:
    """Resolve global log directory via shared module config helpers."""
    cfg = _load_modules_cfg_with_validation()
    global_cfg = get_global_config(cfg)
    return resolve_path(
        global_cfg.get("log_dir"),
        DEFAULT_LOG_DIR,
    )


def _get_ts_format() -> str:
    """Resolve global timestamp format via shared module config helpers."""
    cfg = _load_modules_cfg_with_validation()
    global_cfg = get_global_config(cfg)
    ts_value = global_cfg.get("ts_format", DEFAULT_TS_FORMAT)
    if isinstance(ts_value, str) and ts_value.strip():
        return ts_value.strip()
    return DEFAULT_TS_FORMAT


@dataclass
class TagAddRule:
    """Single rule: run a Browser query, add one or more tags to matching notes."""
    name: str
    query: str
    add_tags: List[str]
    source_file: Path


@dataclass
class RuleStats:
    rule: TagAddRule
    notes_matched: Optional[int] = None
    notes_changed: int = 0
    tags_added: int = 0
    raw_regex: str = ""
    anki_query: str = ""
    search_status: Literal["ok", "error", "not_tested"] = "not_tested"
    error_message: Optional[str] = None


@dataclass
class RunStats:
    dry_run: bool
    rules: List[RuleStats]

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def total_notes_matched(self) -> int:
        return sum(r.notes_matched or 0 for r in self.rules)

    @property
    def total_notes_changed(self) -> int:
        return sum(r.notes_changed for r in self.rules)

    @property
    def total_tags_added(self) -> int:
        return sum(r.tags_added for r in self.rules)

    @property
    def total_search_errors(self) -> int:
        return sum(1 for r in self.rules if r.search_status == "error")


# * JSON loading --------------------------------------------------------------


def _normalize_tags_field(raw: object) -> List[str]:
    """Accept a string or list for tags; return a clean list."""
    tags: List[str] = []
    if isinstance(raw, str):
        # split on whitespace; tags aren’t expected to contain spaces
        tags = [t.strip() for t in raw.split() if t.strip()]
    elif isinstance(raw, (list, tuple)):
        for item in raw:
            if isinstance(item, str):
                item = item.strip()
                if item:
                    tags.append(item)
    # dedupe while preserving order
    seen = set()
    uniq: List[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def _parse_rules_from_payload(data: object, src: Path) -> List[TagAddRule]:
    """
    Accepts either:
      - a list of rule dicts
      - a dict with a top-level "rules" list

    Rule format (any of these tag keys accepted):
      {
        "name": "Step 2 core tag",
        "query": "tag:#AK_Step2_v12",
        "add_tags": ["#Zank::Step2_v12"]
      }

    Skips any objects that don't look like tagging rules
    (e.g., {"file-defaults": {...}} from regex-style files).
    """
    rules_raw: Sequence[object] = ()

    if isinstance(data, list):
        rules_raw = data
    elif isinstance(data, dict):
        maybe_rules = data.get("rules")
        if isinstance(maybe_rules, list):
            rules_raw = maybe_rules

    out: List[TagAddRule] = []
    for idx, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            continue
        if "file-defaults" in item:
            # from regex-style rule files; ignore here
            continue

        query = (
            item.get("query")
            or item.get("browser_query")
            or item.get("search")
        )
        if not isinstance(query, str) or not query.strip():
            continue

        tags_raw = (
            item.get("add_tags")
            or item.get("tags_to_add")
            or item.get("add")
            or item.get("tags")
        )
        tags = _normalize_tags_field(tags_raw)
        if not tags:
            continue

        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            name = f"{src.name} #{idx}"

        out.append(
            TagAddRule(
                name=name.strip(),
                query=query.strip(),
                add_tags=tags,
                source_file=src,
            )
        )
    return out


def load_tag_add_rules() -> List[TagAddRule]:
    """Load all *_tagging.json files from TAG_ADDITIONS_DIR."""
    rules: List[TagAddRule] = []

    if not TAG_ADDITIONS_DIR.exists():
        return rules

    import json

    for path in sorted(TAG_ADDITIONS_DIR.glob(TAG_ADDITIONS_GLOB)):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            # ! Log file-level issues to a log file in the configured log dir
            try:
                log_dir = _get_global_log_dir()
                log_dir.mkdir(parents=True, exist_ok=True)
                marker = log_dir / DEFAULT_LOAD_ERRORS_FILENAME
                with marker.open("a", encoding="utf-8") as fh:
                    fh.write(
                        f"[{strftime(_get_ts_format())}] Failed to load {path} -> {e}\n"
                    )
            except Exception:
                pass
            continue

        rules.extend(_parse_rules_from_payload(data, path))

    return rules


# * Public helper for Tag Updates UI ------------------------------------------



def _sanitize_search_query(q: str) -> str:
    """
    Best-effort cleanup for Browser search queries used in tag-addition rules.

    Currently fixes:
      - A single '\\^' (invalid escape for Anki's search language), which causes
        errors like "the escape sequence `\\^` is not defined". We replace that
        with '^' while leaving '\\\\^' (literal backslash + caret) intact.
    """
    # Replace single '\^' (not preceded by another backslash) with '^'
    return re.sub(r"(?<!\\)\\\^", "^", q)


def _build_tag_re_query_from_pattern(pattern: str) -> str:
    return f"tag:re:{escape_anki_tag_re(pattern)}"


def _build_tag_path_query(tag_path: str) -> tuple[str, str]:
    raw_regex = f"^{re.escape(tag_path)}(::|$)"
    return raw_regex, _build_tag_re_query_from_pattern(raw_regex)


def _ui_process_events() -> None:
    """Keep the UI responsive during long in-thread runs."""
    if QApplication is None:
        return
    try:
        QApplication.processEvents()
    except Exception:
        pass


def _set_progress_state(
    progress_dialog: object | None,
    *,
    label: str | None = None,
    value: int | None = None,
    maximum: int | None = None,
) -> None:
    """Best-effort update for the native progress dialog."""
    if progress_dialog is None:
        return

    try:
        if maximum is not None:
            progress_dialog.setMaximum(max(1, int(maximum)))
        if value is not None:
            v = max(0, int(value))
            try:
                cur_max = int(progress_dialog.maximum())
                v = min(v, max(1, cur_max))
            except Exception:
                pass
            progress_dialog.setValue(v)
        if label is not None:
            progress_dialog.setLabelText(label)
    except Exception:
        return

    _ui_process_events()


def _log_search_error(rule: TagAddRule, query: str, err: Exception) -> None:
    """
    Log a search error for a specific tagging rule to a dedicated log file,
    instead of crashing the entire Tag Updates run.
    """
    try:
        log_dir = _get_global_log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / DEFAULT_SEARCH_ERRORS_FILENAME
        ts = strftime(_get_ts_format())
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] SearchError for rule '{rule.name}' from {rule.source_file}\n")
            fh.write(f"  Query: {query}\n")
            fh.write(f"  Error: {err}\n\n")
    except Exception:
        # Logging failures should never crash the add-on
        pass


def load_tag_add_rules_with_meta() -> Tuple[List[TagAddRule], List[str]]:
    """
    Load all tagging rules plus human-readable labels for a rule picker UI.

    Returns:
        (rules, labels)
          - rules:  full TagAddRule objects
          - labels: strings like "name: query → +tag1, +tag2"
    """
    rules = load_tag_add_rules()
    labels: List[str] = []

    for r in rules:
        tag_str = ", ".join(r.add_tags) if r.add_tags else ""
        # ? Keep labels compact but informative for the selection dialog
        label = f"{r.name}: {r.query} → +{tag_str}" if tag_str else f"{r.name}: {r.query}"
        labels.append(label)

    return rules, labels


# * Core application logic ----------------------------------------------------
def _apply_rules_to_collection(
    col: Collection,
    rules: Sequence[TagAddRule],
    dry_run: bool,
    progress_dialog: object | None = None,
    scope_query: str = "",
) -> RunStats:
    """Core worker: runs inside the GUI thread on the open collection."""
    stats: List[RuleStats] = []
    total_rules = len(rules)
    total_notes_seen = 0
    notes_processed = 0

    for rule_idx, rule in enumerate(rules, start=1):
        rule_stat = RuleStats(rule=rule)
        _set_progress_state(
            progress_dialog,
            label=f"Tag additions: rule {rule_idx}/{total_rules}\n{rule.name}\nSearching notes…",
            value=notes_processed,
            maximum=max(1, total_notes_seen or total_rules),
        )

        # Sanitize the query to avoid invalid escape sequences (like '\^')
        raw_query = _sanitize_search_query(rule.query).strip()

        # If the query doesn't start with a known search prefix, treat it as a tag path
        # and convert it into a tag:re search that matches the full tag (and its children).
        # This allows simple paths like "#AK_Other::Card_Features::^One_By_One" to work
        # without requiring the user to write full Anki search syntax.
        if not raw_query:
            stats.append(rule_stat)
            continue

        known_prefixes = (
            "tag:",
            "deck:",
            "note:",
            "card:",
            "nid:",
            "mid:",
            "prop:",
            "rated:",
            "is:",
            "added:",
            "edited:",
            "dupe:",
            "flag:",
        )

        if raw_query.startswith(known_prefixes):
            if raw_query.startswith("tag:re:"):
                rule_stat.raw_regex = raw_query[len("tag:re:") :]
                query = _build_tag_re_query_from_pattern(rule_stat.raw_regex)
            else:
                query = raw_query
        else:
            # Escape for use inside a regex, then anchor as a full tag path.
            rule_stat.raw_regex, query = _build_tag_path_query(raw_query)

        if scope_query:
            query = f"{query} {scope_query}".strip()
        rule_stat.anki_query = query

        try:
            note_ids = col.find_notes(query)
        except Exception as e:
            # Log and skip this rule instead of crashing the whole Tag Updates run
            _log_search_error(rule, query, e)
            rule_stat.search_status = "error"
            rule_stat.error_message = str(e)
            rule_stat.notes_matched = None
            stats.append(rule_stat)
            continue

        rule_stat.search_status = "ok"
        rule_stat.notes_matched = len(note_ids)
        total_notes_seen += len(note_ids)
        _set_progress_state(
            progress_dialog,
            label=(
                f"Tag additions: rule {rule_idx}/{total_rules}\n{rule.name}\n"
                f"Processing notes: 0/{len(note_ids)}"
            ),
            value=notes_processed,
            maximum=max(1, total_notes_seen),
        )

        for note_pos, nid in enumerate(note_ids, start=1):
            note = col.get_note(nid)
            # Compute which tags are actually missing
            missing = [t for t in rule.add_tags if t not in note.tags]
            if missing:
                rule_stat.notes_changed += 1
                rule_stat.tags_added += len(missing)

                if not dry_run:
                    for t in missing:
                        note.add_tag(t)
                    col.update_note(note)

            notes_processed += 1
            if (
                note_pos == len(note_ids)
                or note_pos == 1
                or note_pos % PROGRESS_UPDATE_EVERY_NOTES == 0
            ):
                _set_progress_state(
                    progress_dialog,
                    label=(
                        f"Tag additions: rule {rule_idx}/{total_rules}\n{rule.name}\n"
                        f"Processing notes: {note_pos}/{len(note_ids)}"
                    ),
                    value=notes_processed,
                    maximum=max(1, total_notes_seen),
                )

        # Keep progress moving even when dry-run or no note changes occurred.
        if not note_ids:
            _set_progress_state(
                progress_dialog,
                label=f"Tag additions: rule {rule_idx}/{total_rules}\n{rule.name}\nNo matching notes.",
                value=notes_processed,
                maximum=max(1, total_notes_seen or total_rules),
            )

        stats.append(rule_stat)

    return RunStats(dry_run=dry_run, rules=stats)


# * Logging -------------------------------------------------------------------


def _write_log(stats: RunStats, scope_query: str = "") -> Optional[Path]:
    """Write a Markdown summary of what happened to the Desktop."""
    if not stats.rules:
        return None

    ts = strftime(_get_ts_format())
    log_dir = _get_global_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"tag_additions_{ts}.md"

    def _md_cell(value: object) -> str:
        return str(value if value is not None else "").replace("\n", "<br>").replace("|", "\\|")

    lines: List[str] = []
    lines.append(f"# Tag additions run — {ts}")
    lines.append("")
    lines.append(f"- dry_run: **{stats.dry_run}**")
    lines.append(f"- rules: **{stats.total_rules}**")
    lines.append(f"- notes matched: **{stats.total_notes_matched}**")
    lines.append(f"- search errors: **{stats.total_search_errors}**")
    lines.append(f"- notes changed: **{stats.total_notes_changed}**")
    lines.append(f"- tags added: **{stats.total_tags_added}**")
    if scope_query:
        lines.append(f"- scope_query: `{scope_query}`")
    lines.append("")
    lines.append(
        "| # | rule | raw_query | add_tags | raw_regex | anki_query | search_status | search_error | matched_notes | notes_changed | tags_added | error_message |"
    )
    lines.append(
        "|---|------|-----------|----------|-----------|------------|---------------|--------------|---------------|---------------|-----------|---------------|"
    )

    for idx, r in enumerate(stats.rules, start=1):
        add_tags = ", ".join(r.rule.add_tags)
        matched = "not tested" if r.search_status == "error" else str(r.notes_matched or 0)
        search_error = "true" if r.search_status == "error" else "false"
        lines.append(
            f"| {idx} | {_md_cell(r.rule.name)} | `{_md_cell(r.rule.query)}` | "
            f"`{_md_cell(add_tags)}` | `{_md_cell(r.raw_regex)}` | "
            f"`{_md_cell(r.anki_query)}` | {r.search_status} | {search_error} | "
            f"{matched} | {r.notes_changed} | {r.tags_added} | {_md_cell(r.error_message or '')} |"
        )

    text = "\n".join(lines)

    try:
        log_path.write_text(text, encoding="utf-8")
    except Exception:
        return None

    return log_path


# * Core runner used by both standalone and Tag Updates -----------------------


def _run_tag_additions_core(
    parent,
    rules: Sequence[TagAddRule],
    dry: bool,
    show_summary: bool = True,
    scope_query: str = "",
) -> Optional[RunStats]:
    """
    Core UI+logic runner.

    Used by:
      * run_tag_additions(..)  -> standalone toolbar action
      * run_tag_updates(..)    -> combined rule picker (renames + additions)

    Args:
        parent: Parent QWidget for dialogs.
        rules: TagAddRule objects to apply.
        dry: If True, perform a dry run (no changes).
        show_summary: If True, show the per-run “Tag additions” popup.
                      Callers like Tag Updates that want to provide their own
                      combined summary can pass False to suppress this window.
        scope_query: Optional Anki Browser query appended to each rule query
                     (for example a tag or note-type filter).

    Returns:
        A RunStats object summarizing what happened, or None if the run was
        aborted (no collection or no rules).
    """
    if parent is None:
        parent = mw

    if mw is None or mw.col is None:
        QMessageBox.warning(parent, "Tag additions", "Collection is not loaded.")
        return None

    if not rules:
        QMessageBox.information(
            parent,
            "Tag additions",
            (
                "No tagging rules selected.\n\n"
                f"Expected JSON files matching '{TAG_ADDITIONS_GLOB}' in:\n"
                f"{TAG_ADDITIONS_DIR}"
            ),
        )
        return None

    col: Collection = mw.col
    progress_dialog = None
    if QProgressDialog is not None:
        try:
            progress_dialog = QProgressDialog("Preparing tag additions…", "", 0, 1, parent)
            progress_dialog.setWindowTitle("Tag additions")
            progress_dialog.setAutoClose(False)
            progress_dialog.setAutoReset(False)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setCancelButton(None)
            if Qt is not None:
                progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
            progress_dialog.show()
            _ui_process_events()
        except Exception:
            progress_dialog = None

    try:
        stats = _apply_rules_to_collection(
            col,
            rules,
            dry_run=dry,
            progress_dialog=progress_dialog,
            scope_query=str(scope_query or "").strip(),
        )
    finally:
        if progress_dialog is not None:
            try:
                final_max = max(1, int(progress_dialog.maximum()))
            except Exception:
                final_max = 1
            _set_progress_state(
                progress_dialog,
                label="Tag additions: finalizing…",
                value=final_max,
                maximum=final_max,
            )
            try:
                progress_dialog.close()
            except Exception:
                pass

    scope_query_norm = str(scope_query or "").strip()
    log_path = _write_log(stats, scope_query=scope_query_norm)

    # * Short summary shown after each run
    msg_lines = [
        f"Tag additions {'(dry run)' if dry else ''} complete.",
        "",
        f"Rules: {stats.total_rules}",
        f"Notes matched: {stats.total_notes_matched}",
        f"Search errors: {stats.total_search_errors}",
        f"Notes changed: {stats.total_notes_changed}",
        f"Tags added: {stats.total_tags_added}",
    ]
    if scope_query_norm:
        msg_lines.insert(2, f"Filter: {scope_query_norm}")
    if log_path is not None:
        msg_lines.append("")
        msg_lines.append(f"Log written to:\n{log_path}")

    if show_summary:
        QMessageBox.information(parent, "Tag additions", "\n".join(msg_lines))

    return stats


# * Public entrypoint ---------------------------------------------------------


def _ask_dry_run(parent) -> Optional[bool]:
    """
    Prompt the user whether to run as a dry run.
    Returns:
      True  -> dry run
      False -> apply changes
      None  -> cancelled
    """
    box = QMessageBox(parent)
    box.setWindowTitle("Tag additions — dry run?")
    box.setText(
        "Run tag additions as a dry run first?\n\n"
        "Yes = dry run (no changes, just log what would change)\n"
        "No  = apply changes to notes\n"
        "Cancel = abort."
    )
    yes = box.addButton("Yes — dry run", QMessageBox.YesRole)
    no = box.addButton("No — apply changes", QMessageBox.NoRole)
    cancel = box.addButton("Cancel", QMessageBox.RejectRole)
    box.setDefaultButton(yes)
    box.exec()

    clicked = box.clickedButton()
    if clicked is cancel:
        return None
    if clicked is no:
        return False
    return True


def run_tag_additions(parent=None) -> None:
    """
    UI entrypoint for the 'tag additions' action.
    - When called directly (toolbar action), it:
        1) loads all rules
        2) prompts for dry run vs apply
        3) runs via _run_tag_additions_core

    - When used indirectly via Tag Updates, the caller should:
        * construct a subset of TagAddRule objects
        * call _run_tag_additions_core(parent, rules, dry)
    """
    if parent is None:
        parent = mw

    # Load all rules from disk
    rules = load_tag_add_rules()
    if not rules:
        QMessageBox.information(
            parent,
            "Tag additions",
            (
                "No tagging rules found.\n\n"
                f"Expected JSON files matching '{TAG_ADDITIONS_GLOB}' in:\n"
                f"{TAG_ADDITIONS_DIR}"
            ),
        )
        return

    # Ask the user whether this run should be dry or live
    dry = _ask_dry_run(parent)
    if dry is None:
        # cancelled
        return

    scope = prompt_scope_filter(parent)
    if scope is None:
        return

    _run_tag_additions_core(
        parent,
        rules,
        dry,
        scope_query=str(scope.query or "").strip(),
    )
