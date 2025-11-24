from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from time import strftime
from typing import List, Optional, Sequence, Tuple

import re

from aqt import mw
from aqt.qt import QMessageBox
from anki.collection import Collection
from anki.errors import SearchError

# * Paths & constants ---------------------------------------------------------

# Folder that holds *_tagging.json files, relative to this module.
BASE_DIR = Path(__file__).resolve().parent
TAG_ADDITIONS_DIR = BASE_DIR / "tag_additions"
TAG_ADDITIONS_GLOB = "*_tagging.json"

# Module/config path helpers
MODULES_DIR = BASE_DIR.parent
MODULES_CONFIG_PATH = MODULES_DIR / "modules_config.json"

def _load_modules_config() -> dict:
    """Load the shared modules_config.json, falling back to simple defaults if missing."""
    try:
        import json

        with MODULES_CONFIG_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # Minimal fallback if config is missing or invalid
        return {
            "global_config": {
                "log_dir": "~/Desktop/anki logs/Main_toolbar",
                "ts_format": "%H-%M_%m-%d",
            }
        }


def _get_global_log_dir() -> Path:
    """Resolve the global log directory from modules_config.json."""
    cfg = _load_modules_config()
    log_dir_str = (
        cfg.get("global_config", {}).get("log_dir")
        or "~/Desktop/anki logs/Main_toolbar"
    )
    return Path(log_dir_str).expanduser()


def _get_ts_format() -> str:
    """Get the timestamp format from modules_config.json."""
    cfg = _load_modules_config()
    return cfg.get("global_config", {}).get("ts_format", "%H-%M_%m-%d")


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
    notes_matched: int = 0
    notes_changed: int = 0
    tags_added: int = 0


@dataclass
class RunStats:
    dry_run: bool
    rules: List[RuleStats]

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def total_notes_matched(self) -> int:
        return sum(r.notes_matched for r in self.rules)

    @property
    def total_notes_changed(self) -> int:
        return sum(r.notes_changed for r in self.rules)

    @property
    def total_tags_added(self) -> int:
        return sum(r.tags_added for r in self.rules)


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
                marker = log_dir / "tag_additions_load_errors.txt"
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


def _log_search_error(rule: TagAddRule, query: str, err: Exception) -> None:
    """
    Log a search error for a specific tagging rule to a dedicated log file,
    instead of crashing the entire Tag Updates run.
    """
    try:
        log_dir = _get_global_log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "tag_additions_search_errors.txt"
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
    col: Collection, rules: Sequence[TagAddRule], dry_run: bool
) -> RunStats:
    """Core worker: runs inside the GUI thread on the open collection."""
    stats: List[RuleStats] = []

    for rule in rules:
        rule_stat = RuleStats(rule=rule)

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
            query = raw_query
        else:
            # Escape for use inside a regex, then anchor as a full tag path.
            escaped = re.escape(raw_query)
            query = f"tag:re:^{escaped}(::|$)"

        try:
            note_ids = col.find_notes(query)
        except SearchError as e:
            # Log and skip this rule instead of crashing the whole Tag Updates run
            _log_search_error(rule, query, e)
            stats.append(rule_stat)
            continue

        rule_stat.notes_matched = len(note_ids)

        for nid in note_ids:
            note = col.get_note(nid)
            # Compute which tags are actually missing
            missing = [t for t in rule.add_tags if t not in note.tags]
            if not missing:
                continue

            rule_stat.notes_changed += 1
            rule_stat.tags_added += len(missing)

            if dry_run:
                continue

            for t in missing:
                note.add_tag(t)
            col.update_note(note)

        stats.append(rule_stat)

    return RunStats(dry_run=dry_run, rules=stats)


# * Logging -------------------------------------------------------------------


def _write_log(stats: RunStats) -> Optional[Path]:
    """Write a Markdown summary of what happened to the Desktop."""
    if not stats.rules:
        return None

    ts = strftime(_get_ts_format())
    log_dir = _get_global_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"tag_additions_{ts}.md"

    lines: List[str] = []
    lines.append(f"# Tag additions run — {ts}")
    lines.append("")
    lines.append(f"- dry_run: **{stats.dry_run}**")
    lines.append(f"- rules: **{stats.total_rules}**")
    lines.append(f"- notes matched: **{stats.total_notes_matched}**")
    lines.append(f"- notes changed: **{stats.total_notes_changed}**")
    lines.append(f"- tags added: **{stats.total_tags_added}**")
    lines.append("")
    lines.append(
        "| # | rule | query | add_tags | notes_matched | notes_changed | tags_added |"
    )
    lines.append(
        "|---|------|-------|----------|---------------|---------------|-----------|"
    )

    for idx, r in enumerate(stats.rules, start=1):
        add_tags = ", ".join(r.rule.add_tags)
        # escape pipe characters in query or tags for Markdown table
        q = r.rule.query.replace("|", "\\|")
        at = add_tags.replace("|", "\\|")
        lines.append(
            f"| {idx} | {r.rule.name} | `{q}` | `{at}` | "
            f"{r.notes_matched} | {r.notes_changed} | {r.tags_added} |"
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
    stats = _apply_rules_to_collection(col, rules, dry_run=dry)
    log_path = _write_log(stats)

    # * Short summary shown after each run
    msg_lines = [
        f"Tag additions {'(dry run)' if dry else ''} complete.",
        "",
        f"Rules: {stats.total_rules}",
        f"Notes matched: {stats.total_notes_matched}",
        f"Notes changed: {stats.total_notes_changed}",
        f"Tags added: {stats.total_tags_added}",
    ]
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

    _run_tag_additions_core(parent, rules, dry)