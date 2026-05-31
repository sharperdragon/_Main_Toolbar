# AC_IMG_DUPES.py — Native API version for internal Anki execution
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:
    from aqt import mw
    from aqt.operations import QueryOp
    from aqt.qt import QInputDialog
    from aqt.utils import showInfo, showWarning
    from anki.notes import Note
except Exception:  # pragma: no cover - allows import in tests/outside Anki
    mw = None  # type: ignore
    QueryOp = None  # type: ignore
    QInputDialog = None  # type: ignore
    Note = object  # type: ignore

    def showInfo(msg: str) -> None:  # type: ignore
        print(msg)

    def showWarning(msg: str) -> None:  # type: ignore
        print(msg)

try:
    from ..module_config import (
        emit_config_warnings,
        get_section,
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
        emit_config_warnings,
        get_section,
        load_modules_config,
        resolve_path,
        validate_modules_config,
    )


# ==========================
# Changeable defaults
# ==========================

DEFAULT_TARGET_FIELDS: Tuple[str, ...] = (
    "Text",
    "Extra",
    "Extra2",
    "Extra3",
    "Extra4",
    "Extra5",
    "Button",
    "Display",
)
DEFAULT_BACKUP_THRESHOLD = 45
DEFAULT_BACKUP_PATH = Path("~/ANki/Missing Media/backups/dupe_img_nids.txt")
RUN_MODE_APPLY = "Apply changes"
RUN_MODE_PREVIEW = "Preview only (dry run)"
RUN_MODE_OPTIONS = (RUN_MODE_APPLY, RUN_MODE_PREVIEW)
IMG_SRC_RE = re.compile(r'<img [^>]*src="([^"]+)"[^>]*>', flags=re.IGNORECASE)
IMG_SPLIT_RE = re.compile(r'(<img [^>]*src="[^"]+"[^>]*>)')


def _coerce_positive_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        out = int(value)
    except Exception:
        out = default
    return out if out > 0 else default


def _normalize_field_list(value: object, fallback: Sequence[str]) -> List[str]:
    out: List[str] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if not isinstance(item, str):
                continue
            field = item.strip()
            if field:
                out.append(field)
    return out if out else list(fallback)


def _build_runtime_settings(cfg: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    raw_cfg = cfg if isinstance(cfg, dict) else load_modules_config()
    emit_config_warnings(validate_modules_config(raw_cfg), raw_cfg)
    section = get_section("img_dupes_config", raw_cfg)

    target_fields = _normalize_field_list(section.get("fields"), DEFAULT_TARGET_FIELDS)
    backup_threshold = _coerce_positive_int(
        section.get("backup_threshold"), DEFAULT_BACKUP_THRESHOLD
    )
    backup_path = resolve_path(section.get("backup_path"), DEFAULT_BACKUP_PATH)

    return {
        "fields": target_fields,
        "backup_threshold": backup_threshold,
        "backup_path": backup_path,
    }


def normalize_tag_input(raw: str) -> str:
    tag = raw.strip().replace("\\_", "_")
    if not tag.startswith("tag:"):
        tag = f"tag:{tag}"
    return tag


def _dedupe_img_tags_in_html(original: str) -> Tuple[str, bool]:
    imgs = IMG_SRC_RE.findall(original)
    if not imgs or len(set(imgs)) == len(imgs):
        return original, False

    seen = set()
    changed = False
    updated_html = ""
    split = IMG_SPLIT_RE.split(original)

    for chunk in split:
        match = IMG_SRC_RE.search(chunk)
        if not match:
            updated_html += chunk
            continue

        src = match.group(1)
        if src in seen:
            changed = True
            continue

        seen.add(src)
        updated_html += chunk

    return updated_html, changed


def _write_backup_if_needed(
    removed_nids: Sequence[int],
    threshold: int,
    backup_path: Path,
) -> bool:
    if len(removed_nids) <= threshold:
        return False

    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_text(
        "\n".join(str(nid) for nid in removed_nids),
        encoding="utf-8",
    )
    return True


def _prompt_dry_run_mode(parent) -> Optional[bool]:
    if QInputDialog is None:
        return False
    selected_mode, ok = QInputDialog.getItem(
        parent,
        "IMG Dupes Mode",
        "Select run mode:",
        list(RUN_MODE_OPTIONS),
        0,
        False,
    )
    if not ok:
        return None
    return str(selected_mode) == RUN_MODE_PREVIEW


def _process_notes_for_dupes(
    col,
    note_ids: Sequence[int],
    target_fields: Sequence[str],
    dry_run: bool,
) -> List[int]:
    changed_nids: List[int] = []

    for nid in note_ids:
        note: Note = col.get_note(nid)
        changed = False

        for field in target_fields:
            if field not in note:
                continue

            original = note[field]
            updated_html, field_changed = _dedupe_img_tags_in_html(original)
            if not field_changed:
                continue

            changed = True
            if dry_run:
                print(f"🔎 Would clean dupes in field '{field}' of note {nid}")
                continue

            print(f"🧹 Removed dupes in field '{field}' of note {nid}")
            note[field] = updated_html

        if not changed:
            continue

        if dry_run:
            changed_nids.append(nid)
            continue

        try:
            note.flush()
            changed_nids.append(nid)
        except Exception as e:
            msg = f"❌ Error flushing note {nid}: {e}"
            print(msg)
            showWarning(msg)

    return changed_nids


def _report_completion(
    changed_nids: Sequence[int],
    dry_run: bool,
    backup_threshold: int,
    backup_path: Path,
) -> None:
    if dry_run:
        msg = (
            f"🔎 Preview complete. {len(changed_nids)} notes would be cleaned. "
            "No changes were applied."
        )
        print(msg)
        showInfo(msg)
        return

    msg = f"✅ Done. Cleaned {len(changed_nids)} notes."
    print(msg)
    showInfo(msg)

    try:
        wrote_backup = _write_backup_if_needed(
            changed_nids, backup_threshold, backup_path
        )
    except Exception as e:
        showWarning(f"❌ Failed to write IMG dupes backup: {e}")
        return

    if wrote_backup:
        print(
            f"📝 Wrote backup of {len(changed_nids)} NIDs to: {backup_path}"
        )


def run_img_dupes_script() -> None:
    if mw is None or getattr(mw, "col", None) is None or QInputDialog is None or QueryOp is None:
        raise RuntimeError("IMG dupes tool must run inside Anki (UI components unavailable).")

    settings = _build_runtime_settings()
    target_fields = list(settings["fields"])
    backup_threshold = int(settings["backup_threshold"])
    backup_path = Path(str(settings["backup_path"]))

    print("🚀 Starting AC_IMG_DUPES inside Anki...")

    dlg = QInputDialog(mw)
    dlg.setWindowTitle("Enter Tag")
    dlg.setLabelText("Enter a search query like in the Anki browser:")
    dlg.setModal(False)
    from PyQt6.QtCore import Qt

    dlg.setWindowModality(Qt.WindowModality.NonModal)
    dlg.setFixedSize(400, 100)
    if dlg.exec() != dlg.Accepted:
        return

    query = normalize_tag_input(dlg.textValue())
    if not query.strip():
        return

    note_ids = mw.col.find_notes(query)
    print(f"📌 Found {len(note_ids)} notes matching query: {query}")

    if not note_ids:
        showInfo("No notes found with tag: #Temp::Dupe_img")
        return

    dry_run = _prompt_dry_run_mode(mw)
    if dry_run is None:
        return

    def process_notes(col):
        return _process_notes_for_dupes(
            col=col,
            note_ids=note_ids,
            target_fields=target_fields,
            dry_run=bool(dry_run),
        )

    def on_success(removed_nids: List[int]) -> None:
        _report_completion(
            changed_nids=removed_nids,
            dry_run=bool(dry_run),
            backup_threshold=backup_threshold,
            backup_path=backup_path,
        )

    QueryOp(
        parent=mw,
        op=process_notes,
        success=on_success,
    ).with_progress(
        "Previewing duplicate images..." if dry_run else "Removing duplicate images..."
    ).run_in_background()
