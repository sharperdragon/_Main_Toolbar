from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:  # pragma: no cover - UI imports are optional in tests
    from aqt.qt import QInputDialog, QLineEdit
except Exception:  # pragma: no cover
    QInputDialog = None  # type: ignore[assignment]
    QLineEdit = None  # type: ignore[assignment]


# ==========================
# Changeable defaults
# ==========================
FILTER_DIALOG_TITLE = "Optional tag filter"
FILTER_TAG_LABEL = "Tag filter (optional; leave blank for all notes):"
FILTER_NOTE_TYPE_LABEL = "Note type filter (optional; leave blank for all notes):"


@dataclass(frozen=True)
class ScopeFilter:
    tag_filter: str
    note_type_filter: str
    query: str


def _quote_anki_term(value: str) -> str:
    """Quote a search token when needed for Anki Browser search syntax."""
    text = str(value or "").strip()
    if not text:
        return ""

    already_quoted = len(text) >= 2 and text.startswith('"') and text.endswith('"')
    if already_quoted:
        return text

    needs_quotes = any(ch.isspace() for ch in text) or any(ch in '"()' for ch in text)
    if not needs_quotes:
        return text

    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _normalize_tag_clause(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""

    low = text.lower()
    if low.startswith("tag:") or low.startswith("-tag:"):
        return text
    return f"tag:{_quote_anki_term(text)}"


def _normalize_note_type_clause(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""

    low = text.lower()
    if low.startswith("note:") or low.startswith("-note:"):
        return text
    return f"note:{_quote_anki_term(text)}"


def build_scope_query(tag_filter: str = "", note_type_filter: str = "") -> str:
    """Build an Anki Browser query that combines optional tag + note filters."""
    clauses = []
    tag_clause = _normalize_tag_clause(tag_filter)
    note_clause = _normalize_note_type_clause(note_type_filter)
    if tag_clause:
        clauses.append(tag_clause)
    if note_clause:
        clauses.append(note_clause)
    return " ".join(clauses).strip()


def prompt_scope_filter(parent) -> Optional[ScopeFilter]:
    """Prompt for optional tag scope. Returns None when cancelled."""
    if QInputDialog is None:
        # UI not available in this environment; default to no filter.
        return ScopeFilter(tag_filter="", note_type_filter="", query="")

    text_mode = QLineEdit.EchoMode.Normal if QLineEdit is not None else 0

    tag_text, ok = QInputDialog.getText(
        parent,
        FILTER_DIALOG_TITLE,
        FILTER_TAG_LABEL,
        text_mode,
        "",
    )
    if not ok:
        return None

    tag_filter = str(tag_text or "").strip()
    note_type_filter = ""
    return ScopeFilter(
        tag_filter=tag_filter,
        note_type_filter=note_type_filter,
        query=build_scope_query(tag_filter, note_type_filter),
    )


__all__ = [
    "ScopeFilter",
    "build_scope_query",
    "prompt_scope_filter",
]
