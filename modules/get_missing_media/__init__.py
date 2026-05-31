# pyright: reportMissingImports=false
# mypy: disable_error_code=import
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

try:
    from aqt import mw
    from aqt.utils import showInfo
except Exception:  # pragma: no cover - allows import in tests/outside Anki
    mw = None  # type: ignore

    def showInfo(msg: str) -> None:  # type: ignore
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

DEFAULT_TAG_FILTER_ENABLED = True
DEFAULT_TAG_NAME = "missing-media"
DEFAULT_MEDIA_EXTENSIONS: Tuple[str, ...] = (
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".gif",
    ".mp3",
    ".mp4",
)
DEFAULT_OUTPUT_DIR = Path("~/Desktop/Missing Media files")
DEFAULT_BACKUP_DIR = Path("~/ANki/Missing Media/backup")
OUTPUT_PREFIX = "missing_media_"
DEFAULT_PROFILE_NAME = "profile"
IMG_TAG_RE = re.compile(r"(?is)<img\b[^>]*>")
SRC_ATTR_RE = re.compile(
    r"""(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)
LOCAL_FILE_SCHEMES = {"", "file"}
LIKE_ESCAPE_CHAR = "\\"

# Backward-compatible knobs (editable at top of file)
TAG_FILTER_ENABLED = DEFAULT_TAG_FILTER_ENABLED
TAG_NAME = DEFAULT_TAG_NAME
MEDIA_EXTENSIONS = set(DEFAULT_MEDIA_EXTENSIONS)


def _normalize_extensions(values: object, fallback: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    if isinstance(values, (list, tuple, set)):
        items = values
    elif isinstance(values, str):
        items = [values]
    else:
        items = []

    for item in items:
        if not isinstance(item, str):
            continue
        s = item.strip().lower()
        if not s:
            continue
        if not s.startswith("."):
            s = f".{s}"
        out.add(s)

    if out:
        return out
    return {str(x).strip().lower() for x in fallback if str(x).strip()}


def _build_runtime_settings(cfg: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    raw_cfg = cfg if isinstance(cfg, dict) else load_modules_config()
    emit_config_warnings(validate_modules_config(raw_cfg), raw_cfg)
    section = get_section("missing_media_config", raw_cfg)

    tag_filter_raw = section.get("tag_filter_enabled", TAG_FILTER_ENABLED)
    tag_filter_enabled = (
        tag_filter_raw if isinstance(tag_filter_raw, bool) else TAG_FILTER_ENABLED
    )

    tag_name_raw = section.get("tag_name", TAG_NAME)
    tag_name = str(tag_name_raw).strip() if isinstance(tag_name_raw, str) else str(TAG_NAME).strip()

    media_extensions = _normalize_extensions(
        section.get("media_extensions"), MEDIA_EXTENSIONS
    )

    output_dir = resolve_path(section.get("output_dir"), DEFAULT_OUTPUT_DIR)
    backup_dir = resolve_path(section.get("backup_dir"), DEFAULT_BACKUP_DIR)

    return {
        "tag_filter_enabled": tag_filter_enabled,
        "tag_name": tag_name,
        "media_extensions": media_extensions,
        "output_dir": output_dir,
        "backup_dir": backup_dir,
    }


def _effective_tag(settings: Dict[str, object]) -> Optional[str]:
    if bool(settings.get("tag_filter_enabled", False)):
        tag = str(settings.get("tag_name", "") or "").strip()
        if tag:
            return tag
    return None


def _normalize_media_ref(raw: str) -> Optional[str]:
    raw_val = str(raw).strip()
    if not raw_val:
        return None

    decoded = unquote(raw_val)
    parsed = urlparse(decoded)
    scheme = (parsed.scheme or "").lower()
    if scheme not in LOCAL_FILE_SCHEMES:
        return None

    # Network-path refs like //cdn.example.com/a.png are remote and excluded.
    if parsed.netloc and scheme != "file":
        return None

    normalized_path = parsed.path or decoded
    basename = os.path.basename(normalized_path).strip()
    if not basename:
        return None
    return basename


def _extract_media_refs(text: str, extensions: Set[str]) -> Set[str]:
    refs: Set[str] = set()
    if not text:
        return refs

    for tag in IMG_TAG_RE.findall(text):
        for m in SRC_ATTR_RE.finditer(tag):
            raw_src = next((group for group in m.groups() if group), "")
            if not raw_src:
                continue
            base = _normalize_media_ref(raw_src)
            if not base:
                continue
            if any(base.lower().endswith(ext) for ext in extensions):
                refs.add(base)
    return refs


def _collect_used_media(rows: Iterable[Tuple[str]], extensions: Set[str]) -> Set[str]:
    used: Set[str] = set()
    for row in rows:
        if not row:
            continue
        flds = row[0]
        for field in str(flds).split("\x1f"):
            used.update(_extract_media_refs(field, extensions))
    return used


def _compute_missing_media(used: Set[str], existing: Set[str]) -> List[str]:
    return sorted(used - existing)


def _resolve_output_paths(
    profile_name: str,
    output_dir: Path,
    backup_dir: Path,
) -> Tuple[Path, Path]:
    filename = f"{OUTPUT_PREFIX}{profile_name}.txt"
    return output_dir / filename, backup_dir / filename


def _resolve_profile_name(default: str = DEFAULT_PROFILE_NAME) -> str:
    raw_profile_name = getattr(getattr(mw, "pm", None), "name", default)
    profile_name = str(raw_profile_name).strip()
    return profile_name if profile_name else default


def _write_name_list(path: Path, names: Iterable[str]) -> None:
    items = list(names)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")


def _write_name_list_safe(path: Path, names: Iterable[str]) -> Tuple[bool, Optional[str]]:
    try:
        _write_name_list(path, names)
        return True, None
    except Exception as e:
        return False, str(e)


def _escape_like_literal(value: str, escape_char: str = LIKE_ESCAPE_CHAR) -> str:
    escaped = value.replace(escape_char, escape_char * 2)
    escaped = escaped.replace("%", f"{escape_char}%")
    escaped = escaped.replace("_", f"{escape_char}_")
    return escaped


def _query_note_rows(col, tag: Optional[str]) -> Iterable[Tuple[str]]:
    db = col.db
    if tag:
        escaped_tag = _escape_like_literal(tag)
        like_pat = f"% {escaped_tag} %"
        return db.all(
            "SELECT flds FROM notes WHERE tags LIKE ? ESCAPE '\\'",
            like_pat,
        )
    return db.all("SELECT flds FROM notes")


def _export_missing_media_for_collection(
    col,
    profile_name: str,
    settings: Dict[str, object],
) -> Dict[str, object]:
    effective_tag = _effective_tag(settings)
    exts = set(settings.get("media_extensions", set()) or set())
    rows = _query_note_rows(col, effective_tag)
    used = _collect_used_media(rows, exts)
    existing = set(os.listdir(col.media.dir()))
    missing = _compute_missing_media(used, existing)

    output_dir = Path(str(settings.get("output_dir")))
    backup_dir = Path(str(settings.get("backup_dir")))
    output_path, backup_path = _resolve_output_paths(profile_name, output_dir, backup_dir)

    primary_ok, primary_err = _write_name_list_safe(output_path, missing)
    backup_ok, backup_err = _write_name_list_safe(backup_path, missing)

    if not primary_ok and primary_err:
        print(f"❌ Failed to write missing media file: {primary_err}")
    if not backup_ok and backup_err:
        print(f"❌ Failed to write backup missing media file: {backup_err}")

    return {
        "output_path": output_path,
        "backup_path": backup_path,
        "missing_count": len(missing),
        "used_tag_scope": bool(effective_tag),
        "effective_tag": effective_tag,
        "primary_write_ok": primary_ok,
        "backup_write_ok": backup_ok,
        "primary_error": primary_err,
        "backup_error": backup_err,
    }


def _build_run_message(
    *,
    scope_text: str,
    missing_count: int,
    output_path: Path,
    backup_path: Path,
    primary_write_ok: bool,
    backup_write_ok: bool,
    primary_error: Optional[str] = None,
    backup_error: Optional[str] = None,
) -> str:
    if primary_write_ok and backup_write_ok:
        return (
            "✅ Missing media check complete.\n\n"
            f"🔎 Scanned: {scope_text}\n"
            f"📦 {missing_count} missing files saved to:\n{output_path}"
        )

    if primary_write_ok and not backup_write_ok:
        err_text = backup_error or "unknown error"
        return (
            "⚠️ Missing media check completed with partial output.\n\n"
            f"🔎 Scanned: {scope_text}\n"
            f"📦 {missing_count} missing files saved to primary output:\n{output_path}\n\n"
            f"Backup write failed:\n{backup_path}\nReason: {err_text}"
        )

    if backup_write_ok and not primary_write_ok:
        err_text = primary_error or "unknown error"
        return (
            "⚠️ Missing media check completed with partial output.\n\n"
            f"🔎 Scanned: {scope_text}\n"
            f"📦 {missing_count} missing files saved to backup output:\n{backup_path}\n\n"
            f"Primary write failed:\n{output_path}\nReason: {err_text}"
        )

    primary_text = primary_error or "unknown error"
    backup_text = backup_error or "unknown error"
    return (
        "❌ Missing media check failed. Could not write output files.\n\n"
        f"🔎 Scanned: {scope_text}\n"
        f"📦 {missing_count} missing files detected.\n\n"
        f"Primary output failed:\n{output_path}\nReason: {primary_text}\n\n"
        f"Backup output failed:\n{backup_path}\nReason: {backup_text}"
    )


def write_missing_file() -> None:
    """
    Toolbar entrypoint.
    - Uses missing_media_config when present.
    - Falls back to top-of-file defaults when keys are absent.
    """
    if mw is None or getattr(mw, "col", None) is None:
        raise RuntimeError("Missing media exporter must run inside Anki (mw.col unavailable).")

    settings = _build_runtime_settings()
    profile_name = _resolve_profile_name()
    result = _export_missing_media_for_collection(
        mw.col, profile_name, settings
    )
    effective_tag = str(result.get("effective_tag") or "")
    used_tag_scope = bool(result.get("used_tag_scope", False))
    scope_text = (
        f"only notes tagged '{effective_tag}'"
        if used_tag_scope
        else "all notes"
    )
    message = _build_run_message(
        scope_text=scope_text,
        missing_count=int(result.get("missing_count", 0)),
        output_path=Path(str(result.get("output_path"))),
        backup_path=Path(str(result.get("backup_path"))),
        primary_write_ok=bool(result.get("primary_write_ok", False)),
        backup_write_ok=bool(result.get("backup_write_ok", False)),
        primary_error=(
            str(result.get("primary_error"))
            if result.get("primary_error") is not None
            else None
        ),
        backup_error=(
            str(result.get("backup_error"))
            if result.get("backup_error") is not None
            else None
        ),
    )
    showInfo(message)


if __name__ == "__main__":
    write_missing_file()
