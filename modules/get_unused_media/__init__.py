from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Optional, Set
from urllib.parse import unquote, urlparse

try:
    from aqt import mw
    from aqt.utils import showInfo
except Exception:  # pragma: no cover - allows tests/outside Anki import
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

DEFAULT_OUTPUT_DIR = Path("~/Desktop")
DEFAULT_FILENAME_PREFIX = "unused_anki_media"
DEFAULT_PROFILE_NAME = "profile"
DEFAULT_CHUNK_SIZE = 30
TIMESTAMP_FMT = "%b-%d-%y_%I-%M-%p"
SOUND_REF_PATTERN = re.compile(r"\[sound:([^\]]+)\]", flags=re.IGNORECASE)
IMG_TAG_PATTERN = re.compile(r"(?is)<img\b[^>]*>")
IMG_SRC_ATTR_PATTERN = re.compile(
    r"""(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)
LOCAL_FILE_SCHEMES = {"", "file"}


def _coerce_positive_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        out = int(value)
    except Exception:
        out = default
    return out if out > 0 else default


def _build_runtime_settings(cfg: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    raw_cfg = cfg if isinstance(cfg, dict) else load_modules_config()
    emit_config_warnings(validate_modules_config(raw_cfg), raw_cfg)
    section = get_section("unused_media_config", raw_cfg)

    default_output_dir = resolve_path(
        section.get("default_output_dir"), DEFAULT_OUTPUT_DIR
    )
    filename_prefix_raw = section.get("filename_prefix", DEFAULT_FILENAME_PREFIX)
    filename_prefix = (
        str(filename_prefix_raw).strip()
        if isinstance(filename_prefix_raw, str)
        else DEFAULT_FILENAME_PREFIX
    )
    if not filename_prefix:
        filename_prefix = DEFAULT_FILENAME_PREFIX

    chunk_size = _coerce_positive_int(section.get("chunk_size"), DEFAULT_CHUNK_SIZE)

    return {
        "default_output_dir": default_output_dir,
        "filename_prefix": filename_prefix,
        "chunk_size": chunk_size,
    }


def _get_profile_name(default: str = DEFAULT_PROFILE_NAME) -> str:
    raw_profile_name = getattr(getattr(mw, "pm", None), "name", default)
    profile_name = str(raw_profile_name).strip()
    return profile_name if profile_name else default


def _build_default_output_path(
    settings: Dict[str, object],
    profile_name: str,
    now: Optional[datetime] = None,
) -> Path:
    ts = (now or datetime.now()).strftime(TIMESTAMP_FMT)
    filename = f"{settings['filename_prefix']}_{profile_name}_{ts}.txt"
    return Path(str(settings["default_output_dir"])) / filename


def _normalize_media_reference(raw: str) -> Optional[str]:
    raw_val = str(raw).strip()
    if not raw_val:
        return None

    decoded = unquote(raw_val)
    parsed = urlparse(decoded)
    scheme = (parsed.scheme or "").lower()
    if scheme not in LOCAL_FILE_SCHEMES:
        return None

    # network-path refs like //cdn.example.com/a.png are remote
    if parsed.netloc and scheme != "file":
        return None

    normalized_path = parsed.path or decoded
    basename = os.path.basename(normalized_path).strip()
    if not basename:
        return None
    return basename


def _extract_img_src_values(text: str) -> Set[str]:
    src_values: Set[str] = set()
    if not text:
        return src_values

    for tag in IMG_TAG_PATTERN.findall(text):
        m = IMG_SRC_ATTR_PATTERN.search(tag)
        if not m:
            continue
        src = next((g for g in m.groups() if g), "")
        if src:
            src_values.add(src)
    return src_values


def _extract_used_files_from_fields(fields: Iterable[str]) -> Set[str]:
    used: Set[str] = set()
    for field in fields:
        for raw_sound in SOUND_REF_PATTERN.findall(field):
            normalized_sound = _normalize_media_reference(raw_sound)
            if normalized_sound:
                used.add(normalized_sound)

        for raw_src in _extract_img_src_values(field):
            normalized_src = _normalize_media_reference(raw_src)
            if normalized_src:
                used.add(normalized_src)
    return used


def _format_unused_files(unused_files: Iterable[str], chunk_size: int) -> str:
    items = list(unused_files)
    grouped = [", ".join(items[i : i + chunk_size]) for i in range(0, len(items), chunk_size)]
    return ",\n\n\n".join(grouped)


def export_unused_media_to_txt(output_path: str = None) -> None:
    """
    Finds all media files in the collection that are unused in any card.
    - If `output_path` is provided, it is used directly.
    - Otherwise, output path is built from `unused_media_config`.
    """
    if mw is None or getattr(mw, "col", None) is None:
        raise RuntimeError("Unused media exporter must run inside Anki (mw.col unavailable).")

    settings = _build_runtime_settings()
    profile_name = _get_profile_name()
    out_path = (
        Path(output_path).expanduser()
        if output_path
        else _build_default_output_path(settings, profile_name)
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    media_dir = Path(mw.col.media.dir())
    all_files = set(os.listdir(media_dir))

    used_files: Set[str] = set()
    for nid in mw.col.find_notes(""):
        note = mw.col.get_note(nid)
        used_files.update(_extract_used_files_from_fields(note.fields))

    unused_files = sorted(all_files - used_files)
    formatted_output = _format_unused_files(
        unused_files, int(settings.get("chunk_size", DEFAULT_CHUNK_SIZE))
    )
    out_path.write_text(formatted_output, encoding="utf-8")

    showInfo(
        "✅ "
        f"{len(unused_files)} unused media files written to:\n{out_path}"
    )
