from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# ==========================
# Stable paths / defaults
# ==========================

# * Likely-to-change defaults are centralized here for VS Code "Run" workflows.
DESKTOP_ROOT: Path = Path.home() / "Desktop"
DEFAULT_LOG_DIR: Path = DESKTOP_ROOT / "anki_logs" / "Main_toolbar"
DEFAULT_TS_FORMAT: str = "%H-%M_%m-%d"

# * Source-of-truth config path for module-level tools.
MODULES_DIR: Path = Path(__file__).resolve().parent
MODULES_CONFIG_PATH: Path = MODULES_DIR / "modules_config.json"
CONFIG_WARNING_LOG_FILENAME = "Module_Config_Warnings.log"

# * Config section schemas (validation-only, non-blocking)
MISSING_MEDIA_SCHEMA: Dict[str, Tuple[type, ...]] = {
    "tag_filter_enabled": (bool,),
    "tag_name": (str,),
    "media_extensions": (list, tuple, set),
    "output_dir": (str, Path),
    "backup_dir": (str, Path),
}
UNUSED_MEDIA_SCHEMA: Dict[str, Tuple[type, ...]] = {
    "default_output_dir": (str, Path),
    "filename_prefix": (str,),
    "chunk_size": (int,),
}
IMG_DUPES_SCHEMA: Dict[str, Tuple[type, ...]] = {
    "fields": (list, tuple, set),
    "backup_threshold": (int,),
    "backup_path": (str, Path),
}
LOG_CLEANUP_SCHEMA: Dict[str, Tuple[type, ...]] = {
    "logs_root": (str, Path),
    "allowed_suffixes": (list, tuple, set),
    "safe_root_marker": (str,),
    "keep_runs": (int,),
}
SECTION_SCHEMAS: Dict[str, Dict[str, Tuple[type, ...]]] = {
    "missing_media_config": MISSING_MEDIA_SCHEMA,
    "unused_media_config": UNUSED_MEDIA_SCHEMA,
    "img_dupes_config": IMG_DUPES_SCHEMA,
    "log_cleanup_config": LOG_CLEANUP_SCHEMA,
}
_LIST_STRING_KEYS = {"media_extensions", "fields", "allowed_suffixes"}
_EMITTED_CONFIG_WARNINGS: set[str] = set()


def load_modules_config(path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load modules_config.json into a dict. Returns {} on any failure."""
    cfg_path = Path(path) if path is not None else MODULES_CONFIG_PATH
    try:
        cfg_path = cfg_path.expanduser().resolve()
    except Exception:
        cfg_path = Path(str(cfg_path))

    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def get_global_config(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return global_config as a plain dict (or {})."""
    data = cfg if isinstance(cfg, dict) else load_modules_config()
    block = data.get("global_config", {})
    return dict(block) if isinstance(block, dict) else {}


def get_section(name: str, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a named top-level config section as a plain dict (or {})."""
    data = cfg if isinstance(cfg, dict) else load_modules_config()
    block = data.get(name, {})
    return dict(block) if isinstance(block, dict) else {}


def _matches_expected_type(value: object, expected: Tuple[type, ...]) -> bool:
    # bool is a subclass of int; treat bool as invalid when int is expected.
    if expected == (int,) and isinstance(value, bool):
        return False
    return isinstance(value, expected)


def _type_label(expected: Tuple[type, ...]) -> str:
    includes_path = Path in expected
    includes_str = str in expected
    labels = []
    for typ in expected:
        if typ is str and includes_path:
            continue
        if typ is Path:
            if includes_str:
                continue
            labels.append("Path")
            continue
        labels.append(typ.__name__)
    if includes_path and includes_str:
        labels.append("str|Path")
    # remove duplicates while preserving order
    unique_labels = list(dict.fromkeys(labels))
    return " | ".join(unique_labels)


def validate_modules_config(cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Validate known config sections and return warning strings.

    This is non-blocking validation: no exceptions are raised.
    """
    data = cfg if isinstance(cfg, dict) else load_modules_config()
    warnings: List[str] = []

    if not isinstance(data, dict):
        return ["modules_config root should be a JSON object; using module defaults."]

    for section_name, schema in SECTION_SCHEMAS.items():
        section = data.get(section_name)
        if section is None:
            continue
        if not isinstance(section, dict):
            warnings.append(
                f"`{section_name}` should be an object; using module defaults for that section."
            )
            continue

        for key, expected in schema.items():
            if key not in section:
                continue
            value = section[key]
            if not _matches_expected_type(value, expected):
                warnings.append(
                    f"`{section_name}.{key}` has invalid type "
                    f"`{type(value).__name__}` (expected `{_type_label(expected)}`); using fallback."
                )
                continue
            if key in _LIST_STRING_KEYS and isinstance(value, (list, tuple, set)):
                if not all(isinstance(item, str) for item in value):
                    warnings.append(
                        f"`{section_name}.{key}` should contain only strings; using fallback."
                    )

    # dedupe while preserving order
    return list(dict.fromkeys(warnings))


def _resolve_warning_log_path(cfg: Optional[Dict[str, Any]] = None) -> Path:
    global_cfg = get_global_config(cfg)
    log_dir = resolve_path(global_cfg.get("log_dir"), DEFAULT_LOG_DIR)
    return log_dir / CONFIG_WARNING_LOG_FILENAME


def _resolve_warning_ts_format(cfg: Optional[Dict[str, Any]] = None) -> str:
    global_cfg = get_global_config(cfg)
    raw = global_cfg.get("ts_format", DEFAULT_TS_FORMAT)
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return DEFAULT_TS_FORMAT


def emit_config_warnings(
    warnings: Iterable[str],
    cfg: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Emit config warnings once per process and append them to a warning log.
    Returns the warnings emitted in this call (post-dedup).
    """
    emitted_now: List[str] = []
    for warning in warnings:
        msg = str(warning).strip()
        if not msg or msg in _EMITTED_CONFIG_WARNINGS:
            continue
        _EMITTED_CONFIG_WARNINGS.add(msg)
        emitted_now.append(msg)
        print(f"[module_config] WARNING: {msg}")

    if not emitted_now:
        return emitted_now

    try:
        log_path = _resolve_warning_log_path(cfg)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime(_resolve_warning_ts_format(cfg))
        with log_path.open("a", encoding="utf-8") as handle:
            for msg in emitted_now:
                handle.write(f"[{ts}] {msg}\n")
    except Exception:
        # Warning logging is best-effort and must never affect runtime behavior.
        pass

    return emitted_now


def resolve_path(raw: Optional[Union[str, Path]], fallback: Path) -> Path:
    """
    Resolve a path value safely.

    - Empty/None -> resolved fallback
    - Relative -> MODULES_DIR-relative
    - Absolute -> normalized absolute
    """
    fb = Path(fallback).expanduser()
    try:
        fb = fb.resolve()
    except Exception:
        pass

    if raw is None:
        return fb

    if not isinstance(raw, (str, Path)):
        return fb

    s = str(raw).strip()
    if not s:
        return fb

    try:
        p = Path(s).expanduser()
    except Exception:
        return fb

    if not p.is_absolute():
        p = MODULES_DIR / p

    try:
        return p.resolve()
    except Exception:
        return p
