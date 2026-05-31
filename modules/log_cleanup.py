from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, TypedDict, Union

try:
    from .module_config import (
        DEFAULT_TS_FORMAT,
        emit_config_warnings,
        get_global_config,
        get_section,
        load_modules_config,
        resolve_path,
        validate_modules_config,
    )
except Exception:  # pragma: no cover
    import sys

    _MODULES_DIR = Path(__file__).resolve().parent
    if str(_MODULES_DIR) not in sys.path:
        sys.path.insert(0, str(_MODULES_DIR))
    from module_config import (  # type: ignore
        DEFAULT_TS_FORMAT,
        emit_config_warnings,
        get_global_config,
        get_section,
        load_modules_config,
        resolve_path,
        validate_modules_config,
    )

# ==========================
# Config / defaults
# ==========================

# * Top-level defaults for VS Code "Run" workflows.
DEFAULT_LOGS_ROOT = Path("~/Desktop/anki_logs/Main_toolbar")
DEFAULT_ALLOWED_SUFFIXES = {".log", ".txt", ".md"}
DEFAULT_SAFE_ROOT_MARKER = "anki_logs"
DEFAULT_KEEP_RUNS = 2
DEFAULT_TIMESTAMP_FMT = DEFAULT_TS_FORMAT

# * Runtime settings (resolved from config by _refresh_runtime_settings()).
LOGS_ROOT = Path(DEFAULT_LOGS_ROOT).expanduser()
ALLOWED_SUFFIXES = set(DEFAULT_ALLOWED_SUFFIXES)
SAFE_ROOT_MARKER = DEFAULT_SAFE_ROOT_MARKER
KEEP_RUNS = DEFAULT_KEEP_RUNS
TIMESTAMP_FMT = DEFAULT_TIMESTAMP_FMT

# * Regex to extract run stamp from filenames ending with '__HH-MM_MM-DD.ext'
RUN_STAMP_RE = re.compile(r"__(\d{2}-\d{2}_\d{2}-\d{2})\.[A-Za-z0-9]+$", re.IGNORECASE)


class RuntimeSettings(TypedDict):
    logs_root: Path
    allowed_suffixes: set[str]
    safe_root_marker: str
    keep_runs: int
    timestamp_fmt: str


def _coerce_suffixes(values: object, fallback: Iterable[str]) -> set[str]:
    out: set[str] = set()
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


def _coerce_non_negative_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default

    if isinstance(value, int):
        out = value
    elif isinstance(value, float):
        try:
            out = int(value)
        except Exception:
            out = default
    elif isinstance(value, str):
        try:
            out = int(value.strip())
        except Exception:
            out = default
    else:
        out = default

    return out if out >= 0 else default


def _build_runtime_settings() -> RuntimeSettings:
    cfg = load_modules_config()
    emit_config_warnings(validate_modules_config(cfg), cfg)
    section = get_section("log_cleanup_config", cfg)
    global_cfg = get_global_config(cfg)

    # Precedence: log_cleanup_config.logs_root -> global_config.log_dir -> fallback
    logs_root_raw = section.get("logs_root")
    if not isinstance(logs_root_raw, (str, Path)) or not str(logs_root_raw).strip():
        logs_root_raw = global_cfg.get("log_dir")
    logs_root = resolve_path(logs_root_raw, DEFAULT_LOGS_ROOT)

    allowed_suffixes = _coerce_suffixes(
        section.get("allowed_suffixes"), DEFAULT_ALLOWED_SUFFIXES
    )

    marker_raw = section.get("safe_root_marker", DEFAULT_SAFE_ROOT_MARKER)
    marker = (
        str(marker_raw).strip()
        if isinstance(marker_raw, str)
        else DEFAULT_SAFE_ROOT_MARKER
    )
    if not marker:
        marker = DEFAULT_SAFE_ROOT_MARKER

    keep_runs = _coerce_non_negative_int(section.get("keep_runs"), DEFAULT_KEEP_RUNS)

    ts_raw = global_cfg.get("ts_format", DEFAULT_TIMESTAMP_FMT)
    timestamp_fmt = str(ts_raw).strip() if isinstance(ts_raw, str) else DEFAULT_TIMESTAMP_FMT
    if not timestamp_fmt:
        timestamp_fmt = DEFAULT_TIMESTAMP_FMT

    return {
        "logs_root": logs_root,
        "allowed_suffixes": allowed_suffixes,
        "safe_root_marker": marker,
        "keep_runs": keep_runs,
        "timestamp_fmt": timestamp_fmt,
    }


def _refresh_runtime_settings() -> None:
    global LOGS_ROOT, ALLOWED_SUFFIXES, SAFE_ROOT_MARKER, KEEP_RUNS, TIMESTAMP_FMT

    data = _build_runtime_settings()
    LOGS_ROOT = Path(str(data["logs_root"])).expanduser()
    ALLOWED_SUFFIXES = data["allowed_suffixes"]
    SAFE_ROOT_MARKER = str(data["safe_root_marker"])
    KEEP_RUNS = data["keep_runs"]
    TIMESTAMP_FMT = str(data["timestamp_fmt"])


# Resolve config-backed runtime defaults at import time.
_refresh_runtime_settings()


# ==========================
# Core helper functions
# ==========================

def _now() -> datetime:
    """Return current time as a naive datetime (local time)."""
    return datetime.now()


def _iter_files_recursive(root: Path) -> Iterable[Path]:
    """
    Recursively yield all regular files under `root`.

    Directories are not yielded, only files.
    """
    if not root.exists():
        return  # nothing to yield

    for path in root.rglob("*"):
        if path.is_file():
            yield path


def _is_safe_root(root: Path) -> bool:
    """
    Extra guard to avoid accidentally pointing at Desktop, Home, or /.

    Conditions:
    - Root must be a directory.
    - Root must NOT be /, home, home/Desktop, or their parents.
    - Root must contain SAFE_ROOT_MARKER in one of its path parts.
    """
    root = root.expanduser().resolve()

    if not root.is_dir():
        return False

    home = Path.home().resolve()
    desktop = (home / "Desktop").resolve()

    # ! Hard blocks for obviously dangerous roots
    forbidden_roots = {
        Path("/").resolve(),
        home,
        desktop,
        home.parent.resolve(),  # e.g. /Users
    }
    if root in forbidden_roots:
        return False

    # * Require marker somewhere in the path (e.g. ".../anki_logs/...")
    parts_lower = [p.lower() for p in root.parts]
    if SAFE_ROOT_MARKER.lower() not in parts_lower:
        return False

    return True


def _is_allowed_log_file(path: Path) -> bool:
    """
    Return True if this path looks like a log file we are allowed to delete.
    """
    suffix = path.suffix.lower()

    # * Only touch explicitly allowed suffixes
    if suffix not in ALLOWED_SUFFIXES:
        return False

    return True


def _extract_run_stamp(filename: str) -> Optional[str]:
    """Extract trailing run stamp '__HH-MM_MM-DD' from a filename."""
    m = RUN_STAMP_RE.search(filename)
    return m.group(1) if m else None


def _parse_run_stamp_parts(stamp: str) -> Optional[Tuple[int, int, int, int]]:
    """Parse 'HH-MM_MM-DD' into integer parts (hour, minute, month, day)."""
    try:
        hhmm, mmdd = stamp.split("_", 1)
        hh_s, mi_s = hhmm.split("-", 1)
        mo_s, dd_s = mmdd.split("-", 1)
        return int(hh_s), int(mi_s), int(mo_s), int(dd_s)
    except Exception:
        return None


def _safe_dt_for_year(
    year: int,
    month: int,
    day: int,
    hour: int,
    minute: int,
) -> Optional[datetime]:
    """Build datetime safely for a specific year; return None when invalid."""
    try:
        return datetime(year, month, day, hour, minute)
    except Exception:
        return None


def _run_stamp_to_dt(stamp: str) -> Optional[datetime]:
    """
    Convert a run stamp 'HH-MM_MM-DD' into a datetime for sorting.

    Notes
    -----
    - The stamp has no year; we assume the current year.
    - To avoid incorrect ordering across New Year (e.g., Dec 31 logs when running on Jan 1),
      if the parsed datetime is > ~1 day in the future, we treat it as last year.
    - If parsing fails, return None.
    """
    parts = _parse_run_stamp_parts(stamp)
    if parts is None:
        return None
    hour, minute, month, day = parts
    now = _now()

    # Prefer current year first.
    dt = _safe_dt_for_year(now.year, month, day, hour, minute)

    # Leap-day and invalid-date fallback: walk back to nearest valid year.
    if dt is None:
        for year in range(now.year - 1, now.year - 9, -1):
            dt = _safe_dt_for_year(year, month, day, hour, minute)
            if dt is not None:
                break
    if dt is None:
        return None

    # ! Year-boundary fix: Dec/Jan rollover
    if dt > (now + timedelta(days=1)):
        shifted = None
        for year in range(dt.year - 1, dt.year - 9, -1):
            shifted = _safe_dt_for_year(year, month, day, hour, minute)
            if shifted is not None:
                break
        if shifted is not None:
            dt = shifted

    return dt


def _collect_run_stamps(root: Path) -> List[Tuple[str, datetime]]:
    """Return sorted unique run stamps found under root as (stamp, dt), oldest->newest."""
    seen: Dict[str, datetime] = {}

    for file_path in _iter_files_recursive(root):
        if not _is_allowed_log_file(file_path):
            continue

        stamp = _extract_run_stamp(file_path.name)
        if not stamp:
            continue

        dt = _run_stamp_to_dt(stamp)
        if dt is None:
            continue

        # Keep the max dt for a given stamp (should be identical, but be defensive)
        prev = seen.get(stamp)
        if prev is None or dt > prev:
            seen[stamp] = dt

    return sorted(seen.items(), key=lambda t: t[1])


def delete_old_anki_log_files(
    base_dir: Optional[Union[Path, str]] = None,
    max_files_per_base: Optional[int] = None,  # deprecated (kept for backward compatibility)
    dry_run: bool = True,
    keep_runs: Optional[int] = None,
) -> List[Path]:
    """
    Delete older log files based on *runs*, not per-base counts.

    A "run" is identified by the trailing stamp in the filename:
        __HH-MM_MM-DD

    Logic:
    - Find all unique run stamps under the root.
    - Keep files whose stamp is in the newest `keep_runs` run stamps.
    - Delete all other allowed log files that have a stamp.
    - Files without a run stamp are NOT deleted (safety default).

    Safety:
    - Only deletes files with ALLOWED_SUFFIXES.
    - Refuses to run if root doesn't pass _is_safe_root.
    - DRY RUN by default (dry_run=True).

    Parameters
    ----------
    base_dir:
        Root directory to clean. If None, uses LOGS_ROOT.
    max_files_per_base:
        Deprecated; ignored. (Kept so existing callers don't break.)
    dry_run:
        If True, does not delete anything; just returns list of files that
        *would* be deleted.
    keep_runs:
        Number of most recent runs to keep. If None, uses KEEP_RUNS.

    Returns
    -------
    deleted_files:
        List of Path objects for files actually deleted (or would be deleted if dry_run=True).
    """
    _refresh_runtime_settings()

    root = Path(base_dir) if base_dir is not None else LOGS_ROOT
    root = root.expanduser().resolve()

    # * Backward compatibility: ignore max_files_per_base
    _ = max_files_per_base

    keep_n = KEEP_RUNS if keep_runs is None else int(keep_runs)
    if keep_n < 0:
        keep_n = 0

    deleted: List[Path] = []

    if not root.exists():
        # ? Nothing to do if the directory doesn't exist
        return deleted

    # ! Safety gate: refuse obviously unsafe roots
    if not _is_safe_root(root):
        raise RuntimeError(
            f"Refusing to clean unsafe root: {root}\n"
            f"Expected a dedicated logs directory containing marker '{SAFE_ROOT_MARKER}'."
        )

    # 1) Determine the newest N run stamps
    stamps = _collect_run_stamps(root)  # oldest->newest
    if not stamps or keep_n == 0:
        # If no stamps found (or keeping none), we do nothing by default.
        # Rationale: don't delete unknown-format files.
        return deleted

    keep_set = {s for s, _dt in stamps[-keep_n:]}

    # 2) Delete stamped files not in keep_set
    for file_path in _iter_files_recursive(root):
        if not _is_allowed_log_file(file_path):
            continue

        stamp = _extract_run_stamp(file_path.name)
        if not stamp:
            # ? No run stamp: keep (safety default)
            continue

        if stamp in keep_set:
            continue

        if dry_run:
            deleted.append(file_path)
        else:
            try:
                file_path.unlink()
                deleted.append(file_path)
            except OSError:
                # If deletion fails, skip but do not remove from list; it's useful to know it was attempted.
                continue

    return deleted


# ==========================
# Optional: direct execution
# ==========================

if __name__ == "__main__":
    """
    If you run this file directly (e.g. from VS Code's "Run" button),
    it will perform a DRY RUN by default:
    - It will NOT delete anything.
    - It will print which files *would* be deleted.
    """
    _refresh_runtime_settings()

    timestamp = _now().strftime(TIMESTAMP_FMT)
    print(
        f"[{timestamp}] DRY RUN - inspecting Anki logs in: {LOGS_ROOT} "
        f"(keeping last {KEEP_RUNS} runs)"
    )

    deleted_files = delete_old_anki_log_files(dry_run=True)

    if not deleted_files:
        print("No files would be deleted (no stamped logs found, or already within last N runs).")
    else:
        print(f"{len(deleted_files)} file(s) would be deleted:")
        for p in deleted_files:
            print(f"  - {p}")

        print(
            "\nIf this list looks correct, call "
            "`delete_old_anki_log_files(dry_run=False)` from Python "
            "(optionally pass keep_runs=2), "
            "or temporarily change dry_run to False in the __main__ block."
        )
