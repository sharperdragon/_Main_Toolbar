from __future__ import annotations

import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple, Union

# ==========================
# Config / defaults
# ==========================

# * This should ALWAYS point to a dedicated logs folder, NEVER Desktop directly.
LOGS_ROOT = Path("/Users/claytongoddard/Desktop/anki_logs/Main_toolbar")

# * Only delete files with these suffixes (lowercased).
ALLOWED_SUFFIXES = {".log", ".txt", ".md"}

# * Require this marker to appear somewhere in the root path as an extra safety net.
SAFE_ROOT_MARKER = "anki_logs"

# * Keep logs from the most recent N unique "runs".
#   A run is identified by the trailing stamp in the filename: __HH-MM_MM-DD
KEEP_RUNS = 2

# * Regex to extract run stamp from filenames ending with '__HH-MM_MM-DD.ext'
RUN_STAMP_RE = re.compile(r"__(\d{2}-\d{2}_\d{2}-\d{2})\.[A-Za-z0-9]+$", re.IGNORECASE)

# * Timestamp format for console messages.
TIMESTAMP_FMT = "%H-%M_%m-%d"


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
    try:
        base = datetime.strptime(stamp, "%H-%M_%m-%d")
        now = _now()
        dt = base.replace(year=now.year)

        # ! Year-boundary fix: Dec/Jan rollover
        if dt > (now + timedelta(days=1)):
            dt = dt.replace(year=now.year - 1)

        return dt
    except Exception:
        return None


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
    timestamp = _now().strftime(TIMESTAMP_FMT)
    print(f"[{timestamp}] DRY RUN – inspecting Anki logs in: {LOGS_ROOT} (keeping last {KEEP_RUNS} runs)")

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