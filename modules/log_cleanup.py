"""
anki_log_cleanup.py

Delete log files older than a configurable age from a target directory.
Designed to be imported from Anki add-on modules or run directly.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

# ==========================
# Config / defaults
# ==========================

LOGS_ROOT = Path("/Users/claytongoddard/Desktop/anki logs")
MAX_AGE_HOURS = 24
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


def _is_older_than(path: Path, cutoff: datetime) -> bool:
    """
    Return True if the file at `path` has a modification time older than `cutoff`.
    """
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        # ? If we can't stat it, just skip it
        return False
    return mtime < cutoff


def delete_old_anki_log_files(
    base_dir: Optional[Path | str] = None,
    max_age_hours: Optional[int] = None,
    dry_run: bool = False,
) -> List[Path]:
    """
    Delete files older than `max_age_hours` under `base_dir`, recursively.

    Parameters
    ----------
    base_dir:
        Root directory to clean. If None, uses LOGS_ROOT.
    max_age_hours:
        Age threshold in hours. If None, uses MAX_AGE_HOURS.
    dry_run:
        If True, does not delete anything; just returns the list of files that
        *would* be deleted.

    Returns
    -------
    deleted_files:
        List of Path objects for files actually deleted (or would be deleted if dry_run=True).
    """
    # * Resolve effective settings
    root = Path(base_dir) if base_dir is not None else LOGS_ROOT
    age_hours = max_age_hours if max_age_hours is not None else MAX_AGE_HOURS

    deleted: List[Path] = []

    if not root.exists():
        # ? Nothing to do if the directory doesn't exist
        return deleted

    now = _now()
    cutoff = now - timedelta(hours=age_hours)

    for file_path in _iter_files_recursive(root):
        if _is_older_than(file_path, cutoff):
            deleted.append(file_path)
            if not dry_run:
                try:
                    file_path.unlink()
                except OSError:
                    # If deletion fails, just skip; you can add logging here if needed.
                    deleted.pop()  # remove from list since it wasn't actually deleted

    return deleted


# ==========================
# Optional: direct execution
# ==========================

if __name__ == "__main__":
    """
    If you run this file directly (e.g. from VS Code's "Run" button),
    it will clean LOGS_ROOT using the defaults above and print a summary.
    """
    timestamp = _now().strftime(TIMESTAMP_FMT)
    print(f"[{timestamp}] Cleaning old Anki logs in: {LOGS_ROOT}")

    deleted_files = delete_old_anki_log_files(dry_run=False)

    if not deleted_files:
        print("No files deleted (none older than threshold or directory empty).")
    else:
        print(f"Deleted {len(deleted_files)} file(s):")
        for p in deleted_files:
            print(f"  - {p}")