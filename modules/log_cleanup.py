"""
anki_log_cleanup.py

Smarter cleanup for Anki log files.

Instead of time-based deletion only, this script:
- Groups log files by a "base name" (stem before the first "__").
- Keeps only the newest MAX_FILES_PER_BASE files per base.
- Deletes only the older files in each group.

Safety features:
- Only touches files with ALLOWED_SUFFIXES.
- Refuses to run on unsafe roots (/, home, Desktop, etc.).
- Requires SAFE_ROOT_MARKER to appear in the root path.
- DRY RUN by default when executed directly.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

# ==========================
# Config / defaults
# ==========================

# * This should ALWAYS point to a dedicated logs folder, NEVER Desktop directly.
LOGS_ROOT = Path("/Users/claytongoddard/Desktop/anki_logs")

# * Only delete files with these suffixes (lowercased).
ALLOWED_SUFFIXES = {".log", ".txt", ".md"}

# * Require this marker to appear somewhere in the root path as an extra safety net.
SAFE_ROOT_MARKER = "anki_logs"

# * Maximum number of log files to keep per "base name".
MAX_FILES_PER_BASE = 10

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


def _get_mtime(path: Path) -> Optional[datetime]:
    """Return file modification time, or None on error."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        return None


def _base_name_for_log(path: Path) -> str:
    """
    Derive a "base name" for grouping log files.

    Example:
    - 'Batch_FR_Debug__09-02_12-09.md' -> 'Batch_FR_Debug'
    - 'Regex_Debug__09-02_12-09.md' -> 'Regex_Debug'
    - If no '__' present, use the full stem.
    """
    stem = path.stem  # e.g. 'Batch_FR_Debug__09-02_12-09'
    if "__" in stem:
        return stem.split("__", 1)[0]
    return stem


def _group_logs_by_base(root: Path) -> Dict[str, List[Tuple[Path, datetime]]]:
    """
    Scan `root` and group allowed log files by base name.

    Returns:
        dict[base_name] -> list of (path, mtime)
    """
    groups: Dict[str, List[Tuple[Path, datetime]]] = {}

    for file_path in _iter_files_recursive(root):
        if not _is_allowed_log_file(file_path):
            continue

        mtime = _get_mtime(file_path)
        if mtime is None:
            continue

        base = _base_name_for_log(file_path)
        groups.setdefault(base, []).append((file_path, mtime))

    return groups


def delete_old_anki_log_files(
    base_dir: Optional[Path | str] = None,
    max_files_per_base: Optional[int] = None,
    dry_run: bool = True,
) -> List[Path]:
    """
    Delete older log files based on count per base name, not just time.

    Logic:
    - Group log files by base name (stem before the first "__").
    - For each base:
        - Sort files by modification time (newest first).
        - Keep the newest `max_files_per_base` files.
        - Mark any remaining older files in that group for deletion.

    Safety:
    - Only deletes files with ALLOWED_SUFFIXES.
    - Refuses to run if root doesn't pass _is_safe_root.
    - DRY RUN by default (dry_run=True).

    Parameters
    ----------
    base_dir:
        Root directory to clean. If None, uses LOGS_ROOT.
    max_files_per_base:
        Maximum number of files to keep per base. If None, uses MAX_FILES_PER_BASE.
    dry_run:
        If True, does not delete anything; just returns list of files that
        *would* be deleted.

    Returns
    -------
    deleted_files:
        List of Path objects for files actually deleted (or would be deleted if dry_run=True).
    """
    root = Path(base_dir) if base_dir is not None else LOGS_ROOT
    root = root.expanduser().resolve()
    limit = max_files_per_base if max_files_per_base is not None else MAX_FILES_PER_BASE

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

    groups = _group_logs_by_base(root)

    for base, items in groups.items():
        # items: list[(path, mtime)]
        # * Sort newest-first by mtime
        items.sort(key=lambda t: t[1], reverse=True)

        # * Files to keep: first `limit` entries
        keep = items[:limit]
        to_delete = items[limit:]

        if not to_delete:
            continue

        for file_path, _mtime in to_delete:
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
    print(f"[{timestamp}] DRY RUN – inspecting Anki logs in: {LOGS_ROOT}")

    deleted_files = delete_old_anki_log_files(dry_run=True)

    if not deleted_files:
        print("No files would be deleted (either under limit per base, or no logs found).")
    else:
        print(f"{len(deleted_files)} file(s) would be deleted:")
        for p in deleted_files:
            print(f"  - {p}")

        print(
            "\nIf this list looks correct, call "
            "`delete_old_anki_log_files(dry_run=False)` from Python, "
            "or temporarily change dry_run to False in the __main__ block."
        )