from __future__ import annotations

"""
Deprecated compatibility wrapper.

This file is kept for older imports and forwards to the active entrypoint in:
`modules/IMG_dupes/__init__.py`.
"""

from pathlib import Path


def run_img_dupes_script() -> None:
    """Forward to the active IMG dupes entrypoint."""
    try:
        from . import run_img_dupes_script as _active_run
    except Exception:
        import sys

        repo_root = Path(__file__).resolve().parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from modules.IMG_dupes import run_img_dupes_script as _active_run  # type: ignore
    _active_run()


if __name__ == "__main__":
    run_img_dupes_script()
