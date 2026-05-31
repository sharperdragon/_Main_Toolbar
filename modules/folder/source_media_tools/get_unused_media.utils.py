from __future__ import annotations

"""
Deprecated compatibility wrapper.

This file is kept for older imports and forwards to the active entrypoint in:
`modules/get_unused_media/__init__.py`.
"""

from pathlib import Path


def export_unused_media_to_txt(output_path: str = None) -> None:
    """Forward to the active unused-media exporter entrypoint."""
    try:
        from ...get_unused_media import export_unused_media_to_txt as _active_export
    except Exception:
        import sys

        repo_root = Path(__file__).resolve().parents[3]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from modules.get_unused_media import (  # type: ignore
            export_unused_media_to_txt as _active_export,
        )
    _active_export(output_path)


if __name__ == "__main__":
    export_unused_media_to_txt()
