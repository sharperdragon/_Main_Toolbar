from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.get_missing_media import (  # noqa: E402
    DEFAULT_OUTPUT_DIR,
    DEFAULT_TAG_FILTER_ENABLED,
    _build_run_message,
    _build_runtime_settings,
    _collect_used_media,
    _compute_missing_media,
    _escape_like_literal,
    _export_missing_media_for_collection,
    _extract_media_refs,
    _query_note_rows,
    _resolve_output_paths,
)


class _FakeDB:
    def __init__(self, rows: list[tuple[str]] | None = None) -> None:
        self.rows = rows or []
        self.last_query: str | None = None
        self.last_params: tuple[object, ...] = ()

    def all(self, query: str, *params: object) -> list[tuple[str]]:
        self.last_query = query
        self.last_params = params
        return self.rows


class _FakeMedia:
    def __init__(self, media_dir: Path) -> None:
        self._media_dir = media_dir

    def dir(self) -> str:
        return str(self._media_dir)


class _FakeCollection:
    def __init__(self, db: _FakeDB, media_dir: Path) -> None:
        self.db = db
        self.media = _FakeMedia(media_dir)


class GetMissingMediaTests(unittest.TestCase):
    def test_extract_media_refs_decodes_and_filters_extensions(self) -> None:
        text = (
            '<img src="folder/foo%20bar.jpg?x=1#frag">'
            '<img src="folder/keep.mp3">'
            '<img src="folder/skip.txt">'
        )
        refs = _extract_media_refs(text, {".jpg", ".mp3"})
        self.assertEqual(refs, {"foo bar.jpg", "keep.mp3"})

    def test_extract_media_refs_supports_single_double_unquoted_and_ignores_remote(self) -> None:
        text = (
            "<IMG SRC='folder/Foo%20Bar.jpg?x=1#frag'>"
            "<img src=folder/keep.mp3>"
            '<img src="https://example.com/remote.png">'
            "<img src=//cdn.example.com/remote2.jpg>"
            "<img src='folder/skip.txt'>"
        )
        refs = _extract_media_refs(text, {".jpg", ".mp3", ".png"})
        self.assertEqual(refs, {"Foo Bar.jpg", "keep.mp3"})

    def test_collect_used_media_reads_note_rows(self) -> None:
        rows = [
            ('<img src="a.png">\x1f<img src="b.jpg">',),
            ('<img src="c.gif">',),
        ]
        used = _collect_used_media(rows, {".png", ".jpg", ".gif"})
        self.assertEqual(used, {"a.png", "b.jpg", "c.gif"})

    def test_compute_missing_media(self) -> None:
        missing = _compute_missing_media(
            used={"a.png", "b.png", "c.png"},
            existing={"a.png"},
        )
        self.assertEqual(missing, ["b.png", "c.png"])

    def test_runtime_settings_and_output_paths(self) -> None:
        cfg = {
            "missing_media_config": {
                "tag_filter_enabled": False,
                "tag_name": "my-tag",
                "media_extensions": ["jpg", ".mp4"],
                "output_dir": "exports/missing",
                "backup_dir": "exports/backup",
            }
        }
        settings = _build_runtime_settings(cfg)
        self.assertFalse(settings["tag_filter_enabled"])
        self.assertEqual(settings["tag_name"], "my-tag")
        self.assertEqual(settings["media_extensions"], {".jpg", ".mp4"})

        output_path, backup_path = _resolve_output_paths(
            profile_name="User 1",
            output_dir=Path(str(settings["output_dir"])),
            backup_dir=Path(str(settings["backup_dir"])),
        )
        self.assertTrue(str(output_path).endswith("missing_media_User 1.txt"))
        self.assertTrue(str(backup_path).endswith("missing_media_User 1.txt"))

    def test_invalid_settings_fall_back_to_defaults(self) -> None:
        cfg = {
            "missing_media_config": {
                "tag_filter_enabled": "false",
                "output_dir": 999,
            }
        }
        settings = _build_runtime_settings(cfg)
        self.assertEqual(settings["tag_filter_enabled"], DEFAULT_TAG_FILTER_ENABLED)
        self.assertEqual(
            Path(str(settings["output_dir"])).expanduser().resolve(),
            DEFAULT_OUTPUT_DIR.expanduser().resolve(),
        )

    def test_query_note_rows_escapes_like_special_chars(self) -> None:
        db = _FakeDB(rows=[])
        with tempfile.TemporaryDirectory() as td:
            col = _FakeCollection(db=db, media_dir=Path(td))
            tag = r"my_tag%50\done"
            _query_note_rows(col, tag)

        self.assertIsNotNone(db.last_query)
        assert db.last_query is not None
        self.assertIn("ESCAPE '\\'", db.last_query)
        expected_pat = f"% {_escape_like_literal(tag)} %"
        self.assertEqual(db.last_params, (expected_pat,))

    def test_query_note_rows_without_tag_uses_full_scan(self) -> None:
        db = _FakeDB(rows=[])
        with tempfile.TemporaryDirectory() as td:
            col = _FakeCollection(db=db, media_dir=Path(td))
            _query_note_rows(col, None)
        self.assertEqual(db.last_query, "SELECT flds FROM notes")
        self.assertEqual(db.last_params, ())

    def test_export_missing_media_returns_write_statuses(self) -> None:
        db = _FakeDB(rows=[('<img src="x.png">',)])
        with tempfile.TemporaryDirectory() as td:
            media_dir = Path(td) / "media"
            media_dir.mkdir(parents=True, exist_ok=True)
            col = _FakeCollection(db=db, media_dir=media_dir)
            settings = _build_runtime_settings(
                {
                    "missing_media_config": {
                        "tag_filter_enabled": False,
                        "output_dir": str(Path(td) / "out"),
                        "backup_dir": str(Path(td) / "backup"),
                        "media_extensions": [".png"],
                    }
                }
            )
            with patch(
                "modules.get_missing_media._write_name_list_safe",
                side_effect=[(True, None), (False, "no write")],
            ):
                result = _export_missing_media_for_collection(
                    col=col,
                    profile_name="User 1",
                    settings=settings,
                )
        self.assertTrue(result["primary_write_ok"])
        self.assertFalse(result["backup_write_ok"])
        self.assertEqual(result["backup_error"], "no write")

    def test_build_run_message_when_both_writes_succeed(self) -> None:
        msg = _build_run_message(
            scope_text="all notes",
            missing_count=2,
            output_path=Path("/tmp/out.txt"),
            backup_path=Path("/tmp/backup.txt"),
            primary_write_ok=True,
            backup_write_ok=True,
        )
        self.assertIn("✅ Missing media check complete", msg)
        self.assertIn("saved to", msg)

    def test_build_run_message_when_backup_fails(self) -> None:
        msg = _build_run_message(
            scope_text="all notes",
            missing_count=2,
            output_path=Path("/tmp/out.txt"),
            backup_path=Path("/tmp/backup.txt"),
            primary_write_ok=True,
            backup_write_ok=False,
            backup_error="permission denied",
        )
        self.assertIn("⚠️ Missing media check completed with partial output", msg)
        self.assertIn("Backup write failed", msg)

    def test_build_run_message_when_primary_fails(self) -> None:
        msg = _build_run_message(
            scope_text="all notes",
            missing_count=2,
            output_path=Path("/tmp/out.txt"),
            backup_path=Path("/tmp/backup.txt"),
            primary_write_ok=False,
            backup_write_ok=True,
            primary_error="permission denied",
        )
        self.assertIn("⚠️ Missing media check completed with partial output", msg)
        self.assertIn("Primary write failed", msg)

    def test_build_run_message_when_both_writes_fail(self) -> None:
        msg = _build_run_message(
            scope_text="all notes",
            missing_count=2,
            output_path=Path("/tmp/out.txt"),
            backup_path=Path("/tmp/backup.txt"),
            primary_write_ok=False,
            backup_write_ok=False,
            primary_error="a",
            backup_error="b",
        )
        self.assertIn("❌ Missing media check failed", msg)
        self.assertNotIn("✅ Missing media check complete", msg)


if __name__ == "__main__":
    unittest.main()
