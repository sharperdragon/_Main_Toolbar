from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.IMG_dupes import (  # noqa: E402
    _dedupe_img_tags_in_html,
    _process_notes_for_dupes,
    _report_completion,
    _write_backup_if_needed,
)


class _FakeNote(dict):
    def __init__(self, **fields: str) -> None:
        super().__init__(fields)
        self.flush_calls = 0

    def flush(self) -> None:
        self.flush_calls += 1


class _FakeCollection:
    def __init__(self, notes_by_id: dict[int, _FakeNote]) -> None:
        self._notes_by_id = notes_by_id

    def get_note(self, nid: int) -> _FakeNote:
        return self._notes_by_id[nid]


class ImgDupesHelperTests(unittest.TestCase):
    def test_dedupe_keeps_first_src_and_removes_later_duplicates(self) -> None:
        html = (
            '<div>before</div>'
            '<img src="a.png">'
            '<img src="a.png">'
            '<img src="b.png">'
            '<img src="a.png">'
        )
        updated, changed = _dedupe_img_tags_in_html(html)
        self.assertTrue(changed)
        self.assertEqual(updated.count('src="a.png"'), 1)
        self.assertEqual(updated.count('src="b.png"'), 1)

    def test_dedupe_noop_when_no_duplicates(self) -> None:
        html = '<img src="a.png"><img src="b.png">'
        updated, changed = _dedupe_img_tags_in_html(html)
        self.assertFalse(changed)
        self.assertEqual(updated, html)

    def test_backup_writes_only_when_count_exceeds_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            backup_path = Path(td) / "backup" / "dupes.txt"

            wrote = _write_backup_if_needed([1, 2], threshold=2, backup_path=backup_path)
            self.assertFalse(wrote)
            self.assertFalse(backup_path.exists())

            wrote = _write_backup_if_needed(
                [1, 2, 3], threshold=2, backup_path=backup_path
            )
            self.assertTrue(wrote)
            self.assertTrue(backup_path.exists())
            self.assertEqual(
                backup_path.read_text(encoding="utf-8"),
                "1\n2\n3",
            )

    def test_process_notes_preview_mode_reports_matches_without_mutating(self) -> None:
        note_with_dupes = _FakeNote(
            Text='<img src="a.png"><img src="a.png"><img src="b.png">'
        )
        unchanged_note = _FakeNote(Text='<img src="c.png"><img src="d.png">')
        col = _FakeCollection({1: note_with_dupes, 2: unchanged_note})

        changed = _process_notes_for_dupes(
            col=col,
            note_ids=[1, 2],
            target_fields=["Text"],
            dry_run=True,
        )

        self.assertEqual(changed, [1])
        self.assertEqual(note_with_dupes.flush_calls, 0)
        self.assertEqual(unchanged_note.flush_calls, 0)
        self.assertEqual(
            note_with_dupes["Text"],
            '<img src="a.png"><img src="a.png"><img src="b.png">',
        )

    def test_process_notes_apply_mode_mutates_and_flushes(self) -> None:
        note_with_dupes = _FakeNote(
            Text='<img src="a.png"><img src="a.png"><img src="b.png">'
        )
        col = _FakeCollection({1: note_with_dupes})

        changed = _process_notes_for_dupes(
            col=col,
            note_ids=[1],
            target_fields=["Text"],
            dry_run=False,
        )

        self.assertEqual(changed, [1])
        self.assertEqual(note_with_dupes.flush_calls, 1)
        self.assertEqual(note_with_dupes["Text"].count('src="a.png"'), 1)
        self.assertEqual(note_with_dupes["Text"].count('src="b.png"'), 1)

    def test_report_completion_preview_skips_backup_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            backup_path = Path(td) / "dupes.txt"
            with patch("modules.IMG_dupes._write_backup_if_needed") as backup_mock:
                with patch("modules.IMG_dupes.showInfo") as show_info_mock:
                    _report_completion(
                        changed_nids=[1, 2, 3],
                        dry_run=True,
                        backup_threshold=2,
                        backup_path=backup_path,
                    )

            backup_mock.assert_not_called()
            show_info_mock.assert_called_once()
            msg = show_info_mock.call_args.args[0]
            self.assertIn("3 notes would be cleaned", msg)
            self.assertIn("No changes were applied", msg)


if __name__ == "__main__":
    unittest.main()
