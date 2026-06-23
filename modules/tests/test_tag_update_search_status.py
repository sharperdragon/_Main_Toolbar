from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
TAG_UPDATES_DIR = REPO_ROOT / "modules" / "tag_updates"


def _install_anki_import_stubs() -> None:
    aqt_mod = types.ModuleType("aqt")
    aqt_mod.mw = object()

    aqt_qt_mod = types.ModuleType("aqt.qt")

    class QMessageBox:  # pragma: no cover - import stub
        pass

    aqt_qt_mod.QMessageBox = QMessageBox
    aqt_mod.qt = aqt_qt_mod

    aqt_operations_mod = types.ModuleType("aqt.operations")

    class CollectionOp:  # pragma: no cover - import stub
        pass

    class QueryOp:  # pragma: no cover - import stub
        pass

    aqt_operations_mod.CollectionOp = CollectionOp
    aqt_operations_mod.QueryOp = QueryOp

    anki_mod = types.ModuleType("anki")
    anki_collection_mod = types.ModuleType("anki.collection")

    class Collection:  # pragma: no cover - import stub
        pass

    class OpChanges:  # pragma: no cover - import stub
        pass

    anki_collection_mod.Collection = Collection
    anki_collection_mod.OpChanges = OpChanges

    anki_errors_mod = types.ModuleType("anki.errors")

    class SearchError(Exception):
        pass

    anki_errors_mod.SearchError = SearchError
    anki_mod.collection = anki_collection_mod
    anki_mod.errors = anki_errors_mod

    sys.modules["aqt"] = aqt_mod
    sys.modules["aqt.qt"] = aqt_qt_mod
    sys.modules["aqt.operations"] = aqt_operations_mod
    sys.modules["anki"] = anki_mod
    sys.modules["anki.collection"] = anki_collection_mod
    sys.modules["anki.errors"] = anki_errors_mod


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeNote:
    def __init__(self, tags: list[str] | None = None) -> None:
        self.tags = tags or []

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)


class FakeTags:
    def __init__(self) -> None:
        self.rename_calls: list[tuple[str, str]] = []

    def rename(self, old: str, new: str) -> None:
        self.rename_calls.append((old, new))

    def clear_unused_tags(self) -> None:
        pass


class FakeDb:
    def __init__(self, rows: list[tuple[int, str]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def all(self, query: str, *args: object) -> list[tuple[int, str]]:
        self.calls.append((query, args))
        return list(self.rows)


class FakeCollection:
    def __init__(
        self,
        note_ids: list[int] | None = None,
        error: Exception | None = None,
        note_tags_by_id: dict[int, list[str]] | None = None,
        db: FakeDb | None = None,
    ) -> None:
        self.note_ids = note_ids or []
        self.error = error
        self.queries: list[str] = []
        note_ids_for_notes = set(self.note_ids)
        note_ids_for_notes.update((note_tags_by_id or {}).keys())
        self.notes = {
            nid: FakeNote((note_tags_by_id or {}).get(nid, []))
            for nid in note_ids_for_notes
        }
        self.updated_notes: list[int] = []
        self.tags = FakeTags()
        self.db = db

    def find_notes(self, query: str) -> list[int]:
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        return list(self.note_ids)

    def get_note(self, nid: int) -> FakeNote:
        return self.notes[nid]

    def update_note(self, note: FakeNote) -> None:
        for nid, candidate in self.notes.items():
            if candidate is note:
                self.updated_notes.append(nid)
                return


class TagUpdateSearchStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._saved_modules = {
            name: sys.modules.get(name)
            for name in (
                "aqt",
                "aqt.qt",
                "aqt.operations",
                "anki",
                "anki.collection",
                "anki.errors",
            )
        }
        _install_anki_import_stubs()

        cls.pkg_name = "tag_updates_search_testpkg"
        pkg = types.ModuleType(cls.pkg_name)
        pkg.__path__ = [str(TAG_UPDATES_DIR)]
        sys.modules[cls.pkg_name] = pkg

        cls.data = _load_module(
            f"{cls.pkg_name}.data",
            TAG_UPDATES_DIR / "data.py",
        )
        cls.utils = _load_module(
            f"{cls.pkg_name}.tag_rename_utils",
            TAG_UPDATES_DIR / "tag_rename_utils.py",
        )
        cls.tr_main = _load_module(
            f"{cls.pkg_name}.TR_main",
            TAG_UPDATES_DIR / "TR_main.py",
        )
        cls.add_tags = _load_module(
            f"{cls.pkg_name}.add_tags",
            TAG_UPDATES_DIR / "add_tags.py",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        for name in list(sys.modules):
            if name == cls.pkg_name or name.startswith(f"{cls.pkg_name}."):
                sys.modules.pop(name, None)
        for name, original in cls._saved_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original

    def test_escape_anki_tag_re_escapes_hierarchical_colons(self) -> None:
        raw = r"^\#AK_Other::Card_Features::\^One_By_One(::|$)"
        expected = r"^\#AK_Other\:\:Card_Features\:\:\^One_By_One(\:\:|$)"

        self.assertEqual(self.utils.escape_anki_tag_re(raw), expected)

    def test_escape_anki_tag_re_keeps_non_capturing_group_syntax(self) -> None:
        raw = r"^(?:.*::)?#AK_Other(::|$)"
        expected = r"^(?:.*\:\:)?#AK_Other(\:\:|$)"

        self.assertEqual(self.utils.escape_anki_tag_re(raw), expected)

    def test_add_tag_simple_path_builds_safe_tag_regex_query(self) -> None:
        rule = self.add_tags.TagAddRule(
            name="one by one",
            query=r"#AK_Other::Card_Features::\^One_By_One",
            add_tags=["1-by-1"],
            source_file=Path("main_tagging.json"),
        )
        col = FakeCollection(note_ids=[1, 2])

        stats = self.add_tags._apply_rules_to_collection(col, [rule], dry_run=True)

        expected_query = r"tag:re:^\#AK_Other\:\:Card_Features\:\:\^One_By_One(\:\:|$)"
        self.assertEqual(col.queries, [expected_query])
        self.assertEqual(stats.rules[0].search_status, "ok")
        self.assertEqual(stats.rules[0].notes_matched, 2)
        self.assertEqual(stats.rules[0].anki_query, expected_query)

    def test_add_tag_search_error_is_not_counted_as_zero_match(self) -> None:
        rule = self.add_tags.TagAddRule(
            name="bad query",
            query=r"#AK_Other::Card_Features::\^One_By_One",
            add_tags=["1-by-1"],
            source_file=Path("main_tagging.json"),
        )
        col = FakeCollection(error=RuntimeError("colon parse error"))

        with patch.object(self.add_tags, "_log_search_error"):
            stats = self.add_tags._apply_rules_to_collection(col, [rule], dry_run=True)

        self.assertEqual(stats.total_notes_matched, 0)
        self.assertEqual(stats.total_search_errors, 1)
        self.assertEqual(stats.rules[0].search_status, "error")
        self.assertIsNone(stats.rules[0].notes_matched)
        self.assertIn("colon parse error", stats.rules[0].error_message or "")

    def test_rename_dry_run_search_error_reports_not_tested(self) -> None:
        pair = self.data.Pair(
            old="#AK_Other::Card_Features::^One_By_One",
            new="#Zank::#Useful::One_By_One",
        )
        col = FakeCollection(error=RuntimeError("colon parse error"))

        outcome = self.tr_main._execute(col, [pair], dry_run=True)

        self.assertEqual(len(outcome.applied), 1)
        result = outcome.applied[0]
        self.assertEqual(result.search_status, "error")
        self.assertIsNone(result.matched_notes)
        self.assertIn(r"\:\:", result.anki_query)
        self.assertIn("colon parse error", result.error_message or "")

    def test_rename_dry_run_zero_match_remains_ok_status(self) -> None:
        pair = self.data.Pair(
            old="#AK_Other::Missing",
            new="#Zank::Other::Missing",
        )
        col = FakeCollection(note_ids=[])

        outcome = self.tr_main._execute(col, [pair], dry_run=True)

        result = outcome.applied[0]
        self.assertEqual(result.search_status, "ok")
        self.assertEqual(result.matched_notes, 0)
        self.assertIsNone(result.error_message)

    def test_step1_broad_parent_rename_is_phase_one(self) -> None:
        pair = self.data.Pair(
            old="#AK_Step1_v12",
            new="#Zank::Step1_v12",
        )

        self.assertEqual(self.tr_main._rename_phase(pair), 10)

    def test_live_rename_uses_per_note_fallback_by_default(self) -> None:
        old = "#AK_Other::Card_Features::Histology"
        new = "#Zank::#Useful::Histology"
        pair = self.data.Pair(old=old, new=new)
        col = FakeCollection(
            note_ids=[1],
            note_tags_by_id={
                1: [
                    old,
                    f"{old}::Subtag",
                    "Unrelated",
                ],
            },
        )

        outcome = self.tr_main._execute(col, [pair], dry_run=False)

        self.assertEqual(outcome.total_notes_changed, 1)
        self.assertEqual(outcome.applied[0].mode, "fallback")
        self.assertEqual(col.tags.rename_calls, [])
        self.assertEqual(
            col.notes[1].tags,
            [
                new,
                f"{new}::Subtag",
                "Unrelated",
            ],
        )
        self.assertEqual(col.updated_notes, [1])

    def test_live_rename_uses_note_table_when_browser_search_finds_nothing(self) -> None:
        old = "#AK_Step1_v12"
        new = "#Zank::Step1_v12"
        pair = self.data.Pair(old=old, new=new)
        db = FakeDb(
            rows=[
                (1, f" {old} "),
                (2, f" {old}::#B&B::01_Anatomy "),
                (3, " Unrelated "),
                (4, f" {old.lower()} "),
            ]
        )
        col = FakeCollection(
            note_ids=[],
            db=db,
            note_tags_by_id={
                1: [old],
                2: [f"{old}::#B&B::01_Anatomy", "Unrelated"],
                4: [old.lower()],
            },
        )

        outcome = self.tr_main._execute(col, [pair], dry_run=False)

        self.assertEqual(col.queries, [])
        self.assertEqual(outcome.total_notes_changed, 2)
        self.assertEqual(outcome.applied[0].matched_notes, 2)
        self.assertEqual(col.notes[1].tags, [new])
        self.assertEqual(col.notes[2].tags, [f"{new}::#B&B::01_Anatomy", "Unrelated"])
        self.assertEqual(col.notes[4].tags, [old.lower()])
        self.assertEqual(col.updated_notes, [1, 2])
        self.assertEqual(db.calls[0][1], (r"% #AK\_Step1\_v12 %", r"% #AK\_Step1\_v12::%"))


if __name__ == "__main__":
    unittest.main()
