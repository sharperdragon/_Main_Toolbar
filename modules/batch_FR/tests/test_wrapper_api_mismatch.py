from __future__ import annotations

import importlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _clear_batch_fr_modules() -> None:
    for name in list(sys.modules.keys()):
        if name == "modules.batch_FR" or name.startswith("modules.batch_FR."):
            sys.modules.pop(name, None)


def _import_batch_fr_wrapper_module():
    _clear_batch_fr_modules()

    # Stub only the UI dialog dependency so package import does not require aqt.qt.
    gui_pkg = types.ModuleType("modules.batch_FR.gui")
    gui_pkg.__path__ = []  # type: ignore[attr-defined]
    sys.modules["modules.batch_FR.gui"] = gui_pkg

    ui_stub = types.ModuleType("modules.batch_FR.gui.ui_dialog")
    ui_stub.prompt_batch_fr_run_options = lambda *args, **kwargs: None
    sys.modules["modules.batch_FR.gui.ui_dialog"] = ui_stub

    return importlib.import_module("modules.batch_FR")


def _import_engine_module():
    # Avoid importing modules.batch_FR.__init__ (which wires UI).
    batch_fr_dir = REPO_ROOT / "modules" / "batch_FR"
    modules_dir = batch_fr_dir.parent
    utils_dir = batch_fr_dir / "utils"

    pkg_modules = sys.modules.get("modules")
    if pkg_modules is None:
        pkg_modules = types.ModuleType("modules")
        pkg_modules.__path__ = [str(modules_dir)]  # type: ignore[attr-defined]
        sys.modules["modules"] = pkg_modules

    pkg_batch = types.ModuleType("modules.batch_FR")
    pkg_batch.__path__ = [str(batch_fr_dir)]  # type: ignore[attr-defined]
    sys.modules["modules.batch_FR"] = pkg_batch

    pkg_utils = types.ModuleType("modules.batch_FR.utils")
    pkg_utils.__path__ = [str(utils_dir)]  # type: ignore[attr-defined]
    sys.modules["modules.batch_FR.utils"] = pkg_utils

    return importlib.import_module("modules.batch_FR.utils.engine")


class _DummyCol:
    pass


class _DummyMw:
    def __init__(self) -> None:
        self.col = _DummyCol()


def _config_snapshot(log_dir: Path) -> dict:
    return {
        "global_config": {
            "log_dir": str(log_dir),
            "ts_format": "%H-%M_%m-%d",
        },
        "batch_FR_config": {
            "rules_path": "",
            "fields_all": ["Text"],
            "Defaults": {},
            "remove_config": {},
            "max_loops": 1,
        },
    }


class BatchFrWrapperApiMismatchTests(unittest.TestCase):
    def test_wrapper_forwards_field_remove_rules(self) -> None:
        wrapper = _import_batch_fr_wrapper_module()
        captured: dict = {}

        def _fake_impl(mw_ref, **kwargs):
            captured.update(kwargs)
            return {"ok": True}

        wrapper._impl_run_batch_find_replace = _fake_impl
        wrapper.load_batch_fr_config = lambda _path=None: {
            "rules_path": "",
            "fields_all": ["Text"],
            "remove_config": {},
        }

        wrapper.run_batch_find_replace(
            None,
            rulesets=[],
            field_remove_rules="field_remove_rules.txt",
        )

        self.assertIn("field_remove_rules", captured)
        self.assertEqual(captured["field_remove_rules"], "field_remove_rules.txt")

    def test_engine_field_remove_precedence_explicit_over_selected(self) -> None:
        engine = _import_engine_module()
        captured: list = []

        orig_remove_only = engine._run_remove_only_batch
        orig_maybe_write = engine._maybe_write_debug_logs
        try:
            def _fake_remove_only(*args, **kwargs):
                captured.append(kwargs.get("field_remove_rules"))
                return None

            engine._run_remove_only_batch = _fake_remove_only
            engine._maybe_write_debug_logs = lambda *args, **kwargs: None

            with tempfile.TemporaryDirectory() as td:
                report = engine.run_batch_find_replace(
                    mw_ref=_DummyMw(),
                    rulesets=[],
                    config_snapshot=_config_snapshot(Path(td)),
                    dry_run=True,
                    rules_files=["field_remove_rules.txt"],
                    field_remove_rules="explicit_field_remove_rules.txt",
                )

            self.assertTrue(isinstance(report, dict))
            self.assertEqual(len(captured), 1)
            self.assertEqual(
                Path(str(captured[0])).name, "explicit_field_remove_rules.txt"
            )
        finally:
            engine._run_remove_only_batch = orig_remove_only
            engine._maybe_write_debug_logs = orig_maybe_write

    def test_engine_field_remove_selected_when_only_ui_file_provided(self) -> None:
        engine = _import_engine_module()
        captured: list = []

        orig_remove_only = engine._run_remove_only_batch
        orig_maybe_write = engine._maybe_write_debug_logs
        try:
            def _fake_remove_only(*args, **kwargs):
                captured.append(kwargs.get("field_remove_rules"))
                return None

            engine._run_remove_only_batch = _fake_remove_only
            engine._maybe_write_debug_logs = lambda *args, **kwargs: None

            with tempfile.TemporaryDirectory() as td:
                report = engine.run_batch_find_replace(
                    mw_ref=_DummyMw(),
                    rulesets=[],
                    config_snapshot=_config_snapshot(Path(td)),
                    dry_run=True,
                    rules_files=["field_remove_rules.txt"],
                )

            self.assertTrue(isinstance(report, dict))
            self.assertEqual(len(captured), 1)
            self.assertEqual(Path(str(captured[0])).name, "field_remove_rules.txt")
        finally:
            engine._run_remove_only_batch = orig_remove_only
            engine._maybe_write_debug_logs = orig_maybe_write

    def test_engine_field_remove_none_when_not_explicit_or_selected(self) -> None:
        engine = _import_engine_module()
        captured: list = []

        orig_remove_only = engine._run_remove_only_batch
        orig_maybe_write = engine._maybe_write_debug_logs
        try:
            def _fake_remove_only(*args, **kwargs):
                captured.append(kwargs.get("field_remove_rules"))
                return None

            engine._run_remove_only_batch = _fake_remove_only
            engine._maybe_write_debug_logs = lambda *args, **kwargs: None

            with tempfile.TemporaryDirectory() as td:
                report = engine.run_batch_find_replace(
                    mw_ref=_DummyMw(),
                    rulesets=[],
                    config_snapshot=_config_snapshot(Path(td)),
                    dry_run=True,
                    remove_only_query="tag:test",
                )

            self.assertTrue(isinstance(report, dict))
            self.assertEqual(len(captured), 1)
            self.assertIsNone(captured[0])
        finally:
            engine._run_remove_only_batch = orig_remove_only
            engine._maybe_write_debug_logs = orig_maybe_write

    def test_engine_batch_only_snapshot_does_not_get_clobbered_by_disk(self) -> None:
        engine = _import_engine_module()

        orig_modules_dir = engine._modules_dir_from_engine
        try:
            with tempfile.TemporaryDirectory() as td:
                td_path = Path(td)
                modules_dir = td_path / "modules"
                modules_dir.mkdir(parents=True, exist_ok=True)

                cfg_path = modules_dir / "modules_config.json"
                cfg_path.write_text(
                    json.dumps(
                        {
                            "global_config": {
                                "log_dir": "/disk/logs",
                                "ts_format": "%H-%M_%m-%d",
                            },
                            "batch_FR_config": {
                                "rules_path": "disk/rules",
                                "fields_all": ["DiskField"],
                                "max_loops": 99,
                            },
                        }
                    ),
                    encoding="utf-8",
                )

                engine._modules_dir_from_engine = lambda: modules_dir

                caller_snapshot = {
                    "rules_path": "caller/rules",
                    "fields_all": ["CallerField"],
                    "max_loops": 5,
                }

                merged = engine._maybe_load_full_modules_config(
                    object(), caller_snapshot
                )

                self.assertEqual(merged.get("rules_path"), "caller/rules")
                self.assertEqual(merged.get("fields_all"), ["CallerField"])
                self.assertEqual(merged.get("max_loops"), 5)
                # Missing keys can still be backfilled from disk.
                self.assertEqual(merged.get("log_dir"), "/disk/logs")
                # Ensure caller snapshot itself is not mutated.
                self.assertEqual(caller_snapshot["rules_path"], "caller/rules")
        finally:
            engine._modules_dir_from_engine = orig_modules_dir


if __name__ == "__main__":
    unittest.main()
