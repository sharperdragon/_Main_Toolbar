from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_anki_import_stubs() -> None:
    aqt_mod = types.ModuleType("aqt")
    aqt_mod.mw = object()

    aqt_qt_mod = types.ModuleType("aqt.qt")

    class QMessageBox:  # pragma: no cover - simple import stub
        pass

    aqt_qt_mod.QMessageBox = QMessageBox
    aqt_mod.qt = aqt_qt_mod

    anki_mod = types.ModuleType("anki")
    anki_collection_mod = types.ModuleType("anki.collection")

    class Collection:  # pragma: no cover - simple import stub
        pass

    anki_collection_mod.Collection = Collection

    anki_errors_mod = types.ModuleType("anki.errors")

    class SearchError(Exception):
        pass

    anki_errors_mod.SearchError = SearchError
    anki_mod.collection = anki_collection_mod
    anki_mod.errors = anki_errors_mod

    sys.modules["aqt"] = aqt_mod
    sys.modules["aqt.qt"] = aqt_qt_mod
    sys.modules["anki"] = anki_mod
    sys.modules["anki.collection"] = anki_collection_mod
    sys.modules["anki.errors"] = anki_errors_mod


class TagAddConfigSharedHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._saved_modules = {
            name: sys.modules.get(name)
            for name in (
                "aqt",
                "aqt.qt",
                "anki",
                "anki.collection",
                "anki.errors",
            )
        }
        _install_anki_import_stubs()
        add_tags_path = REPO_ROOT / "modules" / "tag_updates" / "add_tags.py"
        spec = importlib.util.spec_from_file_location(
            "tag_add_tags_test_module",
            add_tags_path,
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        cls.mod = module

    @classmethod
    def tearDownClass(cls) -> None:
        for name, original in cls._saved_modules.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original

    def test_valid_global_config_values_are_used(self) -> None:
        cfg = {
            "global_config": {
                "log_dir": "~/Desktop/custom_tag_logs",
                "ts_format": "%Y-%m-%d",
            }
        }
        with patch.object(self.mod, "load_modules_config", return_value=cfg):
            with patch.object(self.mod, "validate_modules_config", return_value=[]):
                with patch.object(self.mod, "emit_config_warnings", return_value=[]):
                    log_dir = self.mod._get_global_log_dir()
                    ts_format = self.mod._get_ts_format()

        self.assertTrue(str(log_dir).endswith("custom_tag_logs"))
        self.assertEqual(ts_format, "%Y-%m-%d")

    def test_invalid_global_config_values_fall_back_to_defaults(self) -> None:
        cfg = {"global_config": {"log_dir": 123, "ts_format": None}}
        with patch.object(self.mod, "load_modules_config", return_value=cfg):
            with patch.object(self.mod, "validate_modules_config", return_value=[]):
                with patch.object(self.mod, "emit_config_warnings", return_value=[]):
                    log_dir = self.mod._get_global_log_dir()
                    ts_format = self.mod._get_ts_format()

        self.assertEqual(
            Path(log_dir).expanduser().resolve(),
            self.mod.DEFAULT_LOG_DIR.expanduser().resolve(),
        )
        self.assertEqual(ts_format, self.mod.DEFAULT_TS_FORMAT)

    def test_missing_global_config_values_fall_back_to_defaults(self) -> None:
        cfg = {}
        with patch.object(self.mod, "load_modules_config", return_value=cfg):
            with patch.object(self.mod, "validate_modules_config", return_value=[]):
                with patch.object(self.mod, "emit_config_warnings", return_value=[]):
                    log_dir = self.mod._get_global_log_dir()
                    ts_format = self.mod._get_ts_format()

        self.assertEqual(
            Path(log_dir).expanduser().resolve(),
            self.mod.DEFAULT_LOG_DIR.expanduser().resolve(),
        )
        self.assertEqual(ts_format, self.mod.DEFAULT_TS_FORMAT)

    def test_validation_and_warning_emit_are_called_with_loaded_config(self) -> None:
        cfg = {"global_config": {"log_dir": "~/Desktop/check"}}
        with patch.object(self.mod, "load_modules_config", return_value=cfg):
            with patch.object(self.mod, "validate_modules_config", return_value=["warn"]) as validate_mock:
                with patch.object(self.mod, "emit_config_warnings", return_value=["warn"]) as emit_mock:
                    _ = self.mod._get_global_log_dir()

        validate_mock.assert_called_once_with(cfg)
        emit_mock.assert_called_once_with(["warn"], cfg)


if __name__ == "__main__":
    unittest.main()
