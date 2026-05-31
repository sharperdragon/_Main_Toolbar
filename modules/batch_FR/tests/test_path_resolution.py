from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from importlib import import_module
from pathlib import Path


def _bootstrap_utils_namespace() -> None:
    """Make `modules.batch_FR.utils.*` importable without importing Anki UI packages."""
    batch_fr_dir = Path(__file__).resolve().parents[1]
    modules_dir = batch_fr_dir.parent
    utils_dir = batch_fr_dir / "utils"

    pkg_modules = sys.modules.get("modules")
    if pkg_modules is None:
        pkg_modules = types.ModuleType("modules")
        pkg_modules.__path__ = [str(modules_dir)]  # type: ignore[attr-defined]
        sys.modules["modules"] = pkg_modules

    pkg_batch = sys.modules.get("modules.batch_FR")
    if pkg_batch is None:
        pkg_batch = types.ModuleType("modules.batch_FR")
        pkg_batch.__path__ = [str(batch_fr_dir)]  # type: ignore[attr-defined]
        sys.modules["modules.batch_FR"] = pkg_batch

    pkg_utils = sys.modules.get("modules.batch_FR.utils")
    if pkg_utils is None:
        pkg_utils = types.ModuleType("modules.batch_FR.utils")
        pkg_utils.__path__ = [str(utils_dir)]  # type: ignore[attr-defined]
        sys.modules["modules.batch_FR.utils"] = pkg_utils


_bootstrap_utils_namespace()

fr_globals = import_module("modules.batch_FR.utils.FR_global_utils")
rules_io = import_module("modules.batch_FR.utils.rules_io")
top_helper = import_module("modules.batch_FR.utils.top_helper")


class BatchFrPathResolutionTests(unittest.TestCase):
    def test_dynamic_constants_follow_repo_layout(self) -> None:
        expected_batch_fr_dir = Path(fr_globals.__file__).resolve().parents[1]
        expected_modules_dir = expected_batch_fr_dir.parent

        self.assertEqual(fr_globals.RULES_PATH, expected_batch_fr_dir / "rules")
        self.assertEqual(
            fr_globals.MODULES_CONFIG_PATH, expected_modules_dir / "modules_config.json"
        )
        self.assertEqual(
            fr_globals.FIELD_REMOVE_RULES_PATH,
            (expected_batch_fr_dir / "rules" / "field_remove_rules.txt"),
        )
        self.assertEqual(fr_globals.DESKTOP_PATH, Path.home() / "Desktop")

    def test_load_batch_fr_config_defaults_to_dynamic_rules_path_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_dir = Path(td)
            cfg_path = tmp_dir / "modules_config.json"
            payload = {
                "global_config": {
                    "log_dir": str(tmp_dir / "logs"),
                    "ts_format": "%H-%M_%m-%d",
                },
                "batch_FR_config": {},
            }
            cfg_path.write_text(json.dumps(payload), encoding="utf-8")

            snapshot = top_helper.load_batch_fr_config(cfg_path)
            self.assertEqual(
                Path(str(snapshot["rules_path"])).resolve(),
                Path(fr_globals.RULES_PATH).resolve(),
            )

    def test_load_batch_fr_config_resolves_relative_rules_path_against_config_dir(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_dir = Path(td)
            cfg_dir = tmp_dir / "nested"
            cfg_dir.mkdir(parents=True, exist_ok=True)

            rel_rules_path = Path("batch_FR") / "rules"
            cfg_path = cfg_dir / "modules_config.json"
            payload = {
                "global_config": {"log_dir": str(tmp_dir / "logs")},
                "batch_FR_config": {"rules_path": str(rel_rules_path)},
            }
            cfg_path.write_text(json.dumps(payload), encoding="utf-8")

            snapshot = top_helper.load_batch_fr_config(cfg_path)
            self.assertEqual(
                Path(str(snapshot["rules_path"])).resolve(),
                (cfg_dir / rel_rules_path).resolve(),
            )

    def test_resolve_rule_path_is_cwd_independent(self) -> None:
        expected_under_rules = Path(fr_globals.RULES_PATH) / "uno_remove_rules.txt"
        expected_main_rule = Path(fr_globals.RULES_PATH) / "Main" / "style-br_rules.json"

        self.assertTrue(expected_under_rules.exists())
        self.assertTrue(expected_main_rule.exists())

        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            try:
                resolved_batch_rel = rules_io.resolve_rule_path(
                    "batch_FR/rules/uno_remove_rules.txt"
                )
                resolved_modules_rel = rules_io.resolve_rule_path(
                    "modules/batch_FR/rules/uno_remove_rules.txt"
                )
                resolved_rules_root_rel = rules_io.resolve_rule_path(
                    "Main/style-br_rules.json"
                )
            finally:
                os.chdir(original_cwd)

        self.assertEqual(resolved_batch_rel, expected_under_rules.resolve())
        self.assertEqual(resolved_modules_rel, expected_under_rules.resolve())
        self.assertEqual(resolved_rules_root_rel, expected_main_rule.resolve())


if __name__ == "__main__":
    unittest.main()
