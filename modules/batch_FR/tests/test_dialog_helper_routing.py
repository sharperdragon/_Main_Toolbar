from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def _clear_batch_fr_modules() -> None:
    for name in list(sys.modules.keys()):
        if name == "modules.batch_FR" or name.startswith("modules.batch_FR."):
            sys.modules.pop(name, None)


def _import_dialog_helper_module():
    _clear_batch_fr_modules()

    batch_fr_dir = REPO_ROOT / "modules" / "batch_FR"
    modules_dir = batch_fr_dir.parent
    gui_dir = batch_fr_dir / "gui"
    utils_dir = batch_fr_dir / "utils"

    pkg_modules = sys.modules.get("modules")
    if pkg_modules is None:
        pkg_modules = types.ModuleType("modules")
        pkg_modules.__path__ = [str(modules_dir)]  # type: ignore[attr-defined]
        sys.modules["modules"] = pkg_modules

    pkg_batch = types.ModuleType("modules.batch_FR")
    pkg_batch.__path__ = [str(batch_fr_dir)]  # type: ignore[attr-defined]
    sys.modules["modules.batch_FR"] = pkg_batch

    pkg_gui = types.ModuleType("modules.batch_FR.gui")
    pkg_gui.__path__ = [str(gui_dir)]  # type: ignore[attr-defined]
    sys.modules["modules.batch_FR.gui"] = pkg_gui

    pkg_utils = types.ModuleType("modules.batch_FR.utils")
    pkg_utils.__path__ = [str(utils_dir)]  # type: ignore[attr-defined]
    sys.modules["modules.batch_FR.utils"] = pkg_utils

    return importlib.import_module("modules.batch_FR.gui.dialog_helper")


class BatchFrDialogHelperRoutingTests(unittest.TestCase):
    def test_execute_payload_routes_selection_via_rules_files(self) -> None:
        helper = _import_dialog_helper_module()
        captured: dict = {}

        orig_runner = helper.run_batch_find_replace
        try:
            def _fake_runner(mw_ref, **kwargs):
                captured.update(kwargs)
                return {"ok": True}

            helper.run_batch_find_replace = _fake_runner

            payload = {
                "files": ["foo_remove_rules.txt"],
                "dry_run": False,
            }
            report = helper.execute_batch_fr_from_payload(
                payload,
                mw_ref=object(),
                config_snapshot={"batch_FR_config": {}},
            )

            self.assertEqual(report, {"ok": True})
            self.assertEqual(captured.get("rules_files"), ["foo_remove_rules.txt"])
            self.assertEqual(captured.get("rulesets"), [])
            self.assertFalse(bool(captured.get("dry_run")))
        finally:
            helper.run_batch_find_replace = orig_runner


if __name__ == "__main__":
    unittest.main()
