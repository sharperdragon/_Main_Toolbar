from __future__ import annotations

import importlib
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

health_check = importlib.import_module("run_config_health_check")


class ConfigHealthCheckScriptTests(unittest.TestCase):
    def test_main_reports_warning_summary_without_failing_by_default(self) -> None:
        cfg = {
            "global_config": {"log_dir": "~/Desktop/anki_logs/Main_toolbar"},
            "missing_media_config": {},
            "unused_media_config": {},
        }
        out = io.StringIO()
        with patch.object(health_check.module_config, "load_modules_config", return_value=cfg):
            with patch.object(
                health_check.module_config,
                "validate_modules_config",
                return_value=["warning one", "warning two"],
            ):
                with patch.object(
                    health_check.module_config,
                    "emit_config_warnings",
                    return_value=["warning one", "warning two"],
                ):
                    with redirect_stdout(out):
                        rc = health_check.main(health_check.CONFIG_PATH)

        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("Top-level sections: 3", text)
        self.assertIn("Warning count: 2", text)
        self.assertIn("warning one", text)
        self.assertIn("warning two", text)

    def test_main_can_fail_on_warnings_when_enabled(self) -> None:
        cfg = {"global_config": {}}
        out = io.StringIO()
        with patch.object(health_check.module_config, "load_modules_config", return_value=cfg):
            with patch.object(
                health_check.module_config,
                "validate_modules_config",
                return_value=["warning one"],
            ):
                with patch.object(
                    health_check.module_config,
                    "emit_config_warnings",
                    return_value=["warning one"],
                ):
                    with patch.object(health_check, "FAIL_ON_WARNINGS", True):
                        with redirect_stdout(out):
                            rc = health_check.main(health_check.CONFIG_PATH)

        self.assertEqual(rc, 1)

    def test_main_returns_error_code_2_on_unrecoverable_exception(self) -> None:
        out = io.StringIO()
        with patch.object(
            health_check.module_config,
            "load_modules_config",
            side_effect=RuntimeError("boom"),
        ):
            with redirect_stdout(out):
                rc = health_check.main(health_check.CONFIG_PATH)

        self.assertEqual(rc, 2)
        self.assertIn("ERROR: boom", out.getvalue())


if __name__ == "__main__":
    unittest.main()
