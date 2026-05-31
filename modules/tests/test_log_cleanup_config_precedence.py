from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import modules.log_cleanup as log_cleanup  # noqa: E402


class LogCleanupConfigTests(unittest.TestCase):
    def test_runtime_settings_precedence(self) -> None:
        cfg = {
            "global_config": {
                "log_dir": "~/Desktop/global_logs",
                "ts_format": "%Y-%m-%d",
            },
            "log_cleanup_config": {
                "logs_root": "~/Desktop/cleanup_logs",
                "allowed_suffixes": ["txt", ".md"],
                "safe_root_marker": "cleanup_logs",
                "keep_runs": 7,
            },
        }
        with patch.object(log_cleanup, "load_modules_config", return_value=cfg):
            settings = log_cleanup._build_runtime_settings()

        self.assertTrue(str(settings["logs_root"]).endswith("cleanup_logs"))
        self.assertEqual(settings["allowed_suffixes"], {".txt", ".md"})
        self.assertEqual(settings["safe_root_marker"], "cleanup_logs")
        self.assertEqual(settings["keep_runs"], 7)
        self.assertEqual(settings["timestamp_fmt"], "%Y-%m-%d")

    def test_runtime_settings_fallback_to_global_and_default(self) -> None:
        cfg_global_only = {"global_config": {"log_dir": "~/Desktop/from_global"}}
        with patch.object(log_cleanup, "load_modules_config", return_value=cfg_global_only):
            settings = log_cleanup._build_runtime_settings()
        self.assertTrue(str(settings["logs_root"]).endswith("from_global"))

        cfg_invalid_logs_root = {
            "global_config": {"log_dir": "~/Desktop/from_global"},
            "log_cleanup_config": {"logs_root": 123},
        }
        with patch.object(log_cleanup, "load_modules_config", return_value=cfg_invalid_logs_root):
            settings = log_cleanup._build_runtime_settings()
        self.assertTrue(str(settings["logs_root"]).endswith("from_global"))

        cfg_missing = {}
        with patch.object(log_cleanup, "load_modules_config", return_value=cfg_missing):
            settings = log_cleanup._build_runtime_settings()
        self.assertEqual(
            Path(str(settings["logs_root"])).expanduser().resolve(),
            Path(log_cleanup.DEFAULT_LOGS_ROOT).expanduser().resolve(),
        )

    def test_safe_root_marker_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            safe_root = tmp / "anki_logs" / "main_toolbar"
            safe_root.mkdir(parents=True, exist_ok=True)

            unsafe_root = tmp / "other" / "main_toolbar"
            unsafe_root.mkdir(parents=True, exist_ok=True)

            marker_before = log_cleanup.SAFE_ROOT_MARKER
            try:
                log_cleanup.SAFE_ROOT_MARKER = "anki_logs"
                self.assertTrue(log_cleanup._is_safe_root(safe_root))
                self.assertFalse(log_cleanup._is_safe_root(unsafe_root))
            finally:
                log_cleanup.SAFE_ROOT_MARKER = marker_before

    def test_keep_runs_behavior_for_stamped_logs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "anki_logs" / "tool"
            root.mkdir(parents=True, exist_ok=True)

            old_a = root / "A__09-00_01-01.log"
            old_b = root / "B__10-00_01-01.log"
            newest = root / "C__11-00_01-02.log"
            no_stamp = root / "nostamp.log"

            old_a.write_text("a", encoding="utf-8")
            old_b.write_text("b", encoding="utf-8")
            newest.write_text("c", encoding="utf-8")
            no_stamp.write_text("x", encoding="utf-8")

            would_delete = log_cleanup.delete_old_anki_log_files(
                base_dir=root,
                dry_run=True,
                keep_runs=1,
            )
            would_delete_set = {p.name for p in would_delete}

            self.assertIn(old_a.name, would_delete_set)
            self.assertIn(old_b.name, would_delete_set)
            self.assertNotIn(newest.name, would_delete_set)
            self.assertNotIn(no_stamp.name, would_delete_set)

    def test_run_stamp_to_dt_handles_year_boundary_without_yearless_strptime(self) -> None:
        with patch.object(log_cleanup, "_now", return_value=datetime(2026, 1, 1, 8, 0)):
            dt = log_cleanup._run_stamp_to_dt("23-59_12-31")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2025)
        self.assertEqual((dt.month, dt.day, dt.hour, dt.minute), (12, 31, 23, 59))

    def test_run_stamp_to_dt_supports_leap_day_in_non_leap_current_year(self) -> None:
        with patch.object(log_cleanup, "_now", return_value=datetime(2026, 3, 1, 9, 0)):
            dt = log_cleanup._run_stamp_to_dt("12-00_02-29")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2024)
        self.assertEqual((dt.month, dt.day, dt.hour, dt.minute), (2, 29, 12, 0))


if __name__ == "__main__":
    unittest.main()
