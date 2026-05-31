from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules import module_config  # noqa: E402


class ModuleConfigTests(unittest.TestCase):
    def test_constants_follow_repo_layout(self) -> None:
        self.assertEqual(module_config.MODULES_DIR, REPO_ROOT / "modules")
        self.assertEqual(
            module_config.MODULES_CONFIG_PATH,
            REPO_ROOT / "modules" / "modules_config.json",
        )

    def test_load_modules_config_valid_invalid_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            good = tmp / "good.json"
            good.write_text(json.dumps({"global_config": {"log_dir": "x"}}), encoding="utf-8")
            self.assertIn("global_config", module_config.load_modules_config(good))

            bad = tmp / "bad.json"
            bad.write_text("{not-json", encoding="utf-8")
            self.assertEqual(module_config.load_modules_config(bad), {})

            missing = tmp / "missing.json"
            self.assertEqual(module_config.load_modules_config(missing), {})

    def test_get_global_and_section_are_defensive(self) -> None:
        cfg = {
            "global_config": {"log_dir": "~/Desktop/x"},
            "example_section": {"enabled": True},
            "bad_section": "not-a-dict",
        }
        self.assertEqual(
            module_config.get_global_config(cfg),
            {"log_dir": "~/Desktop/x"},
        )
        self.assertEqual(module_config.get_section("example_section", cfg), {"enabled": True})
        self.assertEqual(module_config.get_section("bad_section", cfg), {})
        self.assertEqual(module_config.get_section("missing", cfg), {})

    def test_resolve_path_handles_none_relative_absolute(self) -> None:
        fallback = Path("~/Desktop/fallback")
        self.assertEqual(
            module_config.resolve_path(None, fallback),
            fallback.expanduser().resolve(),
        )
        self.assertEqual(
            module_config.resolve_path(123, fallback),  # type: ignore[arg-type]
            fallback.expanduser().resolve(),
        )

        rel = module_config.resolve_path("logs/output", fallback)
        self.assertEqual(
            rel,
            (module_config.MODULES_DIR / "logs" / "output").resolve(),
        )

        with tempfile.TemporaryDirectory() as td:
            abs_path = Path(td) / "abs" / "path.txt"
            resolved = module_config.resolve_path(abs_path, fallback)
            self.assertEqual(resolved, abs_path.expanduser().resolve())

    def test_validate_modules_config_reports_schema_warnings(self) -> None:
        cfg = {
            "missing_media_config": {
                "tag_filter_enabled": "yes",
                "media_extensions": [".png", 123],
            },
            "unused_media_config": {"chunk_size": True},
            "img_dupes_config": {"backup_threshold": "45"},
            "log_cleanup_config": "bad-section",
        }
        warnings = module_config.validate_modules_config(cfg)
        joined = "\n".join(warnings)
        self.assertIn("missing_media_config.tag_filter_enabled", joined)
        self.assertIn("missing_media_config.media_extensions", joined)
        self.assertIn("unused_media_config.chunk_size", joined)
        self.assertIn("img_dupes_config.backup_threshold", joined)
        self.assertIn("`log_cleanup_config` should be an object", joined)

    def test_emit_config_warnings_warns_once_and_logs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "warnings.log"
            module_config._EMITTED_CONFIG_WARNINGS.clear()
            with patch.object(
                module_config,
                "_resolve_warning_log_path",
                return_value=log_path,
            ):
                with patch("builtins.print") as print_mock:
                    first = module_config.emit_config_warnings(
                        ["one warning", "one warning", "second warning"]
                    )
                    second = module_config.emit_config_warnings(["one warning"])

            self.assertEqual(first, ["one warning", "second warning"])
            self.assertEqual(second, [])
            self.assertEqual(print_mock.call_count, 2)
            self.assertTrue(log_path.exists())
            text = log_path.read_text(encoding="utf-8")
            self.assertIn("one warning", text)
            self.assertIn("second warning", text)


if __name__ == "__main__":
    unittest.main()
