from __future__ import annotations

import importlib
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class LegacyWrapperDelegationTests(unittest.TestCase):
    def test_img_dupes_legacy_wrapper_forwards_to_active_entrypoint(self) -> None:
        active = importlib.import_module("modules.IMG_dupes")
        legacy = importlib.import_module("modules.IMG_dupes.IMG_dupes")

        with patch.object(active, "run_img_dupes_script") as active_mock:
            legacy.run_img_dupes_script()

        active_mock.assert_called_once_with()

    def test_unused_media_legacy_wrapper_forwards_to_active_entrypoint(self) -> None:
        active = importlib.import_module("modules.get_unused_media")
        legacy = importlib.import_module("modules.folder.source_media_tools.get_unused_media")

        with patch.object(active, "export_unused_media_to_txt") as active_mock:
            legacy.export_unused_media_to_txt("custom.txt")

        active_mock.assert_called_once_with("custom.txt")

    def test_unused_media_utils_wrapper_forwards_to_active_entrypoint(self) -> None:
        active = importlib.import_module("modules.get_unused_media")
        path = (
            REPO_ROOT
            / "modules"
            / "folder"
            / "source_media_tools"
            / "get_unused_media.utils.py"
        )
        spec = importlib.util.spec_from_file_location(
            "legacy_unused_media_utils_wrapper",
            path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        with patch.object(active, "export_unused_media_to_txt") as active_mock:
            module.export_unused_media_to_txt("other.txt")

        active_mock.assert_called_once_with("other.txt")


if __name__ == "__main__":
    unittest.main()
