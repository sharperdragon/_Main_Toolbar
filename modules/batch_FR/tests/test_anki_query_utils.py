from __future__ import annotations

import sys
import types
import unittest
from importlib import import_module
from pathlib import Path


def _bootstrap_utils_namespace() -> None:
    """Make modules.batch_FR.utils.* importable without importing Anki UI packages."""
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

anki_query_utils = import_module("modules.batch_FR.utils.anki_query_utils")
data_defs = import_module("modules.batch_FR.utils.data_defs")
Rule = data_defs.Rule


class BatchFrAnkiQueryUtilsTests(unittest.TestCase):
    def _mk_rule(self, **overrides):
        base = dict(
            query="",
            exclude_query=[],
            pattern="",
            replacement="",
            regex=True,
            flags="m",
            fields=["ALL"],
            loop=False,
            delete_chars={"max_chars": 0, "count_spaces": True},
        )
        base.update(overrides)
        return Rule(**base)

    def test_derived_field_regex_keeps_single_backslashes(self) -> None:
        rule = self._mk_rule(
            pattern=r"(\{\{[^\}]*?)<b>([^\}]*?\}\})",
            fields=["Text"],
            regex=True,
        )

        search = anki_query_utils.compose_search(rule)

        self.assertTrue(search.startswith('"Text:re:'))
        self.assertIn(r"\{\{", search)
        self.assertNotIn(r"\\{\\{", search)

    def test_explicit_regex_query_is_not_backslash_doubled(self) -> None:
        explicit = r"Text:re:(\{\{c\d::[^\}:]+?::)\s"
        rule = self._mk_rule(query=[explicit], pattern="unused")

        search = anki_query_utils.compose_search(rule)

        self.assertEqual(search, f'"{explicit}"')
        self.assertNotIn(r"\\{\\{", search)
        self.assertNotIn(r"\\d", search)
        self.assertNotIn(r"\\s", search)


if __name__ == "__main__":
    unittest.main()
