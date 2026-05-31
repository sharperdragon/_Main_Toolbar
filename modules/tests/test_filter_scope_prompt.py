from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules.filter_scope_prompt import build_scope_query  # noqa: E402


class ScopeFilterQueryTests(unittest.TestCase):
    def test_empty_inputs_return_empty_query(self) -> None:
        self.assertEqual(build_scope_query("", ""), "")

    def test_tag_without_prefix_gets_tag_clause(self) -> None:
        self.assertEqual(build_scope_query("my_tag", ""), "tag:my_tag")

    def test_note_type_with_spaces_is_quoted(self) -> None:
        self.assertEqual(
            build_scope_query("", "Basic (and reversed card)"),
            'note:"Basic (and reversed card)"',
        )

    def test_existing_prefixes_are_preserved(self) -> None:
        self.assertEqual(
            build_scope_query("tag:#AK_Step2", 'note:"Basic"'),
            'tag:#AK_Step2 note:"Basic"',
        )


if __name__ == "__main__":
    unittest.main()
