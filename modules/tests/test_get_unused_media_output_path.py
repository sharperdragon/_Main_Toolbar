from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import modules.get_unused_media as get_unused_media  # noqa: E402


class _FakeMedia:
    def __init__(self, media_dir: Path) -> None:
        self._media_dir = media_dir

    def dir(self) -> str:
        return str(self._media_dir)


class _FakeNote:
    def __init__(self, fields: list[str]) -> None:
        self.fields = fields


class _FakeCollection:
    def __init__(self, media_dir: Path, notes_by_id: dict[int, _FakeNote]) -> None:
        self.media = _FakeMedia(media_dir)
        self._notes_by_id = notes_by_id

    def find_notes(self, _query: str) -> list[int]:
        return list(self._notes_by_id.keys())

    def get_note(self, nid: int) -> _FakeNote:
        return self._notes_by_id[nid]


class _FakePm:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeMw:
    def __init__(self, col: _FakeCollection, profile_name: str | None = "profile") -> None:
        self.col = col
        if profile_name is not None:
            self.pm = _FakePm(profile_name)


class GetUnusedMediaOutputPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_mw = get_unused_media.mw
        self._orig_show_info = get_unused_media.showInfo
        get_unused_media.showInfo = lambda _msg: None

    def tearDown(self) -> None:
        get_unused_media.mw = self._orig_mw
        get_unused_media.showInfo = self._orig_show_info

    def test_explicit_output_path_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            media_dir = tmp / "media"
            media_dir.mkdir(parents=True, exist_ok=True)
            (media_dir / "used.png").write_text("", encoding="utf-8")
            (media_dir / "unused.png").write_text("", encoding="utf-8")

            col = _FakeCollection(
                media_dir=media_dir,
                notes_by_id={1: _FakeNote(['<img src="used.png">'])},
            )
            get_unused_media.mw = _FakeMw(col, profile_name="User 1")

            out_path = tmp / "custom" / "unused_report.txt"
            get_unused_media.export_unused_media_to_txt(str(out_path))

            self.assertTrue(out_path.exists())
            text = out_path.read_text(encoding="utf-8")
            tokens = {tok.strip() for tok in text.replace("\n", ",").split(",") if tok.strip()}
            self.assertIn("unused.png", tokens)
            self.assertNotIn("used.png", tokens)

    def test_default_output_path_uses_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            media_dir = tmp / "media"
            media_dir.mkdir(parents=True, exist_ok=True)
            (media_dir / "used.mp3").write_text("", encoding="utf-8")
            (media_dir / "unused.mp3").write_text("", encoding="utf-8")

            col = _FakeCollection(
                media_dir=media_dir,
                notes_by_id={1: _FakeNote(["[sound:used.mp3]"])},
            )
            get_unused_media.mw = _FakeMw(col, profile_name="User 1")

            out_dir = tmp / "exports"
            cfg = {
                "unused_media_config": {
                    "default_output_dir": str(out_dir),
                    "filename_prefix": "my_unused",
                    "chunk_size": 5,
                }
            }
            with patch.object(get_unused_media, "load_modules_config", return_value=cfg):
                get_unused_media.export_unused_media_to_txt()

            files = list(out_dir.glob("my_unused_User 1_*.txt"))
            self.assertEqual(len(files), 1)
            text = files[0].read_text(encoding="utf-8")
            self.assertIn("unused.mp3", text)

    def test_extract_used_files_supports_core_img_and_sound_variants(self) -> None:
        fields = [
            "[SOUND:folder/Audio%20One.mp3?cache=1#x]",
            "<IMG SRC='pics/My%20Image.PNG?x=1#hash'>",
            "<img alt=x src=pics/second.jpg>",
            '<img data-test="1" src = "third.gif">',
        ]
        used = get_unused_media._extract_used_files_from_fields(fields)
        self.assertEqual(
            used,
            {"Audio One.mp3", "My Image.PNG", "second.jpg", "third.gif"},
        )

    def test_extract_used_files_ignores_remote_refs(self) -> None:
        fields = [
            '<img src="https://example.com/remote.png">',
            "[sound:https://example.com/remote.mp3]",
            "<img src=//cdn.example.com/remote2.jpg>",
            "<img src='local/local.png'>",
        ]
        used = get_unused_media._extract_used_files_from_fields(fields)
        self.assertEqual(used, {"local.png"})

    def test_invalid_unused_media_config_values_fall_back_to_defaults(self) -> None:
        cfg = {
            "unused_media_config": {
                "default_output_dir": 123,
                "filename_prefix": 456,
                "chunk_size": "bad",
            }
        }
        settings = get_unused_media._build_runtime_settings(cfg)
        self.assertEqual(
            Path(str(settings["default_output_dir"])).expanduser().resolve(),
            get_unused_media.DEFAULT_OUTPUT_DIR.expanduser().resolve(),
        )
        self.assertEqual(
            settings["filename_prefix"],
            get_unused_media.DEFAULT_FILENAME_PREFIX,
        )
        self.assertEqual(
            settings["chunk_size"],
            get_unused_media.DEFAULT_CHUNK_SIZE,
        )


if __name__ == "__main__":
    unittest.main()
