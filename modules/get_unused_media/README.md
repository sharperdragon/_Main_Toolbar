# Get Unused Media

## Purpose
Scan collection notes for referenced media and export files present in the media folder but not referenced by notes.

## Toolbar Action + Python Entrypoint
- Toolbar action: `Get Unused`
- Module: `_Main_Toolbar.modules.get_unused_media`
- Entrypoint: `export_unused_media_to_txt()` in `__init__.py`

## Inputs / Config / Rules
- Runtime config section:
  - `modules/modules_config.json -> unused_media_config`
  - keys: `default_output_dir`, `filename_prefix`, `chunk_size`
- Scan scope: all notes returned by `find_notes("")`.
- Reference patterns checked in every field:
  - sound tags: case-insensitive `[sound:filename]`
  - image tags: flexible `<img ... src=...>` parsing
    - supports single-quote, double-quote, and unquoted `src` forms
- Reference normalization:
  - URL decode is applied
  - query string and fragment are stripped
  - basename is extracted from normalized path
  - remote/external URLs are ignored (`http(s)://...`, `//...`, etc.)
- API behavior:
  - `export_unused_media_to_txt(output_path=...)` now honors the provided path.
  - if `output_path` is omitted, output path is built from `unused_media_config`.

## Outputs / Logs
- Output file:
  - explicit `output_path` argument when provided
  - otherwise `<unused_media_config.default_output_dir>/<filename_prefix>_<profile>_<timestamp>.txt`
- File format:
  - unused filenames, comma-separated, grouped in chunks of `chunk_size`.
- Popup summary with total unused file count.

## Run Instructions (Anki UI)
1. Open the tool from the toolbar action `Get Unused`.
2. Wait for the scan to complete.
3. Open the generated file from the path shown in the popup.

## Common Failure Modes + Quick Checks
- Very large output:
  - expected on collections with a lot of orphaned media.
- False positives:
  - quick check: module parses local `[sound:...]` and `<img ... src=...>` references only.
  - remote URL references are intentionally ignored.
- No output file:
  - quick check: confirm the explicit `output_path` (or configured `default_output_dir`) is writable.

## Related Docs
- No dedicated module-specific deep-dive doc yet.
