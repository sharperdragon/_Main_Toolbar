# Export Missing Media

## Purpose
Find media filenames referenced in notes but missing from the collection media folder, then export the missing list to text files.

## Toolbar Action + Python Entrypoint
- Toolbar action: `Export Missing Media`
- Module: `_Main_Toolbar.modules.get_missing_media`
- Entrypoint: `write_missing_file()` in `__init__.py`

## Inputs / Config / Rules
- Runtime config section:
  - `modules/modules_config.json -> missing_media_config`
  - keys: `tag_filter_enabled`, `tag_name`, `media_extensions`, `output_dir`, `backup_dir`
- Fallback defaults are still defined at top of `__init__.py` for quick VS Code edits.
- Scope behavior:
  - if `tag_filter_enabled` is `true` and `tag_name` is non-empty, only notes containing that exact tag are scanned
  - otherwise all notes are scanned
  - `%` and `_` in `tag_name` are treated literally (escaped for SQL `LIKE`)
- Media reference parsing:
  - extracts `src=...` on `<img ...>` tags
  - supports double-quoted, single-quoted, and unquoted `src` forms
  - case-insensitive tag/attribute matching
  - URL-decodes `%xx`
  - strips query/hash
  - excludes remote/network references (`http(s)://...`, `//...`)
  - keeps basename only when extension matches configured `media_extensions`

## Outputs / Logs
- Primary output file:
  - `<missing_media_config.output_dir>/missing_media_<profile>.txt`
- Backup output file:
  - `<missing_media_config.backup_dir>/missing_media_<profile>.txt`
- Popup summary includes scope, count, and write outcome:
  - both writes succeed: success message
  - one write fails: partial-output warning message with failed destination/reason
  - both writes fail: failure message (no false success)

## Run Instructions (Anki UI)
1. Open the tool from the toolbar action `Export Missing Media`.
2. Wait for the scan to finish.
3. Read the popup for the saved output path and missing file count.

## Common Failure Modes + Quick Checks
- Empty output:
  - can be valid (no missing files found).
  - quick check: verify target notes actually reference media in `src="..."`.
- Unexpected scope:
  - quick check: confirm `missing_media_config.tag_filter_enabled` and `missing_media_config.tag_name`.
- Backup write error:
  - quick check: ensure the configured `backup_dir` exists and is writable.
- Success message not shown:
  - expected when one or both output writes fail.
  - quick check: review destination paths and permissions shown in popup.

## Related Docs
- No dedicated module-specific deep-dive doc yet.
