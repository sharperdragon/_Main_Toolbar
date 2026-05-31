# IMG Dupes

## Purpose
Remove duplicate `<img ...>` tags inside supported fields for notes returned by a user-entered Browser query.

## Toolbar Action + Python Entrypoint
- Toolbar action: `Resolve IMG Dupes`
- Module: `_Main_Toolbar.modules.IMG_dupes`
- Entrypoint: `run_img_dupes_script()` in `__init__.py`

## Inputs / Config / Rules
- Runtime config section:
  - `modules/modules_config.json -> img_dupes_config`
  - keys: `fields`, `backup_threshold`, `backup_path`
- Query input is prompted at runtime (non-modal dialog).
- Run mode picker is shown after query entry:
  - `Apply changes` (default): live mutation mode
  - `Preview only (dry run)`: scan-only mode
  - Cancel: exits without running
- Query normalization:
  - leading `tag:` is added if missing
  - `\_` is normalized to `_`
- Fields scanned:
  - from `img_dupes_config.fields` (defaults to `Text`, `Extra`, `Extra2`, `Extra3`, `Extra4`, `Extra5`, `Button`, `Display`)
- Duplicate rule:
  - within each field, the first image `src` is kept
  - later duplicate `src` tags in the same field are removed

## Outputs / Logs
- In `Apply changes` mode:
  - popup summary reports cleaned note count
  - if changed-note count is greater than `img_dupes_config.backup_threshold`, a backup note-id file is written to:
    - `img_dupes_config.backup_path`
- In `Preview only (dry run)` mode:
  - popup summary reports how many notes would be cleaned
  - no note flushes are performed
  - no backup file is written
- Backup path in apply mode:
  - `img_dupes_config.backup_path`

## Run Instructions (Anki UI)
1. Open the tool from the toolbar action `Resolve IMG Dupes`.
2. Enter an Anki Browser-style search query when prompted.
3. Choose `Apply changes` or `Preview only (dry run)` in the mode picker.
4. Let the background operation complete.
5. Review the completion popup.

## Common Failure Modes + Quick Checks
- No matching notes:
  - tool exits with a "No notes found" popup.
  - quick check: confirm the query syntax and tag spelling.
- Backup file write fails on large runs:
  - quick check: ensure configured `backup_path` parent directory is writable.
- Some fields unchanged:
  - expected if the field has no duplicate image `src` values.
- Preview mode shows changes but nothing is modified:
  - expected behavior; rerun in `Apply changes` mode to write updates.

## Related Docs
- No dedicated module-specific deep-dive doc yet.
