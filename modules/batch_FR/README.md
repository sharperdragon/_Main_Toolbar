# Batch Find & Replace

## Purpose
Run bulk note-field text transformations from rule files, with optional remove-rule pipelines and dry/live execution from a rule-selection dialog.

## Toolbar Action + Python Entrypoint
- Toolbar action: `Batch Find & Replace`
- Module: `_Main_Toolbar.modules.batch_FR`
- Toolbar entrypoint: `run_from_toolbar()` in `__init__.py`
- Public wrapper API: `run_batch_find_replace(...)` in `__init__.py` (for callers/integration code)

## Inputs / Config / Rules
- Main config source:
  - `modules/modules_config.json -> batch_FR_config`
- Common keys used by runtime:
  - `rules_path`
  - `fields_all`
  - `defaults`
  - `remove_config`
  - `remove_rules_suffix`
  - `field_remove_rules_name`
  - `max_loops`
  - `order_preference`
  - `batch_fr_debug`
- Global logging/time keys:
  - `modules/modules_config.json -> global_config.log_dir`
  - `modules/modules_config.json -> global_config.ts_format`
- Rule selection behavior:
  - dialog lists discoverable files under configured `rules_path`
  - JSON/JSONL rule files are loaded as find/replace rules
  - `*remove_rule.txt` and `*remove_rules.txt` are routed to remove pipeline
  - `field_remove_rules.txt` is handled separately for field-remove logic
- Field-remove source precedence in engine:
  - explicit `field_remove_rules` argument
  - UI-selected `field_remove_rules.txt`
  - config fallback

## Outputs / Logs
- Toolbar tooltip summary for dry or live outcome.
- Default log directory fallback:
  - `~/Desktop/anki_logs/Main_toolbar` (when no `global_config.log_dir` is configured)
- Typical run artifacts in log dir:
  - `Batch_FR_Debug__<timestamp>.md`
  - `Regex_Debug__<timestamp>.md`
  - `Remove_FR_Debug__<timestamp>.md` (when remove TXT rules are active)
  - `Field_Remove_Debug__<timestamp>.md` (when field-remove rules are active)
  - `Batch_FR_Crash__<timestamp>.txt` (written by toolbar wrapper on crash)

## Run Instructions (Anki UI)
1. Open the tool from the toolbar action `Batch Find & Replace`.
2. Select rule files in the dialog.
3. Choose `Dry run` or `Live` mode.
4. Run and review tooltip summary.
5. Check log files in configured log directory for details.

## Common Failure Modes + Quick Checks
- No rule files shown:
  - quick check: verify `batch_FR_config.rules_path` points to the intended rules folder.
- Run completes with 0 changes:
  - quick check: confirm selected rules match collection content and target fields.
- Remove behavior not as expected:
  - quick check: confirm which remove TXT files were selected and whether `field_remove_rules.txt` was selected.
- Crash log created:
  - quick check: open `Batch_FR_Crash__*.txt` and fix the underlying rule/config error.

## Related Docs
- GUI inspection notes: [`gui/GUI_README.md`](gui/GUI_README.md)
- Rule/config reference notes: [`folder/ref_folder/README.md`](folder/ref_folder/README.md)
