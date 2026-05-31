# Tag Updates

## Purpose
Run a combined tag-maintenance workflow: apply selected tag-addition rules, then apply selected tag-renaming rules in the same dry/live mode.

## Toolbar Action + Python Entrypoint
- Toolbar action: `Update Tags`
- Module: `_Main_Toolbar.modules.tag_updates`
- Entrypoint: `run_tag_updates()` in `__init__.py`
- Other public entrypoints:
  - `run_tag_renamer()` (rename-focused)
  - `run_tag_additions()` (add-tag-focused)

## Inputs / Config / Rules
- Rule sources:
  - rename rules from `modules/tag_updates/rules/` (`.csv` + `.json`)
  - add-tag rules from `modules/tag_updates/tag_additions/*_tagging.json`
- UI behavior:
  - user selects rename rules and add-tag rules in one dialog
  - dry run is selected by default in that dialog
  - execution order is add tags first, then renames
- Config relevant to operator behavior:
  - `modules/modules_config.json -> global_config.log_dir`
  - `modules/modules_config.json -> global_config.ts_format`
- Config relevant to rename engine tuning:
  - `modules/modules_config.json -> tag_renaming.allow_regex`
  - `modules/modules_config.json -> tag_renaming.batch_commit_size`
  - `modules/modules_config.json -> tag_renaming.max_expansions_per_rule`
  - `modules/modules_config.json -> tag_renaming.regex_debug_examples`

## Outputs / Logs
- Combined summary popup after run.
- Rename logs (in configured log dir):
  - `Global_Tag_Renamer_<timestamp>.md`
  - `Regex_Debug_<timestamp>.md` (when regex debug output is enabled)
- Add-tag logs (in configured log dir):
  - `tag_additions_<timestamp>.md`
  - `tag_additions_load_errors.txt` (load/parsing issues)
  - `tag_additions_search_errors.txt` (query/search failures)

## Run Instructions (Anki UI)
1. Open the tool from the toolbar action `Update Tags`.
2. Select rename rules and/or add-tag rules.
3. Choose run mode (`Dry run` or `Apply changes`).
4. Run and review the summary popup, then inspect generated logs if needed.

## Common Failure Modes + Quick Checks
- No rules available:
  - quick check: confirm rule files exist in `rules/` and `tag_additions/`.
- No changes applied:
  - quick check: verify selected rules match actual tags in your collection.
- Search errors during tag additions:
  - quick check: inspect `tag_additions_search_errors.txt` and fix invalid queries.
- Unexpected run mode:
  - quick check: verify dry/live toggle before confirming in dialog.

## Related Docs
- Rename rule format guide: [`rules/RULES_README.md`](rules/RULES_README.md)
