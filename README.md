# Main Toolbar Addon

## Active Toolbar Actions

| Toolbar Label | Module | Entrypoint |
| --- | --- | --- |
| Export Missing Media | `_Main_Toolbar.modules.get_missing_media` | `write_missing_file` |
| Get Unused | `_Main_Toolbar.modules.get_unused_media` | `export_unused_media_to_txt` |
| Resolve IMG Dupes | `_Main_Toolbar.modules.IMG_dupes` | `run_img_dupes_script` |
| Update Tags | `_Main_Toolbar.modules.tag_updates` | `run_tag_updates` |
| Batch Find & Replace | `_Main_Toolbar.modules.batch_FR` | `run_from_toolbar` |

Source of truth: `assets/actions.json`.

## Module READMEs

- `modules/get_missing_media/README.md`
- `modules/get_unused_media/README.md`
- `modules/IMG_dupes/README.md`
- `modules/tag_updates/README.md`
- `modules/batch_FR/README.md`

## Config Map

Primary config file: `modules/modules_config.json`

- `global_config`: shared log directory and timestamp format.
- `missing_media_config`: scope/filter/output for missing media export.
- `unused_media_config`: output directory, filename prefix, chunking.
- `img_dupes_config`: target fields, backup threshold, backup file.
- `log_cleanup_config`: cleanup root, suffix allow-list, safety marker, retention.
- `batch_FR_config`: batch find/replace rules and runtime defaults.
- `tag_renaming`: tag-update defaults and rule tuning.

## VS Code Test Workflow

Use `run_module_tests.py` as the one-click test runner:

1. Open `/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/run_module_tests.py` in VS Code.
2. Run with VS Code's Python "Run Python File" action.
3. Review pass/fail output in the VS Code run panel.

## Config Health Check

Use `/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/run_config_health_check.py` for a one-click config validation run in VS Code:

1. Open the script in VS Code.
2. Run with VS Code's Python "Run Python File" action.
3. Review warning summary in the run panel and check the config warning log path reported by the script.

## Legacy Compatibility Wrappers

The following files are compatibility wrappers and delegate to active module entrypoints:

- `modules/IMG_dupes/IMG_dupes.py`
- `modules/folder/source_media_tools/get_unused_media.py`
- `modules/folder/source_media_tools/get_unused_media.utils.py`
