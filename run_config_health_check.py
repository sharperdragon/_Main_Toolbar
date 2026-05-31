from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, Iterable, List, Union

# ==========================
# Changeable run settings
# ==========================

ROOT_DIR = Path(__file__).resolve().parent
CONFIG_PATH: Path = ROOT_DIR / "modules" / "modules_config.json"

FAIL_ON_WARNINGS = False
PRINT_SECTION_SUMMARY = True
PRINT_WARNING_LINES = True
MAX_WARNING_LINES = 200
HEADER_PREFIX = "[config-health]"


if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from modules import module_config  # noqa: E402


def _warning_log_path(cfg: Dict[str, Any]) -> Path:
    global_cfg = module_config.get_global_config(cfg)
    log_dir = module_config.resolve_path(
        global_cfg.get("log_dir"),
        module_config.DEFAULT_LOG_DIR,
    )
    return log_dir / module_config.CONFIG_WARNING_LOG_FILENAME


def _print_warning_lines(warnings: Iterable[str]) -> None:
    count = 0
    for msg in warnings:
        if count >= MAX_WARNING_LINES:
            print(f"{HEADER_PREFIX} ... warning output truncated at {MAX_WARNING_LINES} lines")
            break
        count += 1
        print(f"{HEADER_PREFIX} {count}. {msg}")


def main(config_path: Union[str, Path] = CONFIG_PATH) -> int:
    try:
        cfg = module_config.load_modules_config(config_path)
        warnings: List[str] = module_config.validate_modules_config(cfg)
        emitted = module_config.emit_config_warnings(warnings, cfg)
        warning_log = _warning_log_path(cfg)

        path_obj = Path(config_path).expanduser()
        try:
            path_obj = path_obj.resolve()
        except Exception:
            pass

        print(f"{HEADER_PREFIX} Config path: {path_obj}")
        if PRINT_SECTION_SUMMARY:
            print(f"{HEADER_PREFIX} Top-level sections: {len(cfg)}")
        print(f"{HEADER_PREFIX} Warning count: {len(warnings)}")
        print(f"{HEADER_PREFIX} Newly emitted this run: {len(emitted)}")
        print(f"{HEADER_PREFIX} Warning log: {warning_log}")

        if PRINT_WARNING_LINES and warnings:
            _print_warning_lines(warnings)

        if warnings and FAIL_ON_WARNINGS:
            return 1
        return 0

    except Exception as exc:
        print(f"{HEADER_PREFIX} ERROR: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
