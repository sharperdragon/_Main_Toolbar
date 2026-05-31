from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# ==========================
# Changeable run settings
# ==========================

ROOT_DIR = Path(__file__).resolve().parent
PYTHON_EXE = sys.executable
TEST_PATTERN = "test_*.py"
STOP_ON_FIRST_FAILURE = False

TEST_TARGETS = [
    ROOT_DIR / "modules" / "tests",
    ROOT_DIR / "modules" / "batch_FR" / "tests",
]


def _run_unittest_discovery(start_dir: Path) -> int:
    cmd = [
        PYTHON_EXE,
        "-m",
        "unittest",
        "discover",
        "-s",
        str(start_dir),
        "-p",
        TEST_PATTERN,
        "-v",
    ]
    print(f"\n=== Running: {start_dir} ===", flush=True)
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR), check=False)
    return int(proc.returncode)


def main() -> int:
    failures: list[Path] = []

    for target in TEST_TARGETS:
        if not target.exists():
            print(f"Missing test target: {target}")
            failures.append(target)
            if STOP_ON_FIRST_FAILURE:
                break
            continue

        rc = _run_unittest_discovery(target)
        if rc != 0:
            failures.append(target)
            if STOP_ON_FIRST_FAILURE:
                break

    if failures:
        print("\nTest run failed for:")
        for path in failures:
            print(f"- {path}")
        return 1

    print("\nAll test targets passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
