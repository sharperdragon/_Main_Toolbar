"""
! 17-03_11-10 — Import check for tag_renaming (run from VS Code)

- Puts your Anki add-ons path on sys.path
- Imports the package exactly as your loader does
- Writes a small report to Desktop
"""

# * Vars you like at the top
DESKTOP = "/Users/claytongoddard/Desktop"
TS_FORMAT = "%H-%M_%m-%d"
ADDONS_PATH = "/Users/claytongoddard/Library/Application Support/Anki2/addons21"

PKG = "_Main_Toolbar.modules.tag_renaming"  # same path used by Run_add_ons loader
from datetime import datetime
from pathlib import Path

# * New config for logic preview
RULES_PATH = "/Users/claytongoddard/Library/Application Support/Anki2/addons21/_Main_Toolbar/modules/tag_renaming/new_tag_rules.json"

# * Focused examples that previously showed issues
EXAMPLES = [
    "#AK_Step1_v12",
    "#AK_Step2_v12",
    "#AK_Step3_v12",
    "#PANCE",
    "#OME_banner::Clinical",
]

# * Toggle to simulate sanitizer behavior for the prefixes preflight
PREVIEW_DROP_TAILS_IN_PREFIX = False  # SAFE default; set True to test tail-trim

def load_rules_json(path: str) -> list[tuple[str, str]]:
    """
    Load JSON rules and normalize $1 → \1 like the module does.
    Returns a list of (pattern, replacement) tuples.
    """
    import json, re
    from pathlib import Path
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    pairs: list[tuple[str, str]] = []
    for item in data:
        if isinstance(item, dict) and "file-defaults" in item:
            continue
        if isinstance(item, dict) and "pattern" in item and "replacement" in item:
            patt = str(item["pattern"]).strip()
            repl_raw = str(item["replacement"]).strip()
            # mimic module behavior: convert $1 → \1 for Python's re.sub
            repl = re.sub(r"\$(\d+)", r"\\\1", repl_raw)
            pairs.append((patt, repl))
    return pairs

def preview_prefix_pass(UT, rules: list[tuple[str, str]], inputs: list[str], drop_tails: bool) -> list[str]:
    """
    For each (pattern, replacement), show original vs. sanitized prefix forms and
    example substitutions for any inputs that fully match the sanitized pattern.
    """
    import re
    rows: list[str] = []

    # temporarily override the module flag if present
    old_flag = getattr(UT, "DROP_TAILS_IN_PREFIX", None)
    try:
        if old_flag is not None:
            setattr(UT, "DROP_TAILS_IN_PREFIX", drop_tails)

        for patt, repl in rules:
            spatt, srepl, changed = UT._sanitize_parent_only(patt, repl)
            try:
                rgx = re.compile(spatt)
            except Exception as e:
                rows.append(f"RULE ! bad pattern: {patt}  err={e}")
                rows.append("")
                continue

            rows.append(f"RULE  pattern={patt}  replacement={repl}")
            if changed or (spatt != patt or srepl != repl):
                rows.append(f"     prefix_pattern={spatt}  prefix_replacement={srepl}")

            for tag in inputs:
                m = rgx.fullmatch(tag)
                if not m:
                    continue
                try:
                    out = rgx.sub(srepl, tag, count=1)
                except Exception as e:
                    out = f"! sub error: {e}"
                rows.append(f"     EX  {tag}  →  {out}")

            rows.append("")
    finally:
        if old_flag is not None:
            setattr(UT, "DROP_TAILS_IN_PREFIX", old_flag)

    return rows

def quick_sanity(UT, rules: list[tuple[str, str]], tags: list[str]) -> list[str]:
    """Show the first matching rule result per tag using the prefix-sanitized pattern."""
    import re
    out: list[str] = ["== Quick Sanity =="]
    for t in tags:
        shown = False
        for patt, repl in rules:
            spatt, srepl, _ = UT._sanitize_parent_only(patt, repl)
            try:
                rgx = re.compile(spatt)
            except Exception:
                continue
            if rgx.fullmatch(t):
                try:
                    res = rgx.sub(srepl, t, count=1)
                except Exception as e:
                    res = f"! sub error: {e}"
                out.append(f"{t}  →  {res}  (by {patt} → {repl}; prefix={spatt} → {srepl})")
                shown = True
                break
        if not shown:
            out.append(f"{t}  →  (no matching rule)")
    out.append("")
    return out

def main() -> None:
    lines = []
    try:
        # ? Ensure the Anki add-ons root is on sys.path
        import sys
        if ADDONS_PATH not in sys.path:
            sys.path.insert(0, ADDONS_PATH)

        import importlib
        mod = importlib.import_module(PKG)
        lines.append(f"OK: Imported {PKG}")
        lines.append(f"Module file: {getattr(mod, '__file__', 'n/a')}")

        # --- Logic preview ---
        import importlib as _importlib
        TR = _importlib.import_module(f"{PKG}.TR_main")
        UT = _importlib.import_module(f"{PKG}.tag_renaming.tag_rename_utils")

        try:
            rules = load_rules_json(RULES_PATH)
            lines.append(f"Loaded rules: {len(rules)} from {RULES_PATH}")
            lines.append(f"DROP_TAILS_IN_PREFIX (module default): {getattr(UT, 'DROP_TAILS_IN_PREFIX', None)}")
            lines.append(f"Preview flag (this test run): {PREVIEW_DROP_TAILS_IN_PREFIX}")
            lines.append("")

            # Focused quick sanity first
            lines.extend(quick_sanity(UT, rules, EXAMPLES))

            # Full prefixes preflight preview
            lines.append("== Prefixes Preflight Preview ==")
            lines.extend(preview_prefix_pass(UT, rules, EXAMPLES, PREVIEW_DROP_TAILS_IN_PREFIX))
        except Exception:
            import traceback
            lines.append("! FAILED during logic preview")
            lines.append("---- TRACEBACK ----")
            lines.append("".join(traceback.format_exc()))

    except Exception as e:
        import traceback
        lines.append(f"! FAILED to import {PKG}")
        lines.append("---- TRACEBACK ----")
        lines.append("".join(traceback.format_exc()))

    log = Path(DESKTOP) / f"tag_renaming_import_check_{datetime.now().strftime(TS_FORMAT)}.txt"
    log.write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    main()