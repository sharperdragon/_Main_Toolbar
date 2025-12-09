from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import json

from ..utils.top_helper import (
    _load_rule_aliases,
    _pretty_rule_file_label as _pretty_label_for_file,
    _group_rule_files_by_folder,
    _rule_group_and_name,
    _load_rule_favorites,
)


def build_initial_context(
    rule_files: List[Path],
    rules_root: Optional[Path],
) -> Dict[str, Any]:
    """
    Build the JSON-serializable payload we send down to the HTML UI.
    """
    aliases = _load_rule_aliases(rule_files)
    group_names, group_to_files = _group_rule_files_by_folder(rule_files, rules_root)

    # * Load favorites (by filename) and expose as a synthetic "Favorites" group
    favorites: Set[str] = _load_rule_favorites(rule_files)

    groups_payload: List[Dict[str, Any]] = []

    # Skip synthetic "All" group; HTML side works with concrete groups.
    for group_name in group_names:
        if group_name == "All":
            continue

        files_payload: List[Dict[str, Any]] = []
        for p in group_to_files.get(group_name, []):
            files_payload.append(
                {
                    "path": str(p),
                    "name": p.name,
                    "label": _pretty_label_for_file(p, aliases),
                    "alias": aliases.get(p.name, "").strip(),
                    "favorite": p.name in favorites,
                }
            )

        groups_payload.append(
            {
                "name": group_name,
                "files": files_payload,
            }
        )

    # --- Synthetic "★ Favorites" group across all folders ------------------
    favorites_files_payload: List[Dict[str, Any]] = []
    if favorites:
        # Preserve a stable order: sort by filename
        name_to_path: Dict[str, Path] = {p.name: p for p in rule_files}
        for fname in sorted(favorites):
            p = name_to_path.get(fname)
            if not p:
                continue
            favorites_files_payload.append(
                {
                    "path": str(p),
                    "name": p.name,
                    "label": _pretty_label_for_file(p, aliases),
                    "alias": aliases.get(p.name, "").strip(),
                    "favorite": True,
                }
            )

    if favorites_files_payload:
        # Insert at the top so it's the first tab / group in the UI
        groups_payload.insert(
            0,
            {
                "name": "★ Favorites",
                "files": favorites_files_payload,
            },
        )

    return {
        "groups": groups_payload,
        "defaults": {
            "dry_run": True,
            # * Extensive debugging: optional heavy logging mode
            "extensive_debug": False,
            "extensive_debug_max_examples": 60,
        },
    }


def build_rule_file_preview(self, path: Path, raw: str) -> str:
    try:
        data = json.loads(raw)
    except Exception:
        return raw

    rules: List[Dict[str, Any]] = []

    if isinstance(data, dict) and isinstance(data.get("rules"), list):
        rules = [r for r in data.get("rules", []) if isinstance(r, dict)]
    elif isinstance(data, list):
        rules = [r for r in data if isinstance(r, dict)]
    else:
        return raw

    if not rules:
        return raw

    try:
        group, fname, label = _rule_group_and_name(path, getattr(self, "_rules_root", None))
    except Exception:
        group, fname, label = ("", path.name, path.name)

    header = label or fname or path.name
    lines: List[str] = [header, ""]

    max_rules = 50
    total_rules = len(rules)

    for idx, rule in enumerate(rules, start=1):
        if idx > max_rules:
            break

        name = str(rule.get("name") or f"Rule {idx}").strip()

        query = str(rule.get("query") or "")
        pattern = str(rule.get("pattern") or "")
        replacement = str(rule.get("replacement") or "")

        loop_flag = bool(rule.get("loop", False))
        delete_cfg = rule.get("delete_chars")

        options_str = format_rule_options_for_preview(loop_flag, delete_cfg)

        lines.append(f"{name}")
        if query:
            lines.append(f'<b>Q: "{query}"')
        elif pattern:
            lines.append(f'Q: "{pattern}"')
        lines.append(f'Pattern: "{pattern}"')
        lines.append(f'Replace: "{replacement}"')
        lines.append(f"Options: {options_str}")
        lines.append("")

    if total_rules > max_rules:
        remaining = total_rules - max_rules
        lines.append(f"... ({remaining} more rule(s) not shown)")

    return "\n".join(lines)


# * Preview helpers for rule options (shared by logger + GUI)
def format_delete_chars_for_preview(delete_cfg: Dict[str, Any] | None) -> str:
    """
    Turn a delete_chars config into a short, human-friendly phrase.

    Examples:
      {"max_chars": 0, "count_spaces": True}   -> "del 0 including spaces"
      {"max_chars": 10, "count_spaces": False} -> "del 10 excluding spaces"
      None or invalid                          -> ""
    """
    if not isinstance(delete_cfg, dict):
        return ""

    raw_max = delete_cfg.get("max_chars", 0)
    try:
        max_chars = int(raw_max)
    except Exception:
        max_chars = 0

    count_spaces = bool(delete_cfg.get("count_spaces", True))
    spaces_text = "including spaces" if count_spaces else "excluding spaces"
    return f"del {max_chars} {spaces_text}"


def format_rule_options_for_preview(loop: bool, delete_cfg: Dict[str, Any] | None) -> str:
    """
    Build the 'Options: ...' line for a rule preview.

    Examples:
      loop=True,  delete_cfg={0, True}   -> "Looping, del 0 including spaces"
      loop=False, delete_cfg={5, False}  -> "del 5 excluding spaces"
      loop=False, delete_cfg=None        -> "(none)"
    """
    parts: list[str] = []

    if loop:
        parts.append("Looping")

    delete_text = format_delete_chars_for_preview(delete_cfg)
    if delete_text:
        parts.append(delete_text)

    if not parts:
        return "(none)"

    return ", ".join(parts)