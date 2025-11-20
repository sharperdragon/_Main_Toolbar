from __future__ import annotations

# =========================
# Rules I/O (files, schema, normalization)
# ! Pure file + normalization utilities; no Anki calls here.

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union
import json
import re
import os
import logging

# * Public surface
__all__ = [
    "discover_rule_files",
    "rules_from_paths",
    "load_rules_from_file",
    "load_plain_rules",
    "load_remove_patterns",
    "load_rule_schema",
    "normalize_rule",
    "strip_comments",
    "read_text",
    "json_load",
    # new helpers
    "json_load_relaxed",
    "iter_jsonl",
    "sort_paths_by_preference",
    "discover_from_config",
    "merge_defaults",
    "coerce_fields",
    "coerce_flags",
    "coerce_queries",
    "validate_rule",
    "maybe_validate_rules",
    "shape_remove_patterns_to_rules",
    "load_rules_from_config",
    "load_remove_sets_from_config",
]

# =========================
# Top-level prefs
# =========================
TS_FORMAT: str = "%H-%M_%m-%d"

VERY_LARGE_ORDER = 1_000_000


def log_warning(msg: str) -> None:
    try:
        logging.getLogger(__name__).warning(msg)
    except Exception:
        pass


def log_error(msg: str) -> None:
    try:
        logging.getLogger(__name__).error(msg)
    except Exception:
        pass


# =========================
# Core discovery / loading
# =========================
def discover_rule_files(root: Union[str, Path]) -> List[Path]:
    """
    * Return a list of rule file paths given a directory or a single file.
    - Supports .json, .jsonl, .txt (line rules), plus future extensions as needed.
    """
    p = Path(root).expanduser().resolve()
    if p.is_file():
        return [p]
    if not p.exists():
        return []
    out: List[Path] = []
    for ext in ("*.json", "*.jsonl", "*_rules.json", "*_rule.json", "*.txt"):
        out.extend(sorted(p.glob(ext)))
    return out


def sort_paths_by_preference(
    paths: List[Path],
    order_map: Optional[Dict[str, int]] = None,
) -> List[Path]:
    if not order_map:
        return sorted(paths, key=lambda p: p.name.lower())
    low = {k.lower(): v for k, v in order_map.items()}

    def _key(p: Path) -> tuple[int, str]:
        return (low.get(p.name.lower(), VERY_LARGE_ORDER), p.name.lower())

    return sorted(paths, key=_key)


def discover_from_config(
    rules_path: Union[str, Path],
    order_preference: Optional[Dict[str, int]] = None,
) -> List[Path]:
    paths = discover_rule_files(rules_path)
    return sort_paths_by_preference(paths, order_preference)



def rules_from_paths(paths: Sequence[Union[str, Path]]) -> List[Dict[str, Any]]:
    """
    * Load and concatenate rules from many files.
    """
    rules: List[Dict[str, Any]] = []
    for path in paths:
        p = Path(path)
        rules.extend(load_rules_from_file(p))
    return rules


# =========================
# Provenance and Dedupe Helpers
# =========================
def _attach_provenance(
    rule: Dict[str, Any],
    source_path: Path,
    idx: int,
) -> Dict[str, Any]:
    """
    * Attach source file + index metadata to a normalized rule dict.
    - Used by logger.rule_prov for debugging.
    """
    r = dict(rule)
    try:
        r["__source_file"] = str(source_path)
        r["__source_index"] = int(idx)
    except Exception:
        # Be defensive; failing provenance must not break rule loading.
        pass
    # Preserve any explicit name the user set on the rule.
    if "name" in rule:
        r["name"] = rule["name"]
    return r


def load_rules_from_file(
    path: Union[str, Path],
    *,
    defaults: Optional[Dict[str, Any]] = None,
    fields_all: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    * Load a JSON/JSONL/TXT rules file into a list of normalized rule dicts.
    - JSON/JSONL => list[dict] or {"rules": [...]}
    - TXT => line-delimited patterns -> wrap into minimal rule dicts
    """
    p = Path(path).expanduser().resolve()
    # Track per-file index for provenance
    idx_in_file = 0

    if p.suffix.lower() == ".jsonl":
        out: List[Dict[str, Any]] = []
        for obj in iter_jsonl(p):
            if isinstance(obj, dict) and isinstance(obj.get("rules"), list):
                for d in obj["rules"]:
                    idx_in_file += 1
                    norm = normalize_rule(d, defaults, fields_all)
                    out.append(_attach_provenance(norm, p, idx_in_file))
            elif isinstance(obj, dict):
                idx_in_file += 1
                norm = normalize_rule(obj, defaults, fields_all)
                out.append(_attach_provenance(norm, p, idx_in_file))
        return out

    if p.suffix.lower() in (".json",):
        data = json_load(p)
        out: List[Dict[str, Any]] = []
        if isinstance(data, list):
            for d in data:
                idx_in_file += 1
                norm = normalize_rule(d, defaults, fields_all)
                out.append(_attach_provenance(norm, p, idx_in_file))
            return out
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            for d in data["rules"]:
                idx_in_file += 1
                norm = normalize_rule(d, defaults, fields_all)
                out.append(_attach_provenance(norm, p, idx_in_file))
            return out
        return []

    if p.suffix.lower() == ".txt":
        return load_plain_rules(p, defaults=defaults)
    return []


def load_plain_rules(
    path: Union[str, Path], *, defaults: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    * Convert a line-delimited TXT file into simple rule dicts.
    - Lines beginning with # are ignored.
    - Uses config Defaults for flags/guards when available.
    """
    text = read_text(Path(path))
    out: List[Dict[str, Any]] = []
    p = Path(path).expanduser().resolve()
    idx_in_file = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        base = {
            "query": "",
            "pattern": line,
            "replacement": "",
            "regex": True,
            "flags": (defaults or {}).get("flags", "m"),
            "fields": ["ALL"],
            "loop": bool((defaults or {}).get("loop", False)),
            "delete_chars": (defaults or {}).get(
                "delete_chars", {"max_chars": 0, "count_spaces": True}
            ),
        }
        idx_in_file += 1
        norm = normalize_rule(base, defaults, None)
        out.append(_attach_provenance(norm, p, idx_in_file))
    return out
# =========================
# Schema / normalization
# =========================


def load_remove_patterns(path: Union[str, Path]) -> List[str]:
    """
    * Load remove patterns from a TXT file (line-delimited).
    """
    text = read_text(Path(path))
    out: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


# =========================
# Schema / normalization
# =========================
def merge_defaults(
    rule: Dict[str, Any], defaults: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if not defaults:
        return rule
    out = dict(rule)
    for k, v in defaults.items():
        if k == "delete_chars":
            rc = dict(v)
            rc.update(dict(out.get("delete_chars", {})))  # rule wins
            out.setdefault("delete_chars", rc)
            continue
        out.setdefault(k, v)
    return out


def coerce_fields(value: Any, *, fallback: Optional[List[str]] = None) -> List[str]:
    if value is None:
        return list(fallback or ["ALL"])
    if isinstance(value, str):
        v = value.strip()
        return ["ALL"] if v.upper() == "ALL" else [v]
    if isinstance(value, list):
        vals = [str(x).strip() for x in value if str(x).strip()]
        return ["ALL"] if any(x.upper() == "ALL" for x in vals) else vals
    return list(fallback or ["ALL"])


def coerce_flags(value: Any, *, fallback: str = "m") -> str:
    if isinstance(value, int):
        # engine will translate ints; store as canonical imsx string best-effort
        return fallback
    s = "".join(ch for ch in str(value or "").lower() if ch in "imsx")
    # dedupe while preserving order
    out: List[str] = []
    for ch in s:
        if ch not in out:
            out.append(ch)
    return "".join(out) or fallback


def coerce_queries(query: Any, exclude_query: Any) -> tuple[List[str], List[str]]:
    def _to_list(v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            v = v.strip()
            return [v] if v else []
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        return []

    return _to_list(query), _to_list(exclude_query)


def normalize_rule(
    rule: Dict[str, Any],
    defaults: Optional[Dict[str, Any]] = None,
    fields_all: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    * Normalize a single rule object to the engine's expected fields.
    - Merge Defaults (without clobbering explicit rule values)
    - Coerce flags, fields, queries, delete_chars
    """
    # Start with a shallow copy
    r = dict(rule)
    # Merge Defaults
    r = merge_defaults(r, defaults)

    # Coerce simple scalars
    r["regex"] = bool(r.get("regex", True))
    r["flags"] = coerce_flags(r.get("flags", (defaults or {}).get("flags", "m")))
    r["fields"] = coerce_fields(r.get("fields", ["ALL"]))

    # Queries
    q, ex = coerce_queries(r.get("query", ""), r.get("exclude_query", []))
    r["query"], r["exclude_query"] = q, ex

    # Pattern(s)
    pat = r.get("pattern", "")
    if isinstance(pat, list):
        r["pattern"] = [str(x) for x in pat]
    else:
        r["pattern"] = str(pat)

    # Replacement
    r["replacement"] = str(r.get("replacement", ""))

    # Loop
    r["loop"] = bool(r.get("loop", False))

    # Delete guard: accept int or dict
    dc = r.get("delete_chars", {"max_chars": 0, "count_spaces": True})
    if isinstance(dc, int):
        r["delete_chars"] = {
            "max_chars": int(dc),
            "count_spaces": bool(
                (defaults or {})
                .get("delete_chars", {})
                .get("count_spaces", True)
            ),
        }
    else:
        # ensure keys exist
        d = {"max_chars": 0, "count_spaces": True}
        d.update(
            {k: v for k, v in dict(dc).items() if k in ("max_chars", "count_spaces")}
        )
        r["delete_chars"] = d

    return r


def load_rule_schema(path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Optional: load a JSON schema. Stub returns {} if unused."""
    try:
        if not path:
            return {}
        p = Path(path)
        data = json_load(p)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def validate_rule(
    rule: Dict[str, Any], schema: Optional[Dict[str, Any]] = None
) -> tuple[bool, str]:
    if not schema:
        return True, "ok"
    # TODO: wire an actual JSON-schema validator if desired
    return True, "ok"


# =========================
# Helper: maybe_validate_rules
# =========================
def maybe_validate_rules(
    rules: List[Dict[str, Any]],
    schema: Optional[Dict[str, Any]] = None,
    on_error: str = "warn",
) -> List[Dict[str, Any]]:
    """
    * Optionally validate a list of rules against a schema.
    - If no schema is provided, returns the rules unchanged.
    - on_error:
        - "warn" (default): log and skip invalid rules.
        - "raise": raise ValueError on first invalid rule.
        - "keep": keep invalid rules but still log a warning.
    """
    if not schema:
        return rules

    out: List[Dict[str, Any]] = []
    for idx, r in enumerate(rules, 1):
        ok, msg = validate_rule(r, schema)
        if ok:
            out.append(r)
            continue

        message = f"Rule {idx} failed schema validation: {msg}"
        if on_error == "raise":
            raise ValueError(message)
        log_warning(message)
        if on_error == "keep":
            out.append(r)
    return out



# =========================
# Rule Signature + Deduplication
# =========================
def _rule_signature(r: Dict[str, Any]) -> tuple:
    """
    * Build a behavioral signature for a rule.
    - Used to drop duplicate rules loaded from multiple files.
    """
    return (
        r.get("pattern"),
        r.get("replacement"),
        tuple(r.get("fields") or []),
        r.get("flags"),
        bool(r.get("loop", False)),
        tuple(r.get("query") or []),
        tuple(r.get("exclude_query") or []),
        tuple(sorted((r.get("delete_chars") or {}).items())),
    )


def dedupe_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    * Drop duplicate rules while preserving the first occurrence.
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for r in rules:
        sig = _rule_signature(r)
        if sig in seen:
            # Optional: could attach a marker or log, but keep it silent for now.
            continue
        seen.add(sig)
        out.append(r)
    return out


def shape_remove_patterns_to_rules(
    patterns: List[str],
    defaults: Optional[Dict[str, Any]] = None,
    fields_all: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in patterns:
        base = {
            "query": "",
            "pattern": line,
            "replacement": "",
            "regex": True,
            "flags": (defaults or {}).get("flags", "ms"),
            "fields": ["ALL"],
            "loop": bool((defaults or {}).get("loop", True)),
            "delete_chars": (defaults or {}).get(
                "delete_chars", {"max_chars": 0, "count_spaces": True}
            ),
        }
        out.append(normalize_rule(base, defaults, fields_all))
    return out


def load_rules_from_config(
    cfg: Dict[str, Any],
    *,
    schema_path: Optional[Union[str, Path]] = None,
    on_error: str = "warn",
) -> List[Dict[str, Any]]:
    # * Config wiring for batch_FR rules
    # ! order_preference is the canonical key; order_prefernce is kept for legacy configs.
    # ! defaults / Defaults are normalized here and passed down to load_rules_from_file.
    order_pref = cfg.get("order_preference") or cfg.get("order_prefernce") or {}
    paths = discover_from_config(cfg.get("rules_path", ""), order_pref)

    # Skip remove files (they are handled separately by load_remove_sets_from_config)
    remove_name = cfg.get("remove_rules_name")
    field_remove_name = cfg.get("field_remove_rules_name")
    skip_names = {n for n in (remove_name, field_remove_name) if n}
    if skip_names:
        filtered: List[Path] = []
        for p in paths:
            try:
                name = Path(p).name
            except Exception:
                name = str(p)
            if name in skip_names:
                continue
            filtered.append(p)
        paths = filtered

    defaults = cfg.get("defaults") or cfg.get("Defaults") or {}
    fields_all = cfg.get("fields_all", [])

    rules: List[Dict[str, Any]] = []
    for p in paths:
        rules.extend(
            load_rules_from_file(p, defaults=defaults, fields_all=fields_all)
        )

    schema = load_rule_schema(schema_path) if schema_path else {}
    validated = maybe_validate_rules(rules, schema, on_error=on_error)
    deduped = dedupe_rules(validated)
    return deduped


def load_remove_sets_from_config(
    cfg: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    defaults = (cfg.get("remove_config") or {}).copy()
    # Ensure sensible defaults if remove_config is missing keys
    if "flags" not in defaults or not defaults.get("flags"):
        defaults["flags"] = "ms"  # multiline + dotall is safer for remove
    if "loop" not in defaults:
        defaults["loop"] = True
    if "delete_chars" not in defaults or not isinstance(
        defaults.get("delete_chars"), dict
    ):
        defaults["delete_chars"] = {"max_chars": 0, "count_spaces": True}

    fields_all = cfg.get("fields_all", [])

    # Start from any explicit paths, if given
    remove_path = cfg.get("remove_path")
    field_remove_path = cfg.get("field_remove_path")

    # Derive from rules_path + *_name if paths are missing
    rules_root = cfg.get("rules_path")
    if rules_root:
        base = Path(rules_root).expanduser()
        if not remove_path and cfg.get("remove_rules_name"):
            remove_path = str((base / cfg["remove_rules_name"]).resolve())
        if not field_remove_path and cfg.get("field_remove_rules_name"):
            field_remove_path = str(
                (base / cfg["field_remove_rules_name"]).resolve()
            )

    if remove_path:
        pats = load_remove_patterns(remove_path)
        out["remove"] = shape_remove_patterns_to_rules(
            pats, defaults, fields_all
        )

    if field_remove_path:
        pats = load_remove_patterns(field_remove_path)
        out["field_remove"] = shape_remove_patterns_to_rules(
            pats, defaults, fields_all
        )

    return out


# =========================
# Helpers
# =========================
def read_text(path: Path, encoding: str = "utf-8") -> str:
    if not path.exists():
        return ""
    txt = path.read_text(encoding=encoding)
    # Strip UTF-8 BOM if present
    if txt.startswith("\ufeff"):
        txt = txt.lstrip("\ufeff")
    return txt


def strip_comments(s: str) -> str:
    """* Remove // and /* */ comments from JSON-like text (best-effort)."""
    if not s:
        return ""
    # Remove /* ... */
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    # Remove // ... endline
    s = re.sub(r"(^|\s)//.*?$", r"\1", s, flags=re.MULTILINE)
    return s


def json_load_relaxed(path: Path) -> Any:
    try:
        raw = read_text(path)
        cleaned = strip_comments(raw)
        return json.loads(cleaned)
    except Exception as e:
        log_warning(f"json_load_relaxed failed for {path}: {e}")
        return None


def iter_jsonl(path: Path) -> Iterator[Any]:
    txt = read_text(path)
    for i, raw in enumerate(txt.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Allow // comments in jsonl as well
        if line.startswith("//"):
            continue
        try:
            yield json.loads(line)
        except Exception as e:
            log_warning(f"jsonl parse error {path}:{i}: {e}")
            continue


def json_load(path: Path) -> Any:
    return json_load_relaxed(path)