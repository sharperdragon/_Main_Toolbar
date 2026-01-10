from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

from .config_utils import get_batch_fr_config
from .data_defs import Rule
from .FR_global_utils import RULES_PATH

# =========================
# Rules I/O (files, schema, normalization)
# ! Pure file + normalization utilities; no Anki calls here.


# =========================
# Path resolution
# =========================


# rules_io.py lives at: modules/batch_FR/utils/rules_io.py
# parents[2] => modules/
MODULES_DIR = Path(__file__).resolve().parents[2]

# * Add-on root (the folder that contains `modules/`)
ADDON_ROOT = MODULES_DIR.parent


# =========================
# Remove-rule file path resolution helper
# =========================


def resolve_remove_paths_from_config(
    cfg: Dict[str, Any],
) -> tuple[List[Path], Optional[Path]]:
    """Resolve remove-rule file paths from config.

    Returns:
      - remove_paths: list of *_remove_rules.txt (or configured suffix) files to load
      - field_remove_path: optional field_remove_rules file path

    Notes:
      - This function returns only paths that exist on disk.
      - It does not load or shape rules; it only resolves paths.
      - Intended for logging/reporting so engine/logger can list remove files used.
    """
    cfg = get_batch_fr_config(cfg)

    remove_path = cfg.get("remove_path")
    field_remove_path = cfg.get("field_remove_path")
    rules_root = cfg.get("rules_path")
    remove_suffix = cfg.get("remove_rules_suffix")
    field_remove_name = cfg.get("field_remove_rules_name")

    # * IMPORTANT: field_remove_rules must NOT be treated as a generic remove_rules file.
    #   It is handled separately as compiled per-field patterns.
    field_remove_filename = (
        str(field_remove_name or "field_remove_rules.txt").strip().lower()
    )

    remove_paths: List[Path] = []
    seen_remove: set[str] = set()

    def _add_if_file(p: Path) -> None:
        try:
            rp = Path(p).expanduser().resolve()
        except Exception:
            rp = p
        s = str(rp)
        if s in seen_remove:
            return
        try:
            if rp.exists() and rp.is_file():
                seen_remove.add(s)
                remove_paths.append(rp)
        except Exception:
            return

    # 3) Resolve field-remove path (optional)
    field_path_obj: Optional[Path] = None

    # 1) Discover remove files under rules_root via suffix (recursive)
    if rules_root and remove_suffix:
        base = resolve_rules_root(rules_root)
        try:
            if base.exists() and base.is_dir():
                # Stable ordering for deterministic logs
                found = sorted(
                    [p for p in base.rglob(f"*{remove_suffix}") if p.is_file()],
                    key=lambda x: str(x),
                )
                for p in found:
                    # Skip the dedicated field-remove file from generic remove discovery
                    try:
                        if p.name.lower() == field_remove_filename:
                            continue
                    except Exception:
                        pass
                    _add_if_file(p)
        except Exception as e:
            log_warning(
                f"resolve_remove_paths_from_config rglob failed for {base}: {e}"
            )

    # 2) Explicit single remove_path (optional)
    if remove_path:
        try:
            cand = resolve_rule_path(remove_path)
            try:
                if Path(cand).name.lower() == field_remove_filename:
                    # Treat as field-remove source, not a generic remove_rules file
                    if cand.exists() and cand.is_file():
                        field_path_obj = cand.resolve()
                else:
                    _add_if_file(cand)
            except Exception:
                _add_if_file(cand)
        except Exception:
            pass

    if field_remove_path:
        try:
            cand = resolve_rule_path(field_remove_path)
            if cand.exists() and cand.is_file():
                field_path_obj = cand.resolve()
        except Exception:
            field_path_obj = None

    # If not explicitly set, try rules_root / field_remove_name
    if field_path_obj is None and rules_root and field_remove_name:
        try:
            base = resolve_rules_root(rules_root)
            cand = base / field_remove_name
            if cand.exists() and cand.is_file():
                field_path_obj = cand.resolve()
        except Exception:
            field_path_obj = None

    return remove_paths, field_path_obj


def resolve_rule_path(path: Union[str, Path]) -> Path:
    """Resolve a rule path deterministically.

    Accepts:
      - absolute paths
      - relative-to-modules paths:    batch_FR/rules/...
      - relative-to-addon-root paths: modules/batch_FR/rules/...
      - relative-to-rules-root paths: Main/..., zBeta/..., rules/Main/...

    Why:
      `Path(...).resolve()` on a relative path is cwd-based, which can break
      when Anki's working directory is not the add-on folder.

    This function prefers returning the *first* candidate path that exists
    on disk, using these anchors:
      1) add-on root (when the input starts with "modules/")
      2) modules/ (default)
      3) the absolute RULES_PATH (fallback) and its parent
    """
    p = Path(path).expanduser()

    # Absolute paths are already unambiguous
    if p.is_absolute():
        return p.resolve()

    parts = p.parts

    # 1) If the path explicitly starts with "modules/", interpret it relative
    #    to the add-on root.
    if parts and parts[0] == "modules":
        cand = ADDON_ROOT / p
        if cand.exists():
            return cand.resolve()
        return cand.resolve()

    # Candidate list: return the first one that exists
    candidates: List[Path] = []

    # 2) Default: relative to the `modules/` directory
    candidates.append(MODULES_DIR / p)

    # 3) Fallbacks based on RULES_PATH (absolute in FR_global_utils)
    try:
        rp = Path(RULES_PATH).expanduser()
    except Exception:
        rp = None

    if rp is not None:
        # If UI hands back paths like "Main/foo.json" or "zBeta/...",
        # try interpreting them as relative to the rules root.
        candidates.append(rp / p)

        # If UI hands back "rules/Main/foo.json", try relative to the
        # parent of rules root (i.e., batch_FR/).
        if parts and parts[0] == "rules":
            candidates.append(rp.parent / p)

        # If UI hands back "batch_FR/rules/..." this will already be caught
        # by the modules/ candidate above, but keep a fallback anyway.
        candidates.append(rp.parent / (Path("batch_FR") / Path("rules") / p))

    for cand in candidates:
        try:
            if cand.exists():
                return cand.resolve()
        except Exception:
            continue

    # Fall back to a deterministic default even if it doesn't exist
    return (MODULES_DIR / p).resolve()


def resolve_rules_root(root: Union[str, Path]) -> Path:
    """Resolve a rules root path.

    - Expands `~`
    - Accepts both:
      - 'batch_FR/rules' (relative to `modules/`)
      - 'modules/batch_FR/rules' (relative to add-on root)
    """
    return resolve_rule_path(root)


# =========================
# Top-level prefs
# =========================

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
    - If `root` is a directory, recursively searches all subfolders so rules can
      be grouped by their parent folder (e.g. Main, Beta).
    """
    p = resolve_rules_root(root)

    # * Allow pointing directly at a single rule file
    if p.is_file():
        return [p]

    # * If the path does not exist, attempt a RULES_PATH fallback (absolute)
    if not p.exists():
        try:
            rp = Path(RULES_PATH).expanduser()
            if rp.exists() and rp.is_dir():
                p = rp.resolve()
        except Exception:
            pass

    # * If it still does not exist, nothing to discover
    if not p.exists():
        log_warning(
            f"discover_rule_files: rules root does not exist: {p} (input={root})"
        )
        return []

    # * Collect all matching files recursively under the root directory
    exts = ("*.json", "*.jsonl", "*_rules.json", "*_rule.json", "*.txt")
    out: List[Path] = []

    try:
        for ext in exts:
            # ? Use rglob so nested folders like Main/Beta are included
            out.extend(sorted(p.rglob(ext)))
    except Exception as e:
        # ! Discovery failures should not crash the add-on; log and bail
        log_warning(f"discover_rule_files failed for {p}: {e}")
        return []

    # * Deduplicate while preserving order, in case a file matches multiple patterns
    seen: set[str] = set()
    unique: List[Path] = []
    for path in out:
        s = str(path)
        if s in seen:
            continue
        seen.add(s)
        unique.append(path)

    return unique


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
        p = resolve_rule_path(path)
        rules.extend(load_rules_from_file(p))
    return rules


def rules_from_paths_as_rules(
    paths: Sequence[Union[str, Path]],
    *,
    defaults: Optional[Dict[str, Any]] = None,
    fields_all: Optional[List[str]] = None,
) -> List[Rule]:
    """Load rules from paths and return Rule dataclass objects.

    Migration helper so callers can opt into dataclass rules without changing
    the existing dict-based pipeline.
    """
    out: List[Rule] = []
    for path in paths:
        p = resolve_rule_path(path)
        for d in load_rules_from_file(p, defaults=defaults, fields_all=fields_all):
            out.append(to_rule(d))
    return out


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
        sp = Path(source_path).expanduser().resolve()
        # Canonical keys (preferred)
        r["source_file"] = sp.name
        r["source_path"] = str(sp)
        r["source_index"] = int(idx)

        # Back-compat keys (older logger/engine expectations)
        r["_source_file"] = r["source_file"]
        r["_source_path"] = r["source_path"]
        r["_source_index"] = r["source_index"]

        # Historical provenance keys kept for diagnostics
        r["__source_file"] = r["source_path"]
        r["__source_index"] = r["source_index"]
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
    p = resolve_rule_path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rule file not found: {p} (input={path})")

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
    p = resolve_rule_path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rule TXT file not found: {p} (input={path})")
    text = read_text(p)
    out: List[Dict[str, Any]] = []
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
    p = resolve_rule_path(path)
    if not p.exists():
        raise FileNotFoundError(f"Remove patterns file not found: {p} (input={path})")
    text = read_text(p)
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


# --- Added: Defensive bool coercion helper
def coerce_bool(value: Any, *, default: bool) -> bool:
    """Coerce common truthy/falsey values into a real bool.

    Accepts bool/int/float and common strings like true/false/1/0/yes/no/on/off.
    Falls back to `default` when ambiguous.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in ("true", "1", "yes", "y", "on"):
        return True
    if s in ("false", "0", "no", "n", "off"):
        return False
    return default


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
    r["regex"] = coerce_bool(r.get("regex", True), default=True)
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
    r["loop"] = coerce_bool(r.get("loop", False), default=False)

    # Delete guard: accept int or dict
    dc = r.get("delete_chars", {"max_chars": 0, "count_spaces": True})
    if isinstance(dc, int):
        r["delete_chars"] = {
            "max_chars": int(dc),
            "count_spaces": bool(
                (defaults or {}).get("delete_chars", {}).get("count_spaces", True)
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


def to_rule(r: Dict[str, Any]) -> Rule:
    """Convert a normalized rule dict into the Rule dataclass.

    Call this after `normalize_rule()` (and after provenance attachment when available).
    Defensive fallbacks allow incremental migration from dict-based rules.
    """
    query = r.get("query", "")
    exclude_query = r.get("exclude_query", None)
    pattern = r.get("pattern", "")
    replacement = str(r.get("replacement", ""))
    regex = coerce_bool(r.get("regex", True), default=True)
    flags = r.get("flags", "m")
    fields = coerce_fields(r.get("fields", ["ALL"]))
    loop = coerce_bool(r.get("loop", False), default=False)
    delete_chars = r.get("delete_chars", {"max_chars": 0, "count_spaces": True})

    # Provenance (canonical first, then fallbacks)
    source_file = r.get("source_file") or r.get("_source_file")

    # Full path provenance (preferred): keep folder information for grouping/logging
    source_path = r.get("source_path") or r.get("_source_path")

    # Historical key sometimes stored as full path
    if not source_path:
        maybe_path = r.get("__source_file")
        if maybe_path and ("/" in str(maybe_path) or "\\" in str(maybe_path)):
            source_path = str(maybe_path)

    source_index = r.get("source_index")
    if source_index is None:
        source_index = r.get("_source_index")
    if source_index is None:
        source_index = r.get("__source_index")

    # If a full path was stored in source_file, normalize:
    # - source_path keeps the full path
    # - source_file becomes basename
    if source_file and ("/" in str(source_file) or "\\" in str(source_file)):
        try:
            if not source_path:
                source_path = str(source_file)
            source_file = Path(str(source_file)).name
        except Exception:
            source_file = str(source_file)

    # If source_path exists, ensure it is a string
    if source_path is not None:
        try:
            source_path = str(source_path)
        except Exception:
            source_path = None

    try:
        if source_index is not None:
            source_index = int(source_index)
    except Exception:
        source_index = None

    return Rule(
        query=query,
        exclude_query=exclude_query,
        pattern=pattern,
        replacement=replacement,
        regex=regex,
        flags=flags,
        fields=fields,
        loop=loop,
        delete_chars=dict(delete_chars)
        if isinstance(delete_chars, dict)
        else {"max_chars": 0, "count_spaces": True},
        source_file=source_file,
        source_path=source_path,
        source_index=source_index,
    )


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
    *,
    source_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sp: Optional[Path] = None
    if source_path is not None:
        try:
            sp = Path(source_path).expanduser().resolve()
        except Exception:
            sp = None

    idx_in_file = 0
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
        idx_in_file += 1
        norm = normalize_rule(base, defaults, fields_all)
        if sp is not None:
            norm = _attach_provenance(norm, sp, idx_in_file)
        out.append(norm)
    return out


def load_rules_from_config(
    cfg: Dict[str, Any],
    *,
    schema_path: Optional[Union[str, Path]] = None,
    on_error: str = "warn",
) -> List[Dict[str, Any]]:
    cfg = get_batch_fr_config(cfg)
    # * Config wiring for batch_FR rules
    # ! order_preference is the canonical key; order_prefernce is kept for legacy configs.
    # ! defaults / Defaults are normalized here and passed down to load_rules_from_file.
    order_pref = cfg.get("order_preference") or cfg.get("order_prefernce") or {}
    paths = discover_from_config(cfg.get("rules_path", ""), order_pref)

    # Skip remove files (they are handled separately by load_remove_sets_from_config)
    remove_suffix = cfg.get("remove_rules_suffix")
    field_remove_name = cfg.get("field_remove_rules_name")
    if remove_suffix or field_remove_name:
        filtered: List[Path] = []
        for p in paths:
            try:
                name = Path(p).name
            except Exception:
                name = str(p)
            # Skip the dedicated field-remove file
            if field_remove_name and name == field_remove_name:
                continue
            # Skip any *_remove_rules.txt (or whatever suffix is configured)
            if remove_suffix and name.endswith(remove_suffix):
                continue
            filtered.append(p)
        paths = filtered

    defaults = cfg.get("defaults") or cfg.get("Defaults") or {}
    fields_all = cfg.get("fields_all", [])

    rules: List[Dict[str, Any]] = []
    for p in paths:
        rules.extend(load_rules_from_file(p, defaults=defaults, fields_all=fields_all))

    schema = load_rule_schema(schema_path) if schema_path else {}
    validated = maybe_validate_rules(rules, schema, on_error=on_error)
    deduped = dedupe_rules(validated)
    return deduped


def load_remove_sets_from_config(
    cfg: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    defaults = (cfg.get("remove_config") or {}).copy()
    if "flags" not in defaults or not defaults.get("flags"):
        defaults["flags"] = "ms"  # multiline + dotall is safer for remove
    if "loop" not in defaults:
        defaults["loop"] = True
    if "delete_chars" not in defaults or not isinstance(
        defaults.get("delete_chars"), dict
    ):
        defaults["delete_chars"] = {"max_chars": 0, "count_spaces": True}

    fields_all = cfg.get("fields_all", [])

    # Resolve which remove files exist and will be used in this run.
    # (Execution uses the shaped rules below; this is the canonical path resolver.)
    remove_paths, field_path_obj = resolve_remove_paths_from_config(cfg)

    if remove_paths:
        all_remove_rules: List[Dict[str, Any]] = []
        for p in remove_paths:
            pats = load_remove_patterns(p)
            all_remove_rules.extend(
                shape_remove_patterns_to_rules(
                    pats,
                    defaults,
                    fields_all,
                    source_path=p,
                )
            )
        out["remove"] = all_remove_rules

    if field_path_obj is not None:
        frp = field_path_obj
        if frp.exists() and frp.is_file():
            try:
                pats = load_remove_patterns(frp)
                out["field_remove"] = shape_remove_patterns_to_rules(
                    pats,
                    defaults,
                    fields_all,
                    source_path=frp,
                )
            except Exception as e:
                # Non-fatal: field-remove rules should never block the run.
                log_warning(
                    f"load_remove_sets_from_config: failed to load field_remove patterns from {frp}: {type(e).__name__}: {e}"
                )
        else:
            # Non-fatal: file missing.
            log_warning(
                f"load_remove_sets_from_config: optional field_remove patterns file missing; skipping: {frp}"
            )
    return out


# =========================
# Helpers
# =========================
def read_text(path: Path, encoding: str = "utf-8") -> str:
    if not path.exists():
        return ""
    txt = path.read_text(encoding=encoding)
    if txt.startswith("\ufeff"):
        txt = txt.lstrip("\ufeff")
    return txt


def strip_comments(s: str) -> str:
    """* Remove // and /* */ comments from JSON-like text (best-effort)."""
    if not s:
        return ""
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
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
