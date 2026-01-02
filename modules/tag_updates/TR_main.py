from __future__ import annotations
from pathlib import Path
import csv
import json
import re, os
import difflib
from typing import Dict, List, Tuple, Optional, Literal 
from time import strftime
from typing import Dict, Iterable, List, Sequence, Tuple, Set


from aqt import mw
from aqt.qt import QMessageBox
from aqt.operations import CollectionOp, QueryOp
from anki.collection import OpChanges

from .tag_rename_utils import (
    Pair, Preflight, Outcome, RegexRuleDebug, ExecResult,
    _discover_rule_files, _load_pairs_from_csv, _load_pairs_from_json,
    _norm_tag, _normalize_pairs, _resolve_chains,
    _compute_prefixes, _first_segment, _looks_literal_segment, _sanitize_parent_only,
    _rename_tag_token,
    has_left_path_capture, inject_left_path_capture,
    build_substring_pairs_from_prefixes, compress_parent_ops,
)


_BACKREF_RE = re.compile(r"\\([1-9])")

# Display-only: placeholder shown when a backreference (e.g. "\\1") exists but the capture group
# is not safely previewable (e.g. the group is something like ".*" or contains regex operators).
UNKNOWN_GROUP_PLACEHOLDER: str = "…"

DRY_RUN: bool = True

# $ Inputs (module-relative; no user/home hardcoding)
HERE: Path = Path(__file__).parent
RULES_DIR: Path = HERE / "rules"

MODULES_DIR: Path = HERE.parent
CONFIG_PATH: Path = MODULES_DIR / "modules_config.json"

def _load_modules_cfg() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _cfg_tag() -> dict:
    return _load_modules_cfg().get("tag_renaming", {})

# Helper to get global config dict from modules_config.json
def _cfg_global() -> dict:
    return _load_modules_cfg().get("global_config", {})

# Coerce ints from config with bounds
def _cfg_int(bucket: dict, key: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    try:
        v = int(bucket.get(key, default))
    except Exception:
        return default
    if lo is not None and v < lo:
        v = lo
    if hi is not None and v > hi:
        v = hi
    return v


# * Report/log locations + timestamp (defaults; can be overridden by modules_config.json)
TS_FORMAT: str = "%H-%M_%m-%d"
LOG_PATH: Path = Path(os.path.expanduser("~/Desktop/anki_logs"))

# Optional overrides from config (prefer global_config; fall back to tag_renaming)
try:
    _cfgG = _cfg_global()
    _cfgT = _cfg_tag()

    
    if isinstance(_cfgG.get("log_dir"), str):
        LOG_PATH = Path(os.path.expanduser(_cfgG["log_dir"]))
    elif isinstance(_cfgT.get("log_dir"), str):
        LOG_PATH = Path(os.path.expanduser(_cfgT["log_dir"]))

    # ts_format: global_config wins; else fallback to tag_renaming if present
    if isinstance(_cfgG.get("ts_format"), str):
        TS_FORMAT = _cfgG["ts_format"]
    elif isinstance(_cfgT.get("ts_format"), str):
        TS_FORMAT = _cfgT["ts_format"]
except Exception:
    # Fail-safe: keep defaults if config not readable
    pass


#
#* Fallback performance knobs (used only when the fast path is unavailable)
BATCH_COMMIT_SIZE: int = 1000
MAX_EXPANSIONS_PER_RULE: int = 500
PREVIEW_EXAMPLES: int = 10

# * Regex debug logging
DEBUG_REGEX: bool = True
REGEX_DEBUG_EXAMPLES: int = 20  

# Optional overrides from config (prefer global_config; fall back to tag_renaming)
try:
    _cfgG = _cfg_global()
    _cfgT = _cfg_tag()
    REGEX_DEBUG_EXAMPLES = _cfg_int(_cfgG, "regex_debug_examples",
                                    _cfg_int(_cfgT, "regex_debug_examples", REGEX_DEBUG_EXAMPLES),
                                    lo=1, hi=200)
    MAX_EXPANSIONS_PER_RULE = _cfg_int(_cfgG, "max_expansions_per_rule",
                                       _cfg_int(_cfgT, "max_expansions_per_rule", MAX_EXPANSIONS_PER_RULE),
                                       lo=1, hi=100000)
    BATCH_COMMIT_SIZE = _cfg_int(_cfgG, "batch_commit_size",
                                 _cfg_int(_cfgT, "batch_commit_size", BATCH_COMMIT_SIZE),
                                 lo=1, hi=100000)
except Exception:
    pass



def _preview_expand_backrefs_for_label(old_pat: str, new_rep: str) -> str:
    """
    Display-only: try to expand \\1..\\9 in the replacement using literal-ish capture groups
    that appear in the *pattern text itself*.

    If we can't confidently infer the group text, return new_rep unchanged.
    """
    if "\\" not in new_rep:
        return new_rep
    if not _BACKREF_RE.search(new_rep):
        return new_rep

    # Extract simple capturing groups from the pattern text.
    # Keep placeholders so capture group numbering stays correct even when some groups are not previewable.
    groups: List[Optional[str]] = []

    i = 0
    while i < len(old_pat):
        ch = old_pat[i]

        # skip escaped parens
        if ch == "\\" and i + 1 < len(old_pat):
            i += 2
            continue

        if ch == "(":
            # Ignore non-capturing / special groups like (?:  (?=  (?P<  etc.
            nxt = old_pat[i + 1 : i + 3] if i + 2 < len(old_pat) else ""
            if i + 1 < len(old_pat) and old_pat[i + 1] == "?":
                # not a simple capturing group
                i += 1
                i += 1
                continue

            # Find the matching ')', but only if there is no nesting (simple case)
            j = i + 1
            buf = []
            nested = 0
            ok = True
            while j < len(old_pat):
                cj = old_pat[j]
                if cj == "\\" and j + 1 < len(old_pat):
                    # keep escaped chars in buffer as literal
                    buf.append(old_pat[j + 1])
                    j += 2
                    continue
                if cj == "(":
                    nested += 1
                if cj == ")":
                    if nested == 0:
                        break
                    nested -= 1
                buf.append(cj)
                j += 1

            if j >= len(old_pat) or old_pat[j] != ")":
                ok = False

            content = "".join(buf).strip()

            # Always reserve a slot for this capturing group so numbering stays stable.
            groups.append(None)

            # Fill the slot only if the group looks literal-ish (no regex operators).
            if ok and content and not re.search(r"[.\[\]\*\+\?\|\{\}\^$]", content):
                groups[-1] = content

            i = j + 1
            continue

        i += 1

    if not groups:
        return new_rep

    def _sub(m: re.Match) -> str:
        n = int(m.group(1))
        if 1 <= n <= len(groups):
            val = groups[n - 1]
            # If the group is previewable, show its literal content.
            if val is not None:
                return val  # type: ignore[return-value]
            # If the group exists but isn't safely previewable, show a placeholder instead of "\\1".
            return UNKNOWN_GROUP_PLACEHOLDER
        # If the backref index is out of range, leave it untouched.
        return m.group(0)

    return _BACKREF_RE.sub(_sub, new_rep)


def load_all_pairs_for_ui() -> Tuple[List[Pair], List[str], List[Path], List[Path]]:
    """
    Load all CSV/JSON rename pairs and build human-readable labels for a rule picker UI.

    Returns:
        (pairs, labels, csv_files, json_files)
    """
    csv_files, json_files = _discover_rule_files(RULES_DIR)
    csv_pairs: List[Pair] = []
    json_pairs: List[Pair] = []

    for f in csv_files:
        csv_pairs += _load_pairs_from_csv(f)

    for f in json_files:
        json_pairs += _load_pairs_from_json(f)

    # CSV-first, then JSON, same as _run_global_tag_renamer
    raw_pairs = _normalize_pairs([*csv_pairs, *json_pairs])

    labels: List[str] = []
    for p in raw_pairs:
        try:
            preview_new = _preview_expand_backrefs_for_label(p.old, p.new)
            label = f"{p.old} → {preview_new}"
        except Exception:
            # Fallback if attributes are missing for some reason
            label = repr(p)
        labels.append(label)

    return raw_pairs, labels, csv_files, json_files


def load_all_pairs_for_ui_with_sources() -> Tuple[List[Pair], List[str], List[Path], List[Path], List[Path]]:
    """ 
    Load all CSV/JSON rename pairs + build labels, but ALSO return the source file path
    for each returned pair (aligned to the normalized list).

    Returns:
        (pairs, labels, pair_sources, csv_files, json_files)

    Notes:
        - pair_sources[i] corresponds to pairs[i]
        - Normalization may drop/merge pairs, so we re-align sources after _normalize_pairs().
    """
    csv_files, json_files = _discover_rule_files(RULES_DIR)

    loaded_pairs: List[Pair] = []
    loaded_sources: List[Path] = []

    # 1) Load CSV pairs (CSV-first to match execution order)
    for f in csv_files:
        these = _load_pairs_from_csv(f)
        for p in these:
            loaded_pairs.append(p)
            loaded_sources.append(f)

    # 2) Load JSON pairs
    for f in json_files:
        these = _load_pairs_from_json(f)
        for p in these:
            loaded_pairs.append(p)
            loaded_sources.append(f)

    # Normalize the combined list (may drop/merge pairs)
    raw_pairs = _normalize_pairs(loaded_pairs)

    # 3) Re-align sources after normalization using a stable key
    def _pair_key(p: Pair) -> Tuple[str, str, str, str]:
        return (
            getattr(p, "old", ""),
            getattr(p, "new", ""),
            str(getattr(p, "src", "")),
            str(getattr(p, "kind", "")),
        )

    # First-seen source for each key
    src_by_key: Dict[Tuple[str, str, str, str], Path] = {}
    for p, src_path in zip(loaded_pairs, loaded_sources):
        k = _pair_key(p)
        if k not in src_by_key:
            src_by_key[k] = src_path

    labels: List[str] = []
    pair_sources: List[Path] = []

    for p in raw_pairs:
        # Human label (same style as load_all_pairs_for_ui)
        try:
            preview_new = _preview_expand_backrefs_for_label(p.old, p.new)
            label = f"{p.old} → {preview_new}"
        except Exception:
            label = repr(p)
        labels.append(label)

        # Source alignment (best-effort)
        pair_sources.append(src_by_key.get(_pair_key(p), Path("<unknown>")))

    return raw_pairs, labels, pair_sources, csv_files, json_files

def _prompt_and_run(parent):
    """
    Ask the user to pick 'Dry Run' or 'Apply Changes' for this run only.
    Does not mutate the global DRY_RUN; passes a local flag onward.
    """
    box = QMessageBox(parent)
    box.setWindowTitle("Global Tag Renamer — Choose Mode")
    box.setText("How would you like to run the Global Tag Renamer?")
    dry_btn = box.addButton("Dry Run (no changes)", QMessageBox.AcceptRole)  # safe default
    live_btn = box.addButton("Apply Changes", QMessageBox.DestructiveRole)
    cancel_btn = box.addButton(QMessageBox.Cancel)

    box.exec()
    clicked = box.clickedButton()
    if clicked is cancel_btn:
        return

    mode_dry_run = (clicked is dry_btn)
    _run_global_tag_renamer(parent=parent, dry_run=mode_dry_run)



def _run_global_tag_renamer(parent, dry_run: bool | None = None) -> None:
    """
    Compatibility wrapper used by the standalone Global Tag Renamer entrypoint.

    - Resolves dry_run flag (falling back to the global default)
    - Loads all rule pairs from CSV/JSON
    - Delegates to _run_tag_renamer_core
    """
    # Decide runtime mode (prefer user pick; fall back to global default)
    run_dry = DRY_RUN if (dry_run is None) else dry_run

    raw_pairs, _labels, csv_files, json_files = load_all_pairs_for_ui()

    _run_tag_renamer_core(
        parent=parent,
        raw_pairs=raw_pairs,
        run_dry=run_dry,
        csv_files=csv_files,
        json_files=json_files,
    )


def _run_tag_renamer_core(
    parent,
    raw_pairs: Sequence[Pair],
    run_dry: bool,
    csv_files: list[Path],
    json_files: list[Path],
    show_preflight_prompt: bool = True,
    show_final_summary: bool = True,
) -> None:
    """
    Core pipeline for the tag renamer.

    This is shared by:
      - _run_global_tag_renamer(..)  (standalone action)
      - run_tag_renamer_subset(..)   (Tag Updates combined picker)

    Args:
        parent: Parent QWidget for dialogs.
        raw_pairs: Sequence of Pair rename operations.
        run_dry: If True, perform a dry run (no changes).
        csv_files: List of CSV rule file paths used this run.
        json_files: List of JSON rule file paths used this run.
        show_preflight_prompt: If True, display the “Proceed with global rename?”
            confirmation dialog before executing. Callers that already confirmed
            with the user (like Tag Updates combined picker) can pass False to
            avoid a second confirmation window.
        show_final_summary: If True, display the final “Global Tag Renamer — Done”
            summary popup. Callers like Tag Updates that want to provide their own
            combined summary can pass False to suppress this extra window.
    """
    if parent is None:
        parent = mw

    if not raw_pairs:
        QMessageBox.warning(parent, "Global Tag Renamer", f"No rule files found in: {RULES_DIR}")
        return

    # Resolve allow_regex from config per run
    cfg = _cfg_tag()
    allow_regex = bool(cfg.get("allow_regex", True))

    # Preflight against the live collection using QueryOp for async safety
    def _pf(col):
        return _preflight(col, raw_pairs, allow_regex=allow_regex)

    def _after_preflight(pf: Preflight):
        # * Write per-rule regex debug file (quiet; does not affect popup)
        _write_regex_debug(pf, run_dry, allow_regex, csv_files, json_files)
        # Collapse cascades so A→B and B→C becomes A→C before executing
        pairs_for_exec, _cycles_ignored = _resolve_chains(pf.valid_pairs)
        n_pairs = len(pairs_for_exec)
        # Sort so deeper tags (more "::") are renamed first
        pairs_for_exec.sort(key=lambda p: p.old.count("::"), reverse=True)

        # * Optional preflight confirmation popup
        if show_preflight_prompt:
            msg = (
                f"Loaded pairs: {pf.total_loaded} (CSV files: {len(csv_files)}; JSON files: {len(json_files)})\n"
                f"After normalize/resolve: {pf.after_normalize}\n"
                f"Valid parent rename ops: {n_pairs}\n"
                f"Skipped (old tag not found): {len(pf.skipped_nonexistent)}\n"
                f"Cycles blocked: {len(pf.cycles_blocked)}\n\n"
                f"DRY_RUN (this run) = {run_dry}\n"
                f"ALLOW_REGEX (config) = {allow_regex}\n"
                "\nProceed with global rename?"
            )
            if (
                QMessageBox.question(
                    parent,
                    "Global Tag Renamer — Preflight",
                    msg,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return

        # Execute in background with a collection handle (single undo step)
        def _exec(col):
            out = _execute(col, pairs_for_exec, dry_run=run_dry)
            # Build an OpChanges payload so Anki knows what to refresh.
            # Dry run ⇒ no changes; live run ⇒ tags and notes changed.
            try:
                changes = OpChanges() if run_dry or not pairs_for_exec else OpChanges(note=True, tag=True)
            except TypeError:
                # Fallback for odd signatures; worst case, return empty changes.
                changes = OpChanges()
            return ExecResult(outcome=out, changes=changes)

        def _on_success(res: ExecResult):
            # Finish progress UI then show results
            mw.progress.finish()
            out = res.outcome
            _write_report(out, pf, run_dry, allow_regex, csv_files, json_files)
            summary = (
                f"Pairs applied: {len(out.applied)}\n"
                f"Pairs skipped: {len(out.skipped)}\n"
                f"Total notes changed: {out.total_notes_changed}"
            )
            # If nothing actually changed, add a brief hint so the user understands why.
            if out.total_notes_changed == 0 and out.applied:
                summary += (
                    "\n\nNo notes were changed.\n"
                    "This usually means none of the 'old' tags from your rules\n"
                    "exist in this collection (or they were already renamed)."
                )
            if show_final_summary:
                QMessageBox.information(parent, "Global Tag Renamer — Done", summary)

        def _on_failure(e):
            # Ensure progress UI is closed on error
            mw.progress.finish()
            QMessageBox.critical(parent, "Global Tag Renamer — Error", str(e))

        # Start a labeled progress indicator (compatible on your build)
        mw.progress.start(label="Renaming tags globally…", immediate=False)

        CollectionOp(parent=mw, op=_exec) \
            .success(_on_success) \
            .failure(_on_failure) \
            .run_in_background()

    # Kick off preflight in background (fixes .run_now crash on your Anki build)
    QueryOp(
        parent=mw,
        op=_pf,
        success=_after_preflight,
    ).failure(
        lambda e: QMessageBox.critical(parent, "Global Tag Renamer — Error", str(e))
    ).run_in_background()




def _preflight(col, pairs: Sequence[Pair], allow_regex: bool) -> Preflight:
    normalized = _normalize_pairs(pairs)
    resolved, cycles = _resolve_chains(normalized)

    try:
        existing_tags: List[str] = col.tags.all()
    except Exception:
        existing_tags = list(col.tags.all())

    # Build parent universe (prefixes) once
    prefixes, root_to_prefixes = _compute_prefixes(existing_tags)

    valid: List[Pair] = []              # parent rename ops only
    skipped: List[Pair] = []
    regex_no_match: List[Tuple[str, str, str]] = []
    regex_hits: Dict[str, int] = {}
    regex_debug: List[RegexRuleDebug] = []

    # 1) CSV literal parents → single op if parent exists (case-sensitive)
    for p in resolved:
        if p.src == "csv" and p.kind == "literal":
            old_parent = _norm_tag(p.old)
            new_parent = _norm_tag(p.new)
            if not old_parent or not new_parent or old_parent == new_parent:
                continue
            if old_parent in prefixes:
                valid.append(Pair(old_parent, new_parent, p.src, p.kind))
            else:
                skipped.append(Pair(p.old, p.new, p.src, p.kind))

    # 2) JSON regex parents → match PREFIXES ONLY (no child expansion)
    if allow_regex:
        for p in resolved:
            if not (p.src == "json" and p.kind == "regex"):
                continue
            # * Fast path for very common literal-substring conversions like `_and_` -> `_&_`.
            #   Your previous debug showed regex + fullmatch over ~50k prefixes is slow.
            #   If the user intends a plain substring swap, do it without regex.
            if p.old == "_and_" and p.new == "_&_":
                # Build all old->new parent pairs using a literal substring swap (fast).
                expanded_pairs = build_substring_pairs_from_prefixes(
                    prefixes,
                    old_sub="_and_",
                    new_sub="_&_",
                    src=p.src,
                    kind=p.kind,
                )

                # Keep only top-level renames; children move automatically when parents rename.
                compressed_pairs = compress_parent_ops(expanded_pairs)

                # Examples for debug (cap output)
                examples: List[Tuple[str, str]] = []
                for pp in expanded_pairs[:REGEX_DEBUG_EXAMPLES]:
                    examples.append((pp.old, pp.new))

                # Emit debug entry similar to regex rules
                meta: List[Tuple[str, str]] = []
                meta.append(("fast-path", "literal substring replace"))
                meta.append(("expanded", str(len(expanded_pairs))))
                meta.append(("compressed", str(len(compressed_pairs))))

                regex_debug.append(RegexRuleDebug(
                    pattern=p.old, replacement=p.new, scope="path",
                    compile_ok=True, compile_error=None, pool="prefixes",
                    pool_size=len(prefixes), matched_count=len(expanded_pairs),
                    examples=(meta + examples), truncated=False,
                    orig_pattern=p.old, orig_replacement=p.new,
                    normalized=False,
                ))

                if expanded_pairs:
                    # Track hits by a stable key for the report table.
                    regex_hits[p.old] = len(expanded_pairs)
                else:
                    regex_no_match.append((p.old, p.new, "path"))

                # Add the *compressed* pairs to the valid ops list.
                valid.extend(compressed_pairs)
                continue
            patt, repl, _ = _sanitize_parent_only(p.old, p.new)
            # * Normalize for full-path matching:
            #     optional prefix ^(?:.*::)? so user capture group indices stay stable.
            orig_patt, orig_repl = patt, repl  # for debug visibility
            if not has_left_path_capture(patt):
                patt = inject_left_path_capture(patt)
                # NOTE: inject_left_path_capture is non-capturing by default, so we
                # deliberately do NOT bump $n group references in the replacement.

            try:
                rgx = re.compile(patt)  # case-sensitive
            except re.error as e:
                regex_no_match.append((p.old, p.new, "path"))
                regex_debug.append(RegexRuleDebug(
                    pattern=p.old, replacement=p.new, scope="path",
                    compile_ok=False, compile_error=str(e), pool="prefixes",
                    pool_size=len(prefixes), matched_count=0, examples=[], truncated=False))
                continue

            first = _first_segment(patt)
            if _looks_literal_segment(first) and first in root_to_prefixes:
                cand_prefixes = set(root_to_prefixes[first])
                pool_name = f"root:{first}"
                pool_size = len(cand_prefixes)
            else:
                cand_prefixes = prefixes
                pool_name = "prefixes"
                pool_size = len(prefixes)

            expanded = 0
            examples: List[Tuple[str, str]] = []
            examples_meta: List[Tuple[str, str]] = []
            if (orig_patt, orig_repl) != (patt, repl):
                examples_meta.append((f"orig: {orig_patt}", f"norm: {patt}"))
            for pref in cand_prefixes:
                if not rgx.fullmatch(pref):
                    continue
                new_pref = _norm_tag(rgx.sub(repl, pref, count=1))
                if new_pref == pref:
                    continue
                valid.append(Pair(pref, new_pref, p.src, p.kind))
                if len(examples) < REGEX_DEBUG_EXAMPLES:
                    examples.append((pref, new_pref))
                expanded += 1

            regex_debug.append(RegexRuleDebug(
                pattern=patt, replacement=repl, scope="path",
                compile_ok=True, compile_error=None, pool=pool_name,
                pool_size=pool_size, matched_count=expanded,
                examples=(examples_meta + examples), truncated=False,
                orig_pattern=orig_patt, orig_replacement=orig_repl,
                normalized=((orig_patt, orig_repl) != (patt, repl))
            ))

            if expanded > 0:
                regex_hits[patt] = expanded
            else:
                regex_no_match.append((patt, repl, "path"))
    else:
        # Regex disabled: ignore regex rules, literals already handled
        pass

    # * Final compression: avoid renaming child tags when a parent rename already exists.
    #   This keeps huge expansions from bogging down execution.
    try:
        valid = compress_parent_ops(valid)
    except Exception:
        # Best-effort only; never block preflight on compression.
        pass

    return Preflight(
        total_loaded=len(pairs),
        after_normalize=len(resolved),
        cycles_blocked=cycles,
        valid_pairs=valid,
        skipped_nonexistent=skipped,
        regex_no_match=regex_no_match or [],
        regex_hits=regex_hits or {},
        existing_tags=existing_tags,
        regex_debug=regex_debug or [],
    )


def _build_tag_regex_query(tag: str) -> str:
    """
    Build a safe tag:re: query for Anki that matches either the exact tag
    or any child under that parent tag. Escapes regex metacharacters and colons
    so Anki's search parser does not treat ':' as a keyword separator.
    """
    base = re.escape(tag)
    # Escape colons for Anki's search language (they are not escaped by re.escape)
    base = base.replace(":", r"\:")
    # Match exact tag or any child (prefix::child)
    suffix = r"(\:\:|$)"
    pattern = f"^{base}{suffix}"
    return f"tag:re:{pattern}"


def _execute(col, pairs: Sequence[Pair], dry_run: bool) -> Outcome:
    applied: List[Tuple[str, str, int, str]] = []
    skipped: List[Tuple[str, str, str]] = []
    warnings: List[str] = []
    total_changed = 0

    if dry_run:
        for p in pairs:
            # Estimate impacted notes cheaply
            try:
                query = _build_tag_regex_query(p.old)
                count = len(col.find_notes(query))
            except Exception as e:
                # ! If count fails, keep going but log a warning
                warnings.append(f'dry-run count failed for "{p.old}"→"{p.new}": {e!s}')
                count = 0
            applied.append((p.old, p.new, count, "dry-run"))
        return Outcome(applied=applied, skipped=skipped, warnings=warnings, total_notes_changed=0)

    # Try fast, global rename via TagManager if available; otherwise fallback.
    def has_fast() -> bool:
        return hasattr(col.tags, "rename")

    for p in pairs:
        notes_changed = 0
        fast_used = False

        # * Fast path: use TagManager.rename if available
        if has_fast():
            try:
                # Fast path: move subtree too, as Anki's TagManager.rename handles hierarchies.
                # Some builds expose rename(old, new); if signature changes, fallback will handle it.
                col.tags.rename(p.old, p.new)
                fast_used = True
            except Exception as e:
                # ? Only the rename itself failed; log and fall back
                warnings.append(f'Fast path rename failed for "{p.old}"→"{p.new}": {e!s}')

        if fast_used:
            # * Rename succeeded; best-effort count on the NEW tag.
            #   If counting fails, we STILL treat this pair as applied.
            try:
                query = _build_tag_regex_query(p.new)
                notes_changed = len(col.find_notes(query))
            except Exception as e:
                warnings.append(f'Fast path count failed for "{p.old}"→"{p.new}": {e!s}')
                notes_changed = 0

            applied.append((p.old, p.new, notes_changed, "fast"))
            total_changed += notes_changed
            # Skip fallback entirely; tags are already renamed
            continue

        # Fallback: chunked per-note updates (still global scope)
        try:
            query = _build_tag_regex_query(p.old)
            nids = col.find_notes(query)
        except Exception as e:
            skipped.append((p.old, p.new, f"search failed: {e!s}"))
            continue

        if not nids:
            skipped.append((p.old, p.new, "no notes found"))
            continue

        # Process in chunks (reduces index churn)
        for i in range(0, len(nids), BATCH_COMMIT_SIZE):
            chunk = nids[i : i + BATCH_COMMIT_SIZE]
            for nid in chunk:
                note = col.get_note(nid)
                original = list(note.tags)
                if not original:
                    continue
                new_tags = [_rename_tag_token(t, p.old, p.new) for t in original]
                # De-dupe and stable sort
                new_tags = sorted(set(new_tags))
                if new_tags != original:
                    note.tags = new_tags
                    col.update_note(note)
                    notes_changed += 1

        applied.append((p.old, p.new, notes_changed, "fallback"))
        total_changed += notes_changed

    # Attempt a tidy pass to clear unused tag rows (best-effort)
    try:
        if hasattr(col.tags, "clear_unused_tags"):
            col.tags.clear_unused_tags()
    except Exception:
        pass

    return Outcome(applied=applied, skipped=skipped, warnings=warnings, total_notes_changed=total_changed)

# =========================
# Reporting
# =========================
def _write_report(out: Outcome, pf: Preflight, run_mode_dry: bool, allow_regex: bool, csv_files: list[Path], json_files: list[Path]) -> Path:
    LOG_PATH.mkdir(parents=True, exist_ok=True)
    stamp = strftime(TS_FORMAT)
    path = LOG_PATH / f"Global_Tag_Renamer_{stamp}.md"

    lines: List[str] = []
    lines.append(f"# Global Tag Renamer — {stamp}\n")
    lines.append("## Settings\n")
    lines.append(f"- DRY_RUN (default): {DRY_RUN}")
    lines.append(f"- DRY_RUN (this run): {run_mode_dry}")
    lines.append(f"- ALLOW_REGEX (config): {allow_regex}")
    lines.append("")
    lines.append("## Preflight\n")
    lines.append(f"Loaded pairs: {pf.total_loaded} (CSV files: {len(csv_files)}, JSON files: {len(json_files)})")
    lines.append(f"After normalize/resolve: {pf.after_normalize}")
    lines.append(f"Valid parent rename ops: {len(pf.valid_pairs)}")
    lines.append(f"Skipped (old tag not found): {len(pf.skipped_nonexistent)}")
    lines.append(f"Cycles blocked: {len(pf.cycles_blocked)}")

    removed_by_norm_resolve = pf.total_loaded - pf.after_normalize
    lit_not_found = sum(
        1 for p in pf.skipped_nonexistent
        if isinstance(p, Pair) and getattr(p, 'kind', 'literal') == 'literal'
    )
    lines.append("### Why 'Valid' < loaded")
    lines.append(f"- Pairs removed by normalize/resolve: {removed_by_norm_resolve}")
    lines.append(f"- Regex rules with 0 matches: {len(getattr(pf, 'regex_no_match', []) )}")
    lines.append(f"- Literal 'old' tags not found: {lit_not_found}")
    lines.append(f"- Cycles blocked: {len(pf.cycles_blocked)}")
    lines.append("")
    if pf.skipped_nonexistent:
        lines.append("### Literal rules where 'old' tag not found (case-sensitive)")
        lines.append("| old | new | case-hint | suggestions |")
        lines.append("|---|---|---|---|")
        # Build a lower-case index for case-hint and suggestions
        lower_index = {t.lower(): t for t in (pf.existing_tags or [])}
        for p in pf.skipped_nonexistent[:200]:  # cap list for report size
            if not isinstance(p, Pair) or getattr(p, 'kind', 'literal') != 'literal':
                continue
            case_hint = "case-only?" if p.old.lower() in lower_index else ""
            sugg = difflib.get_close_matches(p.old, (pf.existing_tags or []), n=3, cutoff=0.85)
            lines.append(f"| `{p.old}` | `{p.new}` | {case_hint} | {', '.join('`'+s+'`' for s in sugg)} |")
        lines.append("")
    if getattr(pf, 'regex_no_match', None):
        lines.append("### Regex rules with 0 matches")
        lines.append("| pattern | replacement | scope |")
        lines.append("|---|---|---|")
        for pat, repl, scope in pf.regex_no_match:
            lines.append(f"| `{pat}` | `{repl}` | {scope} |")
        lines.append("")
    if getattr(pf, 'regex_hits', None):
        lines.append("### Regex rules that matched")
        lines.append("| pattern | replacement | parents_matched |")
        lines.append("|---|---|---:|")
        repl_by_pat = {d.pattern: d.replacement for d in (pf.regex_debug or []) if d.compile_ok}
        for pat, cnt in sorted(pf.regex_hits.items(), key=lambda x: -x[1]):
            repl = repl_by_pat.get(pat, "")
            lines.append(f"| `{pat}` | `{repl}` | {cnt} |")
        lines.append("")
    if pf.cycles_blocked:
        lines.append("### Cycles Blocked")
        for a, b in pf.cycles_blocked:
            lines.append(f"- `{a}` ↔ `{b}`")
        lines.append("")
    lines.append("## Outcome\n")
    lines.append(f"- Pairs applied: {len(out.applied)}")
    lines.append(f"- Pairs skipped: {len(out.skipped)}")
    lines.append(f"- Total notes changed: {out.total_notes_changed}")
    if out.total_notes_changed == 0 and out.applied:
        lines.append("")
        lines.append(
            "No notes were changed. This usually means none of the 'old' tags from your "
            "rules exist in this collection (or they were already renamed)."
        )
    # Show the exact tag search used for counts (helps debug "why so few?")
    if out.applied:
        lines.append("")
        lines.append("### Tag queries")
        lines.append("| old | query | matched_notes |")
        lines.append("|---|---|---:|")
        for old, _new, cnt, _mode in out.applied:
            query = _build_tag_regex_query(old)
            lines.append(f"| `{old}` | `{query}` | {cnt} |")
    if out.warnings:
        lines.append("")
        lines.append("### Warnings")
        for w in out.warnings:
            lines.append(f"- {w}")
    lines.append("")
    if out.applied:
        lines.append("### Applied")
        lines.append("| old | new | notes_changed | mode |")
        lines.append("|---|---|---:|---|")
        for old, new, cnt, mode in out.applied:
            # Keep table compact; avoid huge files
            lines.append(f"| `{old}` | `{new}` | {cnt} | {mode} |")
    if out.skipped:
        lines.append("")
        lines.append("### Skipped")
        lines.append("| old | new | reason |")
        lines.append("|---|---|---|")
        for old, new, reason in out.skipped:
            lines.append(f"| `{old}` | `{new}` | {reason} |")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def run_tag_renamer_subset(
    parent,
    pairs: Sequence[Pair],
    run_dry: bool,
    csv_files: list[Path],
    json_files: list[Path],
) -> None:
    """
    Run the tag renamer on a caller-provided subset of Pair rules.

    Intended for use by the Tag Updates combined picker, which:
      - calls load_all_pairs_for_ui() to build the full list
      - lets the user choose a subset of rules
      - passes that subset into this helper
    """
    # Ensure we always pass a concrete list to the core
    _run_tag_renamer_core(
        parent=parent,
        raw_pairs=list(pairs),
        run_dry=run_dry,
        csv_files=csv_files,
        json_files=json_files,
        show_preflight_prompt=False,   # Tag Updates already confirmed; skip preflight popup
        show_final_summary=False,      # Tag Updates will show its own summary; suppress extra window
    )

# Toolbar entrypoint for _Main_Toolbar launcher
def run_tag_renamer(*_args, **_kwargs):
    from aqt import mw as _mw
    _prompt_and_run(parent=_mw)

# =========================
# Regex debug diagnostics
# =========================
def _write_regex_debug(pf: Preflight, run_mode_dry: bool, allow_regex: bool, csv_files: list[Path], json_files: list[Path]) -> Path | None:
    """Write a per-rule regex diagnostics file to LOG_PATH."""
    if not DEBUG_REGEX or not pf.regex_debug:
        return None
    LOG_PATH.mkdir(parents=True, exist_ok=True)
    stamp = strftime(TS_FORMAT)
    path = LOG_PATH / f"Regex_Debug_{stamp}.md"
    lines: List[str] = []
    lines.append(f"# Regex Debug — {stamp}\n")
    lines.append("## Sources\n")
    lines.append(f"- CSV files: {len(csv_files)}")
    lines.append(f"- JSON files: {len(json_files)}")
    lines.append("")
    lines.append("## Settings\n")
    lines.append(f"- DRY_RUN (default): {DRY_RUN}")
    lines.append(f"- DRY_RUN (this run): {run_mode_dry}")
    lines.append(f"- ALLOW_REGEX (config): {allow_regex}")
    lines.append(f"- MAX_EXPANSIONS_PER_RULE: {MAX_EXPANSIONS_PER_RULE}")
    lines.append(f"- REGEX_DEBUG_EXAMPLES: {REGEX_DEBUG_EXAMPLES}")
    lines.append("")
    lines.append("## Summary\n")
    total = len(pf.regex_debug)
    comp_fail = sum(1 for d in pf.regex_debug if not d.compile_ok)
    zero_match = sum(1 for d in pf.regex_debug if d.compile_ok and d.matched_count == 0)
    some_match = sum(1 for d in pf.regex_debug if d.matched_count > 0)
    lines.append(f"- Total JSON regex rules: {total}")
    lines.append(f"- Compile errors: {comp_fail}")
    lines.append(f"- 0-match rules: {zero_match}")
    lines.append(f"- Matched ≥1: {some_match}")
    lines.append("")
    # * [Examples moved below] Keep details table compact
    lines.append("## Per-rule details\n")
    lines.append("| # | scope | compile | pool | pool_size | matches | truncated | pattern | replacement |")
    lines.append("|---:|---|---|---|---:|---:|---:|---|---|")
    for i, d in enumerate(pf.regex_debug, 1):
        compile_str = "ok" if d.compile_ok else f"ERR: {d.compile_error}"
        # Optional normalization chip if present (data.py)
        if getattr(d, "normalized", False):
            compile_str += " · ✓norm"
        lines.append(
            f"| {i} | {d.scope} | {compile_str} | {d.pool} | {d.pool_size} | "
            f"{d.matched_count} | {int(d.truncated)} | `{d.pattern}` | `{d.replacement}` |"
        )

    # ? New section with separate examples table per rule
    lines.append("\n### Per-rule Examples\n")
    for i, d in enumerate(pf.regex_debug, 1):
        # Render a block if the rule has examples, or if it was normalized (to show orig vs used)
        if not d.examples and not getattr(d, "normalized", False) and not getattr(d, "orig_pattern", None):
            continue

        lines.append(f"\n**Rule {i}**")

        # Show normalization delta if available
        if getattr(d, "normalized", False) or (
            getattr(d, "orig_pattern", None) and (d.orig_pattern != d.pattern or d.orig_replacement != d.replacement)
        ):
            lines.append("\n- normalization:")
            if getattr(d, "orig_pattern", None):
                lines.append(f"  - orig pattern: `{d.orig_pattern}`")
            if getattr(d, "orig_replacement", None):
                lines.append(f"  - orig replacement: `{d.orig_replacement}`")
            lines.append(f"  - used pattern: `{d.pattern}`")
            lines.append(f"  - used replacement: `{d.replacement}`")

        # Examples sub-table
        if d.examples:
            lines.append("\n| matched prefix | new prefix |")
            lines.append("|---|---|")
            shown = 0
            for a, b in d.examples:
                if shown >= REGEX_DEBUG_EXAMPLES:
                    break
                lines.append(f"| `{a}` | `{b}` |")
                shown += 1
            if d.truncated or shown < len(d.examples):
                rest = max(0, len(d.examples) - shown)
                lines.append(f"\n*…{rest} more example(s) not shown*")

    # Suggestions for 0-match rules (best-effort)
    zero = [d for d in pf.regex_debug if d.compile_ok and d.matched_count == 0]
    if zero:
        lines.append("\n### Suggestions for 0-match rules\n")
        for d in zero:
            if pf.existing_tags:
                pool = pf.existing_tags if d.scope == "path" else sorted({t.split('::', 1)[0] for t in pf.existing_tags})
            else:
                pool = []
            sugg = difflib.get_close_matches(d.pattern, pool, n=5, cutoff=0.8)
            lines.append(f"- `{d.pattern}` → suggestions: {', '.join('`'+s+'`' for s in sugg) if sugg else '(none)'}")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path