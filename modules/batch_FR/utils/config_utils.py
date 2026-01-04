from __future__ import annotations

from typing import Any, Dict


def get_batch_fr_config(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Return the batch_FR_config dict regardless of whether the snapshot is:
    - the full modules_config.json dict (contains 'batch_FR_config'), or
    - already the batch_FR_config dict itself.
    """
    if not isinstance(snapshot, dict):
        return {}
    if "batch_FR_config" in snapshot and isinstance(snapshot.get("batch_FR_config"), dict):
        return dict(snapshot.get("batch_FR_config") or {})
    return dict(snapshot)


def normalize_modules_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize incoming config so engine can accept either:
    - the batch_FR_config dict alone, OR
    - the full modules_config.json dict with {global_config, batch_FR_config, ...}

    Returns a merged, mostly-flat dict where global_config overrides batch config keys.
    """
    if not isinstance(snapshot, dict):
        return {}

    # Full modules_config.json
    if "batch_FR_config" in snapshot:
        base = dict(snapshot.get("batch_FR_config") or {})
        glob = dict(snapshot.get("global_config") or {})
        base.update(glob)  # global overrides
        return base

    # Already batch-only
    return dict(snapshot)