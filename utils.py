# ? Utility helpers and shared state for managing custom toolbar tools in Anki add-ons.

# pyright: reportMissingImports=false
# mypy: disable_error_code=import
import os
import json
from aqt import mw
from aqt.qt import QAction, QMenu, QIcon
from aqt.utils import showText
from collections import OrderedDict
from typing import Optional
_submenu_cache: "OrderedDict[str, object]" = OrderedDict()  # submenu_name -> QMenu

# ? Stores registered toolbar actions, grouped by submenu path (e.g., "Top::Sub::Leaf")
addon_actions = {}

# Load and return JSON data from a file path
def load_json_file(path):
    """Load and return JSON data from the given file path."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

 # ? Global configuration loaded from ./assets/config.json
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "assets", "config.json")
CONFIG = load_json_file(CONFIG_PATH)

def _svg_candidate(path: str) -> str:
    """
    Convert an icon path candidate to SVG-only form.
    Rules:
    - .svg stays .svg
    - .png becomes .svg
    - no extension becomes .svg
    - any other extension is rejected
    """
    clean = (path or "").strip().replace("\\", "/")
    if not clean or clean.endswith("/"):
        return ""

    root, ext = os.path.splitext(clean)
    ext = ext.lower()
    if ext == ".svg":
        return clean
    if ext in ("", ".png"):
        return f"{root}.svg" if root else ""
    return ""


def normalize_icon_reference(path: str) -> str:
    """
    Normalize user/config icon inputs into an existing SVG reference.
    Returns:
      - absolute path (for absolute inputs)
      - :assets/... (for pseudo resource inputs)
      - addon-relative path (icons/... or assets/...)
      - "" when icon is invalid/missing/non-SVG-resolvable
    """
    raw = str(path or "").strip().replace("\\", "/")
    if not raw:
        return ""

    addon_dir = os.path.dirname(__file__)

    if raw.startswith(":assets/"):
        rel = _svg_candidate(raw.replace(":assets/", "", 1))
        if not rel:
            return ""
        abs_path = os.path.join(addon_dir, "assets", rel)
        return f":assets/{rel}" if os.path.exists(abs_path) else ""

    # Strict mode: allow only :assets/... pseudo-resource form.
    if raw.startswith(":"):
        return ""

    if os.path.isabs(raw):
        abs_candidate = _svg_candidate(raw)
        return abs_candidate if abs_candidate and os.path.exists(abs_candidate) else ""

    rel = raw if raw.startswith(("assets/", "icons/")) else os.path.join("icons", raw)
    rel = _svg_candidate(rel)
    if not rel:
        return ""
    abs_path = os.path.join(addon_dir, rel)
    return rel if os.path.exists(abs_path) else ""


def resolve_icon_path(path):
    """
    Resolve icon path for runtime QIcon loading.
    This uses strict SVG normalization and returns an absolute filesystem path.
    """
    normalized = normalize_icon_reference(path)
    if not normalized:
        return ""

    addon_dir = os.path.dirname(__file__)

    if normalized.startswith(":assets/"):
        return os.path.join(addon_dir, "assets", normalized.replace(":assets/", "", 1))

    if os.path.isabs(normalized):
        return normalized

    return os.path.join(addon_dir, normalized)


def show_icon_drop_warning(context: str, dropped_icons: list[tuple[str, str]]) -> None:
    """
    Show a single aggregated warning for icons that were dropped because they
    could not be resolved to existing SVG files.
    """
    if not dropped_icons:
        return

    seen = set()
    lines = []
    for name, icon_path in dropped_icons:
        clean_name = (name or "<unnamed>").strip() or "<unnamed>"
        clean_icon = (icon_path or "").strip() or "<empty>"
        key = (clean_name, clean_icon)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- {clean_name}: {clean_icon}")

    if not lines:
        return

    showText(
        "These icons were removed because they do not resolve to existing SVG files "
        f"while {context}:\n\n" + "\n".join(lines),
        title=CONFIG.get("toolbar_title", "Custom Tools") + " Icon Warning",
    )


def format_config_label(addon: str, config: dict) -> str:
    """
    Build the display label for the Add-ons Configurations submenu using:
      [emoji␠][nickname OR prettified addon name]
    where nickname is sourced from config["addon_nicknames"].
    """
    emojis = (config.get("addon_emojis") or {})
    nicknames = (config.get("addon_nicknames") or {})

    emoji = emojis.get(addon, "") or ""
    # Prefer nickname if provided; fall back to prettified addon key
    display = nicknames.get(addon) or addon.replace("_", " ").replace("-", " ").title()

    return f"{emoji} {display}" if emoji else display


 # ? Rebuild "Custom Tools" menus based on current registrations (supports '::' nesting)
def _refresh_menu():
    """Rebuilds all top-level menus based on registered addon tools and submenu structure."""
    # ? Remove existing menus that match the current set of top-level registered names
    existing_titles = {submenu.split("::")[0] if submenu else CONFIG.get("toolbar_title", "Custom Tools") 
                       for submenu in addon_actions}
    for action in mw.form.menubar.actions():
        if action.menu() and action.menu().title() in existing_titles:
            mw.form.menubar.removeAction(action)

    # Recursively build nested actions based on '::' submenu structure
    def add_nested_action(menu: QMenu, path: list[str], name, callback, icon=None, enabled=True):
        if not path:
            action = QAction(name, mw)
            action.triggered.connect(callback)
            action.setEnabled(enabled)
            if icon:
                action.setIcon(QIcon(resolve_icon_path(icon)))
            menu.addAction(action)
        else:
            head, *tail = path
            sub = next((a.menu() for a in menu.actions() if a.menu() and a.menu().title() == head), None)
            if not sub:
                sub = QMenu(head, mw)
                menu.addMenu(sub)
            add_nested_action(sub, tail, name, callback, icon, enabled)

    # Build top-level menus by grouping tools (preserve first-seen order)
    menu_groups = OrderedDict()
    for submenu_path, actions in addon_actions.items():
        top = submenu_path.split("::")[0] if submenu_path else CONFIG.get("toolbar_title", "Custom Tools")
        if top not in menu_groups:
            menu_groups[top] = []
        menu_groups[top].append((submenu_path, actions))

    for top_title, grouped in menu_groups.items():
        top_menu = QMenu(top_title, mw)
        for submenu_path, actions in grouped:
            path = submenu_path.split("::")[1:] if submenu_path else []
            for (name, callback, icon, enabled) in actions:
                add_nested_action(top_menu, path, name, callback, icon, enabled)
        mw.form.menubar.addMenu(top_menu)


# Register a tool into the custom toolbar and refresh the menu
def register_addon_tool(name, callback, submenu_name: str = "", icon=None, enabled=True, order_index: Optional[int] = None):
    """
    * Register a new tool under a submenu. 'submenu_name' can use '::' for nesting.
    ^ If 'order_index' is provided, insert at that position within its submenu list; otherwise append.
    """
    key = submenu_name or ""
    items = addon_actions.setdefault(key, [])
    # Insert at a fixed position when requested (bounds-safe), else append
    if isinstance(order_index, int) and 0 <= order_index <= len(items):
        items.insert(order_index, (name, callback, icon, enabled))
    else:
        items.append((name, callback, icon, enabled))
    _refresh_menu()

def build_config_tools(config, make_open_fn):
    """
    Build config tool definitions for the "Add-ons Configurations" submenu.
    Args:
        config (dict): Global config dictionary.
        make_open_fn (Callable): Function that returns a callback to open the config dialog.

    Returns:
        List[dict]: List of tool definitions with name, callback, icon, and other display settings.
    """
    tools = []
    dropped_icons: list[tuple[str, str]] = []
    default_icon_raw = config.get("default_icon")
    default_icon = normalize_icon_reference(default_icon_raw)

    for addon in config.get("Other_addon_names", []):
        label = format_config_label(addon, config)
        if default_icon_raw and not default_icon:
            dropped_icons.append((label, default_icon_raw))
        tools.append(dict(
            name=label,  # includes emoji + nickname fallback
            callback=make_open_fn(addon),
            submenu_name="Addon Configs",
            icon=default_icon,
            enabled=True
        ))

    if dropped_icons:
        show_icon_drop_warning("building Add-ons Configurations menu", dropped_icons)

    return tools
