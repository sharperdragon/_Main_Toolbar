# pyright: reportMissingImports=false
# mypy: disable_error_code=import

import os
import traceback
import importlib
from collections import OrderedDict
from aqt import mw
from aqt.utils import showText


from .utils import CONFIG, register_addon_tool, build_config_tools 
import json

# Local definition to ensure UTF-8 reading for JSON files
def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
from .assets.config_ui import ConfigDialog
from .assets.config_manager import ConfigManager


# * Hard-coded "Toolbar Settings" action kept out of actions.json
def _open_toolbar_settings():
    """
    * Opens the Toolbar Editor dialog without using actions.json
    ^ Lazy import avoids circular imports and keeps startup fast.
    """
    from .toolbar_editor import edit_toolbar_json
    edit_toolbar_json()

def register_hardcoded_toolbar_settings(order_index=None):
    """
    & Register a persistent 'Toolbar Settings' menu item directly in the menu.
    & This keeps it OUT of actions.json, so it will NOT appear in the editor table.
    """
    register_addon_tool(
        name="Toolbar Settings",
        callback=_open_toolbar_settings,
        submenu_name=CONFIG.get("toolbar_title", "Custom Tools"),
        icon="icons/bent_menu-burger.png",
        enabled=True,
        order_index=order_index,  # ^ allow explicit placement
    )


# Loads and registers separate configuration dialogs for other add-ons into a submenu.
def load_other_configs():
    """
    Load and register configuration dialogs for other add-ons into a dedicated submenu.
    This function checks the global configuration to determine if toolbar settings
    should be enabled, then dynamically creates menu entries for each add-on listed
    in the 'OTher_addon_names' configuration key.
    """
    # Skip if toolbar settings are disabled in the config.
    # Exit early if toolbar settings are disabled in the config
    # This flag controls whether the 'Other Add-ons Configurations' submenu is shown
    if not CONFIG.get("enable_toolbar_settings", False):
        return


    # Generates a function to open the config dialog for a given add-on name.
    # Returns a function that opens the config dialog for a specific add-on
    # This closure allows each menu item to open the correct add-on's config dialog
    def make_open_fn(addon_name):
        def _open():
            dlg = ConfigDialog(addon_name, ConfigManager)
            dlg.exec()
        return _open

    try:
        # Prepare the list of config tools to register
        config_tools = build_config_tools(CONFIG, make_open_fn)


        # Locate the custom toolbar menu already present in the Anki Tools menu.
        custom_tools_menu = None
        for action in mw.form.menubar.actions():
            if action.menu() and action.menu().title() == CONFIG.get("toolbar_title", "Custom Tools"):
                custom_tools_menu = action.menu()
                break

        if not custom_tools_menu:
            return

        # Register each tool using the unified system so it appears under the correct menu
        for tool in config_tools:
            register_addon_tool(
                name=tool["name"],
                callback=tool["callback"],
                submenu_name=CONFIG.get("toolbar_title", "Custom Tools") + "::Add-ons Configurations",
                icon=tool["icon"],
                enabled=tool["enabled"]
            )

    except Exception:
        err = traceback.format_exc()
        showText(
            f"[Custom Tools] Failed to load Other Add-ons Configurations menu:\n\n{err}",
            title=CONFIG.get("toolbar_title", "Custom Tools") + " Error"
        )

# Main function to dynamically load functional tools defined in actions.json and add to the toolbar.
# Dynamically loads and registers tools from actions.json file.
def load_tools_from_config():
    # Define and check path to the actions.json configuration file.
    tools_path = os.path.join(os.path.dirname(__file__), "assets", "actions.json")
   
    # Skip loading if the config file is missing
    if not os.path.exists(tools_path):
        return

    # Load and parse the JSON file containing tool definitions
    tools = load_json_file(tools_path)

    # ! Build an ordered manifest: { submenu_name: [entries...] } in file order
    manifest: OrderedDict[str, list[dict]] = OrderedDict()

    for entry in tools:
        entry_type = (entry.get("type") or "").strip()
        name = (entry.get("name") or "").strip()
        if not name:
            continue
        # Skip separators/labels for menu registration (editor handles those)
        if entry_type in ("separator", "label") or name == "separator" or name == "\u2014\u2014\u2014":
            continue

        raw_submenu = (entry.get("submenu") or "").strip()
        submenu_name = CONFIG.get("toolbar_title", "Custom Tools")
        if raw_submenu:
            submenu_name += f"::{raw_submenu}"

        func_name = entry.get("function")
        module_path = entry.get("module")
        if not func_name or not module_path:
            continue

        if submenu_name not in manifest:
            manifest[submenu_name] = []
        manifest[submenu_name].append(entry)

    # ^ Register entries by position within each submenu (no sorting)
    for submenu_name, entries in manifest.items():
        for idx, entry in enumerate(entries):
            try:
                module = importlib.import_module(entry["module"])
                callback = getattr(module, entry["function"])
            except Exception:
                err = traceback.format_exc()
                showText(
                    f"[Custom Tools] Failed to import '{entry['name']}' from {entry['module']}.{entry['function']}:\n\n{err}",
                    title=CONFIG.get("toolbar_title", "Custom Tools") + " Error"
                )
                continue

            register_addon_tool(
                name=entry["name"],
                callback=callback,
                submenu_name=submenu_name,
                icon=entry.get("icon"),
                enabled=entry.get("enabled", True),
                order_index=idx,  # ! explicit position from file order
            )

    # Add hard-coded item last (or pass an index to place it)
    register_hardcoded_toolbar_settings()