# Toolbar Editor (WebView rewrite) (WebView rewrite)
# - Loads HTML UI from assets/toolbar.html with inlined CSS/JS
# - Uses AnkiWebView + bridge for save/refresh
# - Right-click → Inspect opens DevTools focused at cursor

from __future__ import annotations
import os, json, traceback
from typing import Any, Dict

from aqt.qt import (
    QDialog, QVBoxLayout, Qt, QTimer, QCursor, QMenu, QWebEngineView
)
from aqt.webview import AnkiWebView
from aqt.utils import showInfo, showText
from aqt import gui_hooks

from .utils import _refresh_menu

# --- Paths & constants ---
ADDON_DIR = os.path.dirname(__file__)
ASSETS = os.path.join(ADDON_DIR, "assets")
CONFIG_PATH = os.path.join(ASSETS, "config.json")
ACTIONS_PATH = os.path.join(ASSETS, "actions.json")
HTML_PATH = os.path.join(ASSETS, "toolbar.html")
CSS_PATH = os.path.join(ASSETS, "toolbar_style.css")
JS_PATH  = os.path.join(ASSETS, "toolbar_script.js")
DEVTOOLS_WINDOW_TITLE = "Toolbar DevTools"

# * Sentinel & helper to keep 'Toolbar Settings' OUT of actions.json and the table
TOOLBAR_SETTINGS_SENTINEL = {
    "name": "Toolbar Settings",
    "module": "_Main_Toolbar.toolbar_editor",
    "function": "edit_toolbar_json",
}
def _is_toolbar_settings(entry: Dict[str, Any]) -> bool:
    """
    & Identify the hard-coded Toolbar Settings row regardless of submenu/icon/enabled.
    """
    return (
        (entry or {}).get("name") == TOOLBAR_SETTINGS_SENTINEL["name"]
        and (entry or {}).get("module") == TOOLBAR_SETTINGS_SENTINEL["module"]
        and (entry or {}).get("function") == TOOLBAR_SETTINGS_SENTINEL["function"]
    )

# Load config (labels, defaults)
try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        CONFIG = json.load(f)
except Exception:
    CONFIG = {"toolbar_title": "Toolbar Editor"}

# Keep handles to the editor view and the DevTools window so we can attach DevTools
_toolbar_view: AnkiWebView | None = None
_toolbar_devtools: QWebEngineView | None = None

# Keep a reference to the open dialog when modeless
_TOOLBAR_DIALOG = None


class ToolbarEditorDialog(QDialog):
    """Modeless dialog hosting an AnkiWebView UI for toolbar editing."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("toolbarEditorDialog")
        self.setWindowTitle(CONFIG.get("toolbar_title", "Toolbar Editor"))
        self.resize(1100, 700)

        # Open modeless so Anki remains interactive; destroy widget on close
        self.setModal(False)
        self.setWindowModality(Qt.NonModal)
        self.setAttribute(Qt.WA_DeleteOnClose, True)

        # Layout + WebView
        lay = QVBoxLayout(self)
        self.view = AnkiWebView(title="Toolbar Editor")
        lay.addWidget(self.view)

        # Expose global reference for the context-menu hook
        global _toolbar_view
        _toolbar_view = self.view

        # Bridge for save/refresh
        self.view.set_bridge_command(self._on_bridge, "toolbar_editor")

        # Load body-only HTML and inline CSS/JS like High-Yield Tags
        tpl = self._read_html()
        css = self._read_text(CSS_PATH)
        js  = self._read_text(JS_PATH)
        html = (
            tpl.replace("{{ toolbar_style }}", f"<style>\n{css}\n</style>")
               .replace("{{ toolbar_script }}", f"<script>\n{js}\n</script>")
        )
        self.view.stdHtml(html, context=None)

        # Hydrate the UI with current actions.json
        self._inject_model(self._load_actions())

    # --- I/O helpers ---
    def _read_html(self) -> str:
        try:
            with open(HTML_PATH, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            showText(traceback.format_exc(), title="Load HTML Error")
            return "<div>Failed to load toolbar.html</div>"

    def _read_text(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            showText(traceback.format_exc(), title=f"Load Error: {os.path.basename(path)}")
            return ""

    def _load_actions(self) -> list[Dict[str, Any]]:
        try:
            if os.path.exists(ACTIONS_PATH):
                with open(ACTIONS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # ! Keep the hard-coded item out of the editor grid
                    data = [e for e in (data or []) if not _is_toolbar_settings(e)]
                    return data
        except Exception:
            showText(traceback.format_exc(), title="Load Actions Error")
        return []

    def _prefer_svg_path(self, path: str) -> str:
        """If path ends with .png and a sibling .svg exists, return the .svg path; otherwise return original."""
        try:
            if not path or not path.lower().endswith(".png"):
                return path
            # Respect relative paths under assets/icons
            base = path[:-4]  # strip .png
            candidate = base + ".svg"
            # If path is relative, resolve against addon dir
            if not os.path.isabs(candidate):
                abs_candidate = os.path.join(ADDON_DIR, candidate)
            else:
                abs_candidate = candidate
            if os.path.exists(abs_candidate):
                # Return the same style (relative vs absolute) as input, but with .svg
                return candidate if not os.path.isabs(path) else abs_candidate
            return path
        except Exception:
            return path

    def _inject_model(self, data: list[Dict[str, Any]]) -> None:
        # Pass JSON string to JS hydrate(jsonStr)
        payload = json.dumps(data)
        # Double-encode so quotes are preserved inside JS call
        js = f"hydrate({json.dumps(payload)});"
        self.view.eval(js)

    # --- Bridge ---
    def _on_bridge(self, cmd: str) -> None:
        # toolbar_editor:save:<json>
        # toolbar_editor:refresh
        if not cmd.startswith("toolbar_editor:"):
            return
        try:
            _, action, rest = cmd.split(":", 2)
        except ValueError:
            return

        if action == "refresh":
            _refresh_menu()
            return

        if action == "save":
            try:
                tools = json.loads(rest)
                # Normalize separators and prefer SVG icons
                for e in tools:
                    # Prefer .svg over .png when available
                    icon_path = e.get("icon") or ""
                    if icon_path:
                        e["icon"] = self._prefer_svg_path(icon_path)
                    name = (e.get("name") or "").strip()
                    if name in ("---", "—", "——", "———", "————", "—————"):
                        e["type"] = "separator"
                    else:
                        e.pop("type", None)
                # ? Ensure the hard-coded item never gets saved
                clean_tools = [e for e in tools if not _is_toolbar_settings(e)]
                # Backup + write
                if os.path.exists(ACTIONS_PATH):
                    os.replace(ACTIONS_PATH, ACTIONS_PATH + ".bak")
                with open(ACTIONS_PATH, "w", encoding="utf-8") as f:
                    json.dump(clean_tools, f, indent=2)
                _refresh_menu()
                showInfo("Saved. Reopen the Tools menu to see changes.")
                # ^ Re-hydrate with the filtered model so the row never reappears
                self._inject_model(clean_tools)
            except Exception:
                showText(traceback.format_exc(), title="Save Error")



# --- DevTools context menu hook (right-click → Inspect) ---

def _toolbar_context_menu_hook(webview: AnkiWebView, menu: QMenu) -> None:
    """Add an Inspect action to the context menu of our toolbar editor webview only."""
    global _toolbar_view
    if webview is not _toolbar_view:
        return
    act = menu.addAction("Inspect")
    act.triggered.connect(lambda: _inspect_toolbar_at_cursor(webview))




def _inspect_toolbar_at_cursor(for_view: AnkiWebView) -> None:
    global _toolbar_devtools
    if _toolbar_devtools is None:
        _toolbar_devtools = QWebEngineView()
        _toolbar_devtools.setWindowTitle(DEVTOOLS_WINDOW_TITLE)
        _toolbar_devtools.resize(1100, 800)

    page = for_view.page()
    page.setDevToolsPage(_toolbar_devtools.page())
    _toolbar_devtools.show()
    _toolbar_devtools.raise_()

    # Capture cursor position and map to the view
    gp = QCursor.pos()
    lp = for_view.mapFromGlobal(gp)

    # Defer the inspection slightly to ensure DevTools is shown
    def do_inspect():
        try:
            page.inspectElementAt(lp.x(), lp.y())
        except Exception:
            pass

    QTimer.singleShot(0, do_inspect)

# Register the hook once (hooks aren’t iterable; track via module flag)
try:
    _TOOLBAR_HOOK_REGISTERED
except NameError:
    _TOOLBAR_HOOK_REGISTERED = False

if not _TOOLBAR_HOOK_REGISTERED:
    try:
        gui_hooks.webview_will_show_context_menu.append(_toolbar_context_menu_hook)
    except Exception:
        # Older/newer hook APIs: best effort, ignore if unavailable
        pass
    _TOOLBAR_HOOK_REGISTERED = True


# --- Entry points ---

def open_toolbar_editor() -> None:
    from aqt import mw
    global _TOOLBAR_DIALOG
    # If already open, focus it
    if _TOOLBAR_DIALOG is not None and _TOOLBAR_DIALOG.isVisible():
        _TOOLBAR_DIALOG.raise_()
        _TOOLBAR_DIALOG.activateWindow()
        return
    _TOOLBAR_DIALOG = ToolbarEditorDialog(mw)
    # When closed, drop the reference
    try:
        _TOOLBAR_DIALOG.destroyed.connect(lambda *_: _reset_toolbar_dialog_ref())
    except Exception:
        pass
    _TOOLBAR_DIALOG.show()

def _reset_toolbar_dialog_ref():
    global _TOOLBAR_DIALOG
    _TOOLBAR_DIALOG = None

# Back-compat name used in actions.json
edit_toolbar_json = open_toolbar_editor
