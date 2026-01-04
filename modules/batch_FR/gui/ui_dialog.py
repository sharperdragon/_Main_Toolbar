from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional
import json

from ..utils.top_helper import (
    _load_rule_aliases,
    _pretty_rule_file_label as _pretty_label_for_file,
    _group_rule_files_by_folder,
    _rule_group_and_name,
    _load_rule_favorites,
    _save_rule_favorites,
)


from .dialog_helper import (
    build_initial_context,
    format_rule_options_for_preview,
    build_rules_panel_html,
)


try:
    from aqt.webview import AnkiWebView  # type: ignore[import]
    WEB_UI_AVAILABLE = True
except Exception:  # pragma: no cover - extremely unlikely, but we guard for safety
    AnkiWebView = None  # type: ignore[assignment]
    WEB_UI_AVAILABLE = False

WEB_PREVIEW_AVAILABLE = WEB_UI_AVAILABLE
from aqt.qt import (  # type: ignore[import]
    QDialog,
    QListWidget,
    QListWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QHBoxLayout,
    QDialogButtonBox,
    QPushButton,
    QLabel,
    QLineEdit,
    QRadioButton,
    QPlainTextEdit,
    QMouseEvent,
    Qt
)

# ---------------------------------------------------------------------------
# ! Styling & layout constants
# ---------------------------------------------------------------------------

DIALOG_MIN_WIDTH = 700
DIALOG_MIN_HEIGHT = 700
GROUP_LIST_MIN_WIDTH = 180
TREE_COLUMN_WIDTH = 320  # width of rule/alias column in the tree

# Initial widths for [tree, preview] when splitter is used
SPLITTER_INITIAL_SIZES = (520, 360)

# Status label (bottom line) QSS
STATUS_LABEL_STYLE = "color: #555; font-size: 11px;"


# Inspector window size
INSPECTOR_WIDTH = 640
INSPECTOR_HEIGHT = 480

# Base directory for HTML/CSS/JS assets used by the HTML-based dialog
_GUI_DIR = Path(__file__).resolve().parent


def _load_rules_html() -> str:
    """Backward-compatible wrapper around dialog_helper.build_rules_panel_html()."""
    return build_rules_panel_html(_GUI_DIR)



class BatchFRHtmlDialog(QDialog):
    """
    HTML-driven Batch FR rule selection dialog.

    UI is rendered in an AnkiWebView; all interactions go through a JS <-> Python
    bridge, so the entire window is inspectable via web devtools.
    """

    def __init__(
        self,
        parent,
        rule_files: List[Path],
        rules_root: Optional[Path] = None,
    ) -> None:
        super().__init__(parent)

        self._rule_files = list(rule_files)
        self._rules_root = rules_root
        self._context = build_initial_context(self._rule_files, self._rules_root)

        # * Merge persisted defaults (group/file selection) into the initial payload
        #   so the HTML UI can render the saved selections on open.
        self._merge_persisted_defaults_into_context()

        self._result: Optional[Dict[str, Any]] = None

        self._build_html_ui()
        self._wire_bridge()
        self._load_page()

    # --- HTML UI scaffold --------------------------------------------------

    def _build_html_ui(self) -> None:
        self.setWindowTitle("Batch Find & Replace — Rule sets")
        self.resize(DIALOG_MIN_WIDTH, DIALOG_MIN_HEIGHT)

        layout = QVBoxLayout(self)
        self.web = AnkiWebView(parent=self)
        layout.addWidget(self.web)

    def _load_page(self) -> None:
        html = _load_rules_html()
        self.web.stdHtml(html, context=self)

        # Defer sending the initial context slightly to give the HTML/JS time
        # to load and define window.batchFrInit.
        try:
            from aqt.qt import QTimer  # type: ignore

            QTimer.singleShot(0, self._send_initial_context)
        except Exception:
            # Fallback: call directly if QTimer is unavailable
            self._send_initial_context()

    def _wire_bridge(self) -> None:
        """
        Connect JS bridge so pycmd(...) calls arrive here.
        """
        # API name depends on Anki version, so we support both.
        if hasattr(self.web, "set_bridge_command"):
            # Newer Anki versions
            self.web.set_bridge_command(self._on_bridge_cmd, self)
        elif hasattr(self.web, "setOnBridgeCmd"):
            # Older Anki versions
            self.web.setOnBridgeCmd(self._on_bridge_cmd)

    # --- Bridge handler ----------------------------------------------------

    def _on_bridge_cmd(self, cmd: str) -> None:
        """
        Handle commands from JS. All commands are prefixed with 'batchFr:'.
        """
        if not isinstance(cmd, str):
            return

        prefix = "batchFr:"
        if not cmd.startswith(prefix):
            return

        payload_str = cmd[len(prefix) :]
        try:
            data = json.loads(payload_str)
        except Exception:
            return

        command = data.get("command")
        if command == "ready":
            self._send_initial_context()
        elif command == "submit":
            self._handle_submit(data)
        elif command == "cancel":
            self.reject()
        elif command == "preview":
            # * Preview a single rule file in the HTML panel
            self._handle_preview(data)
        elif command == "toggle_favorite":
            # * Update favorites list on disk
            self._handle_toggle_favorite(data)
        elif command == "save_default_selection":
            # * Persist default group + rule-file selections from Settings modal
            self._handle_save_default_selection(data)

    def _send_initial_context(self) -> None:
        """
        Push the initial rule/group context down into the HTML UI.
        """
        try:
            payload = json.dumps(self._context)
        except Exception:
            return

        js = f"window.batchFrInit && window.batchFrInit({payload});"
        self.web.eval(js)

    def _handle_submit(self, data: Dict[str, Any]) -> None:
        """
        Handle a 'submit' command from JS: gather selected files and run mode.
        """
        files_raw = data.get("files") or []
        dry_run = bool(data.get("dry_run", True))
        extensive_debug = bool(data.get("extensive_debug", False))

        paths: List[Path] = []
        for p_str in files_raw:
            try:
                paths.append(Path(str(p_str)))
            except Exception:
                continue

        if not paths:
            # Require at least one file; do not close if empty
            return

        # * Normalize to JSON-safe primitives (strings), and provide both legacy and canonical keys.
        selected = [str(p) for p in paths]
        self._result = {
            "dry_run": dry_run,
            "extensive_debug": extensive_debug,
            "rule_files": selected,   # legacy key used by older glue
            "rules_files": selected,  # canonical key
        }
        self.accept()

    def _handle_preview(self, data: Dict[str, Any]) -> None:
        path_str = data.get("path")
        if not path_str:
            return

        try:
            p = Path(str(path_str))
        except Exception:
            return

        try:
            raw = p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            preview_text = f"Error reading file: {e}"
        else:
            # Try to build a structured preview; fall back to raw if parsing fails
            try:
                preview_text = self._build_rule_file_preview(p, raw)
            except Exception:
                preview_text = raw

        # Wrap in a small JSON payload; JS side is responsible for escaping
        try:
            payload = json.dumps({"text": preview_text})
        except Exception:
            return

        js = f"window.batchFrSetPreview && window.batchFrSetPreview({payload});"
        self.web.eval(js)

    def _build_rule_file_preview(self, path: Path, raw: str) -> str:
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

        # Header line based on group + file name
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

            lines.append(f"Rule {idx}: {name}")
            if query:
                lines.append(f'Q: "{query}"')
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

    def _handle_toggle_favorite(self, data: Dict[str, Any]) -> None:
        """
        * 13-32_12-07  Handle a single favorite toggle from the HTML UI.

        The JS side passes an absolute path and a boolean "favorite" flag.
        We persist favorites as a simple list of filenames in rule_favorites.json.
        """
        path_str = data.get("path") or ""
        if not path_str:
            return

        try:
            p = Path(str(path_str))
        except Exception:
            # ! If the path cannot be resolved, do not modify favorites
            return

        # * We store favorites keyed by filename only, to keep JSON stable
        #   even if the rules root moves on disk.
        key = p.name

        # ! Reload current favorites for the known rule files and adjust the set
        favorites = _load_rule_favorites(self._rule_files)
        if bool(data.get("favorite")):
            favorites.add(key)
        else:
            favorites.discard(key)

        # * Persist updated favorites back to disk
        _save_rule_favorites(favorites)


    # --- Settings defaults persistence -------------------------------------
    def _defaults_json_path(self) -> Path:
        """Return the JSON path used to persist Settings default selections."""
        # gui/ -> batch_FR/ -> json/
        json_dir = _GUI_DIR.parent / "json"
        return json_dir / "ui_settings.json"

    def _merge_persisted_defaults_into_context(self) -> None:
        """Load saved defaults from dedicated JSON and merge into self._context."""
        cfg_path = self._defaults_json_path()
        # * One-time migration: older builds used default_selection.json
        legacy_path = cfg_path.parent / "default_selection.json"
        if not cfg_path.exists() and legacy_path.exists():
            try:
                legacy_raw = legacy_path.read_text(encoding="utf-8")
                legacy_cfg = json.loads(legacy_raw)
                if isinstance(legacy_cfg, dict):
                    cfg_path.parent.mkdir(parents=True, exist_ok=True)
                    cfg_path.write_text(
                        json.dumps(legacy_cfg, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
            except Exception:
                # ! Migration should never break dialog open
                pass
        try:
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            return
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            return

        if not isinstance(cfg, dict):
            return

        # File format: { "default_group_names": [...], "default_rule_paths": [...] }
        merged = dict(self._context.get("defaults") or {})
        if "default_group_names" in cfg:
            merged["default_group_names"] = cfg.get("default_group_names")
        if "default_rule_paths" in cfg:
            merged["default_rule_paths"] = cfg.get("default_rule_paths")

        self._context["defaults"] = merged

    def _handle_save_default_selection(self, data: Dict[str, Any]) -> None:
        """Persist Settings modal defaults to dedicated JSON file and refresh UI state."""
        # JS sends: { default_group_names: [...], default_rule_paths: [...] }
        raw_groups = data.get("default_group_names")
        raw_paths = data.get("default_rule_paths")

        # Sanitize to JSON-serializable lists of strings (empty list is valid!).
        group_names: List[str] = []
        if isinstance(raw_groups, list):
            group_names = [str(x) for x in raw_groups if str(x).strip()]

        rule_paths: List[str] = []
        if isinstance(raw_paths, list):
            rule_paths = [str(x) for x in raw_paths if str(x).strip()]

        cfg_path = self._defaults_json_path()
        # Ensure folder exists
        try:
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            return

        # File format: { "default_group_names": [...], "default_rule_paths": [...] }
        cfg = {
            "default_group_names": group_names,
            "default_rule_paths": rule_paths,
        }

        try:
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            # If we cannot write, silently fail (do not crash UI)
            return

        # Update the in-memory context for this dialog session
        merged = dict(self._context.get("defaults") or {})
        merged["default_group_names"] = group_names
        merged["default_rule_paths"] = rule_paths
        self._context["defaults"] = merged

        # Push defaults back down so JS can re-render with authoritative values.
        try:
            payload = json.dumps({
                "default_group_names": group_names,
                "default_rule_paths": rule_paths,
            })
        except Exception:
            return

        js = f"window.batchFrSetDefaults && window.batchFrSetDefaults({payload});"
        self.web.eval(js)

    # --- Public API --------------------------------------------------------

    def result_payload(self) -> Optional[Dict[str, Any]]:
        """
        Return the final payload after exec(), or None if cancelled.
        """
        return self._result


class BatchFRRuleDialog(QDialog):
    """
    Sleek rule selection dialog for Batch FR:
    - Grouped by folder under rules_root.
    - Filterable list with checkboxes.
    - Simple details pane and dry-run toggle.
    """

    def __init__(
        self,
        parent,
        rule_files: List[Path],
        rules_root: Path | None = None,
    ) -> None:
        super().__init__(parent)

        self._all_rule_files: List[Path] = rule_files
        self._rules_root: Path | None = rules_root
        self._aliases: Dict[str, str] = _load_rule_aliases(rule_files)

        self._group_names, self._group_to_files = _group_rule_files_by_folder(
            rule_files, rules_root
        )

        self._list_filter_text: str = ""

        self._build_ui()
        self._refresh_list()
        self._install_inspector_filters()
    def _install_inspector_filters(self) -> None:
        """
        Install this dialog as an event filter on key widgets so right-click
        can trigger the inspector.
        """
        widgets = [
            self,
            getattr(self, "group_list", None),
            getattr(self, "tree_widget", None),
            getattr(self, "filter_edit", None),
            getattr(self, "select_all_btn", None),
            getattr(self, "select_none_btn", None),
            getattr(self, "dry_radio", None),
            getattr(self, "live_radio", None),
            getattr(self, "status_label", None),
        ]

        for w in widgets:
            if w is not None:
                w.installEventFilter(self)

    # --- Public API --------------------------------------------------------

    def selected_files(self) -> List[Path]:
        """
        Return the list of rule files currently checked in the tree widget.
        """
        files: List[Path] = []
        if not hasattr(self, "tree_widget"):
            return files

        for i in range(self.tree_widget.topLevelItemCount()):
            group_item = self.tree_widget.topLevelItem(i)
            if group_item is None:
                continue
            for j in range(group_item.childCount()):
                child = group_item.child(j)
                if child is None:
                    continue
                if child.checkState(0) != Qt.CheckState.Checked:
                    continue
                path_str = child.data(0, Qt.ItemDataRole.UserRole)
                if not path_str:
                    continue
                try:
                    files.append(Path(str(path_str)))
                except Exception:
                    continue
        return files

    def is_dry_run(self) -> bool:
        """
        True if 'Dry run' is selected, False if 'Apply changes' is selected.
        """
        return bool(self.dry_radio.isChecked())

    # --- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        self.setWindowTitle("Batch Find & Replace — Rule Sets")
        self.setMinimumSize(DIALOG_MIN_WIDTH, DIALOG_MIN_HEIGHT)

        layout = QVBoxLayout(self)

        # Header
        header = QLabel("Choose rule groups and files to run, then select a run mode.")
        header.setWordWrap(False)
        layout.addWidget(header)

        # Main row: groups on the left, files on the right
        main_row = QHBoxLayout()

        # Left: group checkbox list
        self.group_list = QListWidget(self)
        self.group_list.setMinimumWidth(GROUP_LIST_MIN_WIDTH)
        self.group_list.setAlternatingRowColors(True)

        group_names_for_list = [g for g in self._group_names if g != "All"]
        for name in group_names_for_list:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, name)
            item.setFlags(
                item.flags()
                | Qt.ItemFlag.ItemIsUserCheckable
                | Qt.ItemFlag.ItemIsEnabled
            )
            # * Default selection rule:
            #   - Groups whose names start with "z" (case-insensitive) are NOT selected by default.
            #   - All other groups start checked.
            name_str = str(name).strip().lower()
            if name_str.startswith("z"):
                item.setCheckState(Qt.CheckState.Unchecked)
            else:
                item.setCheckState(Qt.CheckState.Checked)
            self.group_list.addItem(item)

        main_row.addWidget(self.group_list)

        # Right: filter, select buttons, and file tree (with optional preview)
        right_layout = QVBoxLayout()

        # Filter row
        filter_row = QHBoxLayout()
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText("Filter by name or alias…")
        filter_row.addWidget(self.filter_edit)
        right_layout.addLayout(filter_row)

        # Select all/none
        select_row = QHBoxLayout()
        self.select_all_btn = QPushButton("Select all", self)
        self.select_none_btn = QPushButton("Select none", self)
        select_row.addWidget(self.select_all_btn)
        select_row.addWidget(self.select_none_btn)
        select_row.addStretch()
        right_layout.addLayout(select_row)

        # File tree: groups as parents, rule files as children
        self.tree_widget = QTreeWidget(self)
        self.tree_widget.setHeaderHidden(True)
        self.tree_widget.setRootIsDecorated(True)  # show expand/collapse arrows
        self.tree_widget.setAlternatingRowColors(True)
        self.tree_widget.setColumnCount(1)
        self.tree_widget.setColumnWidth(0, TREE_COLUMN_WIDTH)

        if WEB_PREVIEW_AVAILABLE:
            # Create a splitter: left side tree, right side preview
            from aqt.qt import QSplitter  # type: ignore
            splitter = QSplitter(self)
            splitter.setOrientation(Qt.Orientation.Horizontal)
            splitter.addWidget(self.tree_widget)

            # Web preview panel (Anki's wrapped webview, with built-in devtools)
            self.web_view = AnkiWebView(parent=self)
            splitter.addWidget(self.web_view)

            # Use configured initial sizes
            splitter.setSizes(list(SPLITTER_INITIAL_SIZES))

            right_layout.addWidget(splitter)
        else:
            # Fallback: just show the tree
            right_layout.addWidget(self.tree_widget)

        main_row.addLayout(right_layout, 1)

        layout.addLayout(main_row, 1)

        # Status line
        self.status_label = QLabel("", self)
        self.status_label.setStyleSheet(STATUS_LABEL_STYLE)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self.status_label)

        # Bottom: mode + buttons
        bottom_row = QHBoxLayout()

        mode_label = QLabel("Run mode:", self)
        self.dry_radio = QRadioButton("Dry run (no changes)", self)
        self.live_radio = QRadioButton("Apply changes", self)
        self.dry_radio.setChecked(True)

        bottom_row.addWidget(mode_label)
        bottom_row.addWidget(self.dry_radio)
        bottom_row.addWidget(self.live_radio)
        bottom_row.addStretch()

        layout.addLayout(bottom_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        layout.addWidget(buttons)

        # Wire signals
        self.group_list.itemChanged.connect(self._on_group_item_changed)
        self.filter_edit.textChanged.connect(self._on_filter_changed)
        self.tree_widget.currentItemChanged.connect(self._on_current_item_changed)
        if WEB_PREVIEW_AVAILABLE:
            self.tree_widget.currentItemChanged.connect(self._on_update_preview)
        self.select_all_btn.clicked.connect(self._on_select_all)
        self.select_none_btn.clicked.connect(self._on_select_none)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    # --- Event handlers ----------------------------------------------------

    def eventFilter(self, obj, event):
        """
        Intercept right-clicks on the dialog and its key child widgets to
        provide a Qt widget inspector. The embedded web preview (AnkiWebView)
        is left to handle its own context menu and devtools.
        """
        try:
            if isinstance(event, QMouseEvent):
                if event.button() == Qt.MouseButton.RightButton:
                    if hasattr(event, "globalPosition"):
                        global_pos = event.globalPosition().toPoint()
                    else:
                        global_pos = event.globalPos()
                    self._inspect_at_global_pos(global_pos)
                    # Do not consume the event: allow default context menus too
                    return False
        except Exception:
            # Never let inspector errors break normal UI
            return False
        return super().eventFilter(obj, event)

    def _inspect_at_global_pos(self, global_pos) -> None:
        """
        Locate the widget under the given global position and show an inspector
        dialog with widget and style information.
        """
        top = self.window()
        if top is None:
            return

        local_pos = top.mapFromGlobal(global_pos)
        widget = top.childAt(local_pos)
        if widget is None:
            return

        item = None
        # If the widget is a view, try to locate the item under the cursor
        if isinstance(widget, QTreeWidget):
            vp_pos = widget.viewport().mapFromGlobal(global_pos)
            item = widget.itemAt(vp_pos)
        elif isinstance(widget, QListWidget):
            vp_pos = widget.viewport().mapFromGlobal(global_pos)
            item = widget.itemAt(vp_pos)

        self._show_widget_inspector(widget, item)

    def _show_widget_inspector(self, widget, item=None) -> None:
        """
        Show a small dialog with information about the clicked widget and,
        if applicable, the underlying list/tree item.
        """
        info_lines: List[str] = []

        # Widget basics
        try:
            meta = widget.metaObject()
            class_name = meta.className() if meta else widget.__class__.__name__
        except Exception:
            class_name = widget.__class__.__name__
        info_lines.append(f"Widget class: {class_name}")
        info_lines.append(f"objectName: {widget.objectName()!r}")

        # Geometry
        try:
            g = widget.geometry()
            info_lines.append(
                f"geometry: x={g.x()}, y={g.y()}, w={g.width()}, h={g.height()}"
            )
        except Exception:
            pass

        # Style sheet
        try:
            ss = widget.styleSheet() or ""
        except Exception:
            ss = ""
        info_lines.append("styleSheet:")
        if ss.strip():
            info_lines.append(ss)
        else:
            info_lines.append("  (empty)")

        # Font info
        try:
            f = widget.font()
            info_lines.append(
                f"font: family={f.family()!r}, pointSize={f.pointSize()}"
            )
        except Exception:
            pass

        # Palette colors (a few key roles)
        try:
            pal = widget.palette()
            def _hex_color(role):
                c = pal.color(role)
                return f"#{c.red():02X}{c.green():02X}{c.blue():02X}"
            info_lines.append("palette:")
            info_lines.append(
                f"  window={_hex_color(pal.Window)} windowText={_hex_color(pal.WindowText)}"
            )
            info_lines.append(
                f"  base={_hex_color(pal.Base)} text={_hex_color(pal.Text)}"
            )
        except Exception:
            pass

        # Item info if applicable
        if item is not None:
            info_lines.append("")
            info_lines.append("Item:")
            try:
                # For tree widgets, item.text takes a column index; for list widgets, no args
                try:
                    txt = item.text(0)
                except TypeError:
                    txt = item.text()
                info_lines.append(f"  text={txt!r}")
            except Exception:
                pass
            try:
                data = item.data(0, Qt.ItemDataRole.UserRole)
            except Exception:
                data = None
            info_lines.append(f"  userRole={data!r}")

        text = "\n".join(info_lines)

        dlg = QDialog(self)
        dlg.setWindowTitle("Widget inspector")
        layout = QVBoxLayout(dlg)
        edit = QPlainTextEdit(dlg)
        edit.setReadOnly(True)
        edit.setPlainText(text)
        layout.addWidget(edit)
        close_btn = QPushButton("Close", dlg)
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)
        dlg.resize(INSPECTOR_WIDTH, INSPECTOR_HEIGHT)
        dlg.exec()

    def _on_group_item_changed(self, _item: QListWidgetItem) -> None:
        """
        Refresh the file list when the set of selected groups changes.
        """
        self._refresh_list()

    def _selected_group_names(self) -> List[str]:
        """
        Return the names of all currently checked groups.
        """
        names: List[str] = []
        if not hasattr(self, "group_list"):
            return names
        for i in range(self.group_list.count()):
            item = self.group_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                name = item.data(Qt.ItemDataRole.UserRole) or item.text()
                if name:
                    names.append(str(name))
        return names

    def _on_filter_changed(self, text: str) -> None:
        self._list_filter_text = text.strip().lower()
        self._refresh_list()

    def _on_select_all(self) -> None:
        if not hasattr(self, "tree_widget"):
            return
        for i in range(self.tree_widget.topLevelItemCount()):
            group_item = self.tree_widget.topLevelItem(i)
            if group_item is None:
                continue
            for j in range(group_item.childCount()):
                child = group_item.child(j)
                if child is None:
                    continue
                if child.data(0, Qt.ItemDataRole.UserRole):
                    child.setCheckState(0, Qt.CheckState.Checked)

    def _on_select_none(self) -> None:
        if not hasattr(self, "tree_widget"):
            return
        for i in range(self.tree_widget.topLevelItemCount()):
            group_item = self.tree_widget.topLevelItem(i)
            if group_item is None:
                continue
            for j in range(group_item.childCount()):
                child = group_item.child(j)
                if child is None:
                    continue
                if child.data(0, Qt.ItemDataRole.UserRole):
                    child.setCheckState(0, Qt.CheckState.Unchecked)

    def _on_current_item_changed(self, current, _previous) -> None:
        """
        Respond to selection changes in the tree widget. Only child items
        (those with a stored path) produce details in the status line.
        """
        if current is None:
            self._update_details(None)
            return
        path_str = current.data(0, Qt.ItemDataRole.UserRole)
        if not path_str:
            self._update_details(None)
            return
        try:
            p = Path(str(path_str))
        except Exception:
            self._update_details(None)
            return
        self._update_details(p)

    def _on_update_preview(self, current, _previous) -> None:
        """
        When a rule file is selected and web preview is available, load a basic
        HTML preview of its raw content into the web view.
        """
        if not WEB_PREVIEW_AVAILABLE:
            return
        if current is None:
            self.web_view.setHtml("<html><body><p>No file selected</p></body></html>")
            return

        path_str = current.data(0, Qt.ItemDataRole.UserRole)
        if not path_str:
            self.web_view.setHtml("<html><body><p>Not a rule file</p></body></html>")
            return

        try:
            p = Path(str(path_str))
            raw = p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            raw = f"Error reading file: {e}"

        # Simple HTML wrapper with basic escaping
        escaped = (
            raw.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        html = (
            "<html><body>"
            "<pre style='white-space: pre-wrap; font-family: monospace;'>"
            f"{escaped}"
            "</pre></body></html>"
        )
        self.web_view.setHtml(html)

    # --- Internal helpers --------------------------------------------------


    def _visible_files_for_group(self) -> Dict[str, List[Path]]:
        """
        Return visible files grouped by group name, respecting filter text
        and the currently checked groups.
        """
        selected_groups = self._selected_group_names()
        if not selected_groups:
            return {}

        ft = self._list_filter_text
        by_group: Dict[str, List[Path]] = {}

        for group_name in selected_groups:
            files = self._group_to_files.get(group_name, [])
            if not ft:
                if files:
                    by_group[group_name] = list(files)
                continue

            group_files: List[Path] = []
            for p in files:
                alias = self._aliases.get(p.name, "")
                label = _pretty_label_for_file(p, self._aliases)
                haystack = f"{alias} {label} {p.name}".lower()
                if ft in haystack:
                    group_files.append(p)
            if group_files:
                by_group[group_name] = group_files

        return by_group

    def _refresh_list(self) -> None:
        if not hasattr(self, "tree_widget"):
            return

        self.tree_widget.clear()

        by_group = self._visible_files_for_group()
        if not by_group:
            self._update_details(None)
            return

        for group_name in sorted(by_group.keys(), key=str.lower):
            files = by_group[group_name]

            # Top-level group node (non-checkable, expandable)
            group_item = QTreeWidgetItem([f"{group_name} ({len(files)} files)"])
            group_item.setData(0, Qt.ItemDataRole.UserRole, None)
            group_font = group_item.font(0)
            group_font.setBold(True)
            group_item.setFont(0, group_font)
            group_item.setExpanded(True)
            self.tree_widget.addTopLevelItem(group_item)

            # Cache for intermediate folder nodes under this group, keyed by a simple
            # path string like "group/sub1/sub2". This avoids duplicating folder nodes
            # when multiple files share the same subfolder.
            folder_cache: Dict[str, QTreeWidgetItem] = {}

            for p in files:
                # Compute the relative path parts under the rules_root, falling back
                # to a simple "[group_name, filename]" structure if anything fails.
                try:
                    if self._rules_root is not None:
                        rel = p.relative_to(self._rules_root)
                        parts = list(rel.parts)
                    else:
                        parts = [group_name, p.name]
                except Exception:
                    parts = [group_name, p.name]

                if not parts:
                    continue

                # The first part should usually match group_name; any remaining parts
                # represent nested folders and the final filename.
                if parts[0] == group_name:
                    sub_parts = parts[1:]
                else:
                    sub_parts = parts

                # Ensure we have at least one element for the file name.
                if not sub_parts:
                    sub_parts = [p.name]

                parent_item = group_item
                path_prefix = group_name

                for i, part in enumerate(sub_parts):
                    is_leaf = i == len(sub_parts) - 1
                    if is_leaf:
                        # Leaf: actual rule file node (checkable, holds full path)
                        label = _pretty_label_for_file(p, self._aliases)
                        file_item = QTreeWidgetItem([label])
                        file_item.setToolTip(0, str(p))
                        file_item.setData(0, Qt.ItemDataRole.UserRole, str(p))
                        flags = file_item.flags()
                        file_item.setFlags(
                            flags
                            | Qt.ItemFlag.ItemIsUserCheckable
                            | Qt.ItemFlag.ItemIsSelectable
                            | Qt.ItemFlag.ItemIsEnabled
                        )
                        file_item.setCheckState(0, Qt.CheckState.Checked)
                        parent_item.addChild(file_item)
                    else:
                        # Intermediate folder node under this group
                        path_prefix = f"{path_prefix}/{part}"
                        folder_item = folder_cache.get(path_prefix)
                        if folder_item is None:
                            folder_item = QTreeWidgetItem([part])
                            folder_item.setData(0, Qt.ItemDataRole.UserRole, None)
                            folder_font = folder_item.font(0)
                            folder_font.setBold(True)
                            folder_item.setFont(0, folder_font)
                            folder_item.setExpanded(True)
                            parent_item.addChild(folder_item)
                            folder_cache[path_prefix] = folder_item
                        parent_item = folder_item

        # Select the first real child item (file) so details show immediately
        for i in range(self.tree_widget.topLevelItemCount()):
            group_item = self.tree_widget.topLevelItem(i)
            if group_item is None:
                continue
            # Walk down to the first file node (UserRole set to a path string)
            nodes = [group_item]
            while nodes:
                node = nodes.pop(0)
                if node is None:
                    continue
                data = node.data(0, Qt.ItemDataRole.UserRole)
                if data:
                    self.tree_widget.setCurrentItem(node)
                    break
                for j in range(node.childCount()):
                    child = node.child(j)
                    if child is not None:
                        nodes.append(child)
            else:
                continue
            break
        else:
            self._update_details(None)

    def _update_details(self, path: Optional[Path]) -> None:
        """
        Update the compact status line under the list.
        """
        if path is None:
            if hasattr(self, "status_label"):
                self.status_label.setText("")
            return

        group, fname, label = _rule_group_and_name(path, self._rules_root)
        alias = self._aliases.get(path.name, "").strip()

        parts: List[str] = []
        if label:
            parts.append(label)
        if alias:
            parts.append(f"alias: {alias}")
        if path:
            parts.append(str(path))

        text = " — ".join(parts)
        if hasattr(self, "status_label"):
            self.status_label.setText(text)


# ---------------------------------------------------------------------------
# ! Public entry point used by top_utils/__init__
# ---------------------------------------------------------------------------

def prompt_batch_fr_run_options(
    parent,
    rule_files: List[Path],
    rules_root: Path | None = None,
) -> Optional[Dict[str, Any]]:
    # Only run when the web-based UI is available; otherwise emit a debug message and bail.
    if not WEB_UI_AVAILABLE:
        # ! Debug-only: you can route this through your logger if desired.
        print("[Batch_FR] Web-based Batch FR dialog requires AnkiWebView; web UI not available.")
        return None

    # If Qt import failed, bail out gracefully
    if not isinstance(QDialog, type):  # crude but effective check
        return None

    if not rule_files:
        return None

    dlg = BatchFRHtmlDialog(parent, list(rule_files), rules_root)
    result_code = dlg.exec()

    # Qt6: Accepted is now under QDialog.DialogCode
    if result_code != QDialog.DialogCode.Accepted:
        return None

    payload = dlg.result_payload()
    if not payload:
        return None

    dry_run = bool(payload.get("dry_run", True))
    extensive_debug = bool(payload.get("extensive_debug", False))
    selected = payload.get("rules_files") or payload.get("rule_files") or []
    if not selected:
        return None

    # * Ensure List[str]
    selected_str = [str(x) for x in selected]

    return {
        "dry_run": dry_run,
        "extensive_debug": extensive_debug,
        "rules_files": selected_str,
        "rule_files": selected_str,  # compat alias
    }