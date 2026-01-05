# pyright: reportMissingImports=false
# mypy: disable_error_code=import

import json
import os
from aqt.qt import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextBrowser,
    QSplitter, Qt, QWidget, QTextEdit, qtmajor,  # * add qtmajor for Qt5/Qt6 branching
)
from aqt import mw
import markdown
from aqt.utils import showInfo


class ConfigDialog(QDialog):
    def __init__(self, addon_name: str, config_manager_cls, parent=None):
        super().__init__(parent or mw)
        self.addon_name = addon_name
        self.config_manager = config_manager_cls(addon_name)

        # Initialize dialog window with title and modality
        self.setWindowTitle(f"{addon_name} Add-on Configuration")

        # ? Set window flags & modality with Qt5/Qt6 compatibility
        if qtmajor >= 6:
            # * Qt6: enums moved under WindowType / WindowModality
            self.setWindowFlags(Qt.WindowType.Window)
            self.setWindowModality(Qt.WindowModality.ApplicationModal)
        else:
            # * Qt5: legacy enum names
            self.setWindowFlags(Qt.WindowType.Window)
            self.setWindowModality(Qt.WindowModality.ApplicationModal)

        self.resize(900, 600)

        # Main layout
        main_layout = QVBoxLayout(self)

        # Splitter for README (left) and JSON editor (right)
        # ? Horizontal splitter orientation (Qt5/Qt6 safe)
        if qtmajor >= 6:
            splitter = QSplitter(Qt.Orientation.Horizontal)
        else:
            splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel: README viewer
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        readme_label = QLabel("README")
        self.readme_browser = QTextBrowser()
        self.readme_browser.setOpenExternalLinks(True)

        left_layout.addWidget(readme_label)
        left_layout.addWidget(self.readme_browser)

        # Right panel: JSON config editor
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        config_label = QLabel("config.json")
        self.config_editor = QTextEdit()
        self.config_editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        right_layout.addWidget(config_label)
        right_layout.addWidget(self.config_editor)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter)

        # Buttons row
        button_row = QHBoxLayout()

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.on_save)

        self.restore_button = QPushButton("Restore Defaults")
        self.restore_button.clicked.connect(self.on_restore_defaults)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)

        button_row.addStretch(1)
        button_row.addWidget(self.save_button)
        button_row.addWidget(self.restore_button)
        button_row.addWidget(self.close_button)

        main_layout.addLayout(button_row)

        # Load initial data
        self.load_readme()
        self.load_config()

    # =====================
    # Config + README logic
    # =====================

    def load_readme(self) -> None:
        """Load README.md from the add-on folder, render as HTML markdown."""
        addon_path = os.path.join(mw.addonManager.addonsFolder(), self.addon_name)
        readme_path = os.path.join(addon_path, "README.md")
        if not os.path.exists(readme_path):
            self.readme_browser.setHtml("<i>No README.md found for this add-on.</i>")
            return

        try:
            with open(readme_path, "r", encoding="utf-8") as f:
                md_text = f.read()
        except Exception as exc:
            self.readme_browser.setHtml(
                f"<b>Error loading README.md:</b><br><pre>{exc}</pre>"
            )
            return

        # Render markdown to HTML
        html = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
        self.readme_browser.setHtml(html)

    def load_config(self) -> None:
        """Load config via ConfigManager and display it as pretty JSON."""
        try:
            config = self.config_manager.load_config()
            self.config_editor.setPlainText(json.dumps(config, indent=4))
        except Exception as exc:
            showInfo(f"Error loading config: {exc}")

    def on_save(self) -> None:
        """Save JSON text in the editor back through ConfigManager."""
        raw = self.config_editor.toPlainText()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            showInfo(f"JSON error:\n{exc}")
            return

        try:
            self.config_manager.save_config(parsed)
            showInfo("Configuration saved.")
        except Exception as exc:
            showInfo(f"Error saving config:\n{exc}")

    def on_restore_defaults(self) -> None:
        """
        Reload config.json from disk (preferring assets/config.json)
        and overwrite the stored config with that.
        """
        addon_path = os.path.join(mw.addonManager.addonsFolder(), self.addon_name)
        assets_path = os.path.join(addon_path, "assets", "config.json")
        default_path = os.path.join(addon_path, "config.json")
        config_path = assets_path if os.path.exists(assets_path) else default_path

        try:
            with open(config_path, "r", encoding="utf-8") as file:
                default_config = json.load(file)
            self.config_manager.save_config(default_config)
            self.config_editor.setPlainText(json.dumps(default_config, indent=4))
            showInfo("Defaults Restored.")
        except FileNotFoundError:
            showInfo("Error: config.json file not found.")
        except json.JSONDecodeError:
            showInfo("Error: config.json is not a valid JSON.")
        except Exception as exc:
            showInfo(f"Error restoring defaults:\n{exc}")