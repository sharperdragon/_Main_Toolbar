from __future__ import annotations

from typing import List

from aqt import mw
from aqt.qt import (
    Qt,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTabWidget,
    QDialogButtonBox,
    QRadioButton,
    QWidget,
    QLabel,
    QMessageBox,
    QFont,
)

from .TR_main import run_tag_renamer, load_all_pairs_for_ui, run_tag_renamer_subset
from .add_tags import run_tag_additions, load_tag_add_rules_with_meta, _run_tag_additions_core


class TagUpdatesDialog(QDialog):
    """
    Combined picker for tag rename + tag addition rules.

    - Tab 1: Renames (per Pair)
    - Tab 2: Add tags (per TagAddRule)
    - Bottom row: Dry run vs Apply changes
    """

    def __init__(
        self,
        parent: QWidget | None,
        rename_labels: List[str],
        add_labels: List[str],
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Tag updates — choose rules")
        # * Give the dialog a sensible default size so long labels are readable
        self.resize(800, 600)

        # * Use a monospaced font in the lists so arrows and tags line up
        self._mono_font = QFont("Menlo")

        main_layout = QVBoxLayout(self)

        self.tabs = QTabWidget(self)

        # Renames tab --------------------------------------------------------
        rename_widget = QWidget(self)
        rename_layout = QVBoxLayout(rename_widget)
        self.rename_list = QListWidget(rename_widget)
        self.rename_list.setFont(self._mono_font)
        self.rename_list.itemChanged.connect(self._update_counts)
        self.rename_count_label = QLabel("", rename_widget)
        for idx, label in enumerate(rename_labels):
            item = QListWidgetItem(label, self.rename_list)
            # Make items checkable, default to checked
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            # Store the original index from the pairs list
            item.setData(Qt.ItemDataRole.UserRole, idx)
            # ? Full label in tooltip for long rules
            item.setToolTip(label)
        rename_layout.addWidget(self.rename_list)
        rename_layout.addWidget(self.rename_count_label)
        self._add_select_buttons(rename_layout, self.rename_list)
        rename_widget.setLayout(rename_layout)
        self.tabs.addTab(rename_widget, "Renames")

        # Add-tags tab -------------------------------------------------------
        add_widget = QWidget(self)
        add_layout = QVBoxLayout(add_widget)
        self.add_list = QListWidget(add_widget)
        self.add_list.setFont(self._mono_font)
        self.add_list.itemChanged.connect(self._update_counts)
        self.add_count_label = QLabel("", add_widget)
        for idx, label in enumerate(add_labels):
            item = QListWidgetItem(label, self.add_list)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, idx)
            item.setToolTip(label)
        add_layout.addWidget(self.add_list)
        add_layout.addWidget(self.add_count_label)
        self._add_select_buttons(add_layout, self.add_list)
        add_widget.setLayout(add_layout)
        self.tabs.addTab(add_widget, "Add tags")

        main_layout.addWidget(self.tabs)

        # Run mode (dry vs apply) --------------------------------------------
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Run mode:", self)
        self.dry_radio = QRadioButton("Dry run (no changes)", self)
        self.live_radio = QRadioButton("Apply changes", self)
        self.dry_radio.setChecked(True)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.dry_radio)
        mode_layout.addWidget(self.live_radio)
        mode_layout.addStretch(1)
        main_layout.addLayout(mode_layout)

        # Dialog buttons -----------------------------------------------------
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)
        # Initialize counts based on default-checked items
        self._update_counts()

    def _add_select_buttons(self, layout: QVBoxLayout, list_widget: QListWidget) -> None:
        """Add 'Select all' / 'Select none' buttons for a given list widget."""
        row = QHBoxLayout()
        btn_all = QPushButton("Select all", self)
        btn_none = QPushButton("Select none", self)

        def select_all() -> None:
            for i in range(list_widget.count()):
                list_widget.item(i).setCheckState(Qt.CheckState.Checked)
            self._update_counts()

        def select_none() -> None:
            for i in range(list_widget.count()):
                list_widget.item(i).setCheckState(Qt.CheckState.Unchecked)
            self._update_counts()

        btn_all.clicked.connect(select_all)
        btn_none.clicked.connect(select_none)

        row.addWidget(btn_all)
        row.addWidget(btn_none)
        row.addStretch(1)
        layout.addLayout(row)

    def _update_counts(self) -> None:
        """Update 'X / Y selected' labels for both tabs."""
        def _calc(list_widget: QListWidget) -> tuple[int, int]:
            total = list_widget.count()
            selected = 0
            for i in range(total):
                if list_widget.item(i).checkState() == Qt.CheckState.Checked:
                    selected += 1
            return selected, total

        if hasattr(self, "rename_list"):
            sel_ren, tot_ren = _calc(self.rename_list)
            if hasattr(self, "rename_count_label"):
                self.rename_count_label.setText(
                    f"Renames: {sel_ren} / {tot_ren} selected"
                )

        if hasattr(self, "add_list"):
            sel_add, tot_add = _calc(self.add_list)
            if hasattr(self, "add_count_label"):
                self.add_count_label.setText(
                    f"Add tags: {sel_add} / {tot_add} selected"
                )

    def get_selection(self) -> tuple[list[int], list[int], bool]:
        """
        Return:
          - indices of selected rename rules
          - indices of selected add-tag rules
          - dry_run flag
        """
        rename_idx: List[int] = []
        add_idx: List[int] = []

        for i in range(self.rename_list.count()):
            item = self.rename_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                idx = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(idx, int):
                    rename_idx.append(idx)

        for i in range(self.add_list.count()):
            item = self.add_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                idx = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(idx, int):
                    add_idx.append(idx)

        dry = self.dry_radio.isChecked()
        return rename_idx, add_idx, dry


def run_tag_updates() -> None:
    """
    Combined entrypoint for Tag Updates:
      - Lets the user choose which rename + add-tag rules to run
      - Lets the user choose dry run vs apply
      - Executes tag additions first, then renames, sharing the same mode
    """
    if mw is None or mw.col is None:
        QMessageBox.warning(None, "Tag updates", "Collection is not loaded.")
        return

    # Gather rename rules + labels
    rename_pairs, rename_labels, csv_files, json_files = load_all_pairs_for_ui()
    # Gather add-tag rules + labels
    add_rules, add_labels = load_tag_add_rules_with_meta()

    if not rename_pairs and not add_rules:
        QMessageBox.information(
            mw,
            "Tag updates",
            "No tag renaming or tag addition rules were found.",
        )
        return

    dlg = TagUpdatesDialog(mw, rename_labels, add_labels)
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return

    rename_idx, add_idx, dry = dlg.get_selection()
    if not rename_idx and not add_idx:
        QMessageBox.information(mw, "Tag updates", "No rules selected.")
        return

    # Map selected indices back to actual rule objects
    selected_pairs = [rename_pairs[i] for i in rename_idx] if rename_pairs else []
    selected_add_rules = [add_rules[i] for i in add_idx] if add_rules else []

    # Run tag additions first, then renamer, using the same dry/apply choice
    rename_ran = False

    add_stats = None
    if selected_add_rules:
        # Suppress the standalone "Tag additions" popup; we'll show a combined summary instead
        add_stats = _run_tag_additions_core(mw, selected_add_rules, dry, show_summary=False)

    if selected_pairs:
        run_tag_renamer_subset(mw, selected_pairs, dry, csv_files, json_files)
        rename_ran = True

    # * Combined summary popup for Tag Updates
    lines: list[str] = []
    lines.append(f"Tag Updates {'(dry run)' if dry else ''} complete.")
    lines.append("")

    # Renaming section
    if rename_ran:
        lines.append("Tag renaming: rules ran. See the Global Tag Renamer log for details.")
    else:
        lines.append("Tag renaming: no rules selected.")

    lines.append("")

    # Additions section
    if add_stats is not None:
        lines.append("Tag additions:")
        lines.append(f"  · Rules: {add_stats.total_rules}")
        lines.append(f"  · Notes matched: {add_stats.total_notes_matched}")
        lines.append(f"  · Notes changed: {add_stats.total_notes_changed}")
        lines.append(f"  · Tags added: {add_stats.total_tags_added}")
    elif selected_add_rules:
        # Fallback: additions were requested, but no stats returned
        lines.append("Tag additions: rules ran. See the Tag Additions log for details.")
    else:
        lines.append("Tag additions: no rules selected.")

    QMessageBox.information(mw, "Tag Updates — Summary", "\n".join(lines))


__all__ = ["run_tag_renamer", "run_tag_additions", "run_tag_updates"]