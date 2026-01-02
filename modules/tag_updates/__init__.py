from __future__ import annotations

from typing import List, Dict
from collections import defaultdict
from pathlib import Path

from aqt import mw
from aqt.qt import (
    Qt, QDialog, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton, QTabWidget,
    QDialogButtonBox, QRadioButton, QWidget, QLabel, QMessageBox, QFont, QHeaderView, QBrush, QColor,
)

from .TR_main import run_tag_renamer, load_all_pairs_for_ui_with_sources, run_tag_renamer_subset
from .add_tags import run_tag_additions, load_tag_add_rules_with_meta, _run_tag_additions_core


# Helper for group header cleaning
def _clean_group_header(src: str) -> str:
    """
    Return a human-friendly group header for a rule file path.
    """
    p = Path(src)
    name = p.name.lower()
    suffix = p.suffix.lower()

    # Explicit filename mappings
    explicit = {
        "_and_.json": "and → &  (JSON)",
        "minor_rules.json": "Minor (JSON)",
        "new_tag_rules.json": "New rules (JSON)",
        "tag_renaming.csv": "Renaming CSV",
    }

    if name in explicit:
        return explicit[name]

    # Fallbacks
    stem = p.stem.replace("_", " ").strip().title()
    if suffix == ".json":
        return f"{stem} (JSON)"
    if suffix == ".csv":
        return f"{stem} (CSV)"

    return stem


# Group header roles for badge/label metadata
ROLE_GROUP = int(Qt.ItemDataRole.UserRole) + 100
ROLE_BASE_LABEL = ROLE_GROUP + 1
ROLE_FULL_PATH = ROLE_GROUP + 2


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
        rename_pairs: List[object],
        rename_labels: List[str],
        rename_sources: List[str],
        add_labels: List[str],
        add_sources: List[str],
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Tag updates — choose rules")
        # * Give the dialog a sensible default size so long labels are readable
        self.resize(800, 600)

        # * Use a monospaced font in the lists so arrows and tags line up
        self._mono_font = QFont("Menlo")

        self._rename_pairs_raw = rename_pairs
        main_layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)

        # Renames tab --------------------------------------------------------
        rename_widget = QWidget(self)
        rename_layout = QVBoxLayout(rename_widget)

        self.rename_tree = QTreeWidget(rename_widget)
        self.rename_tree.setColumnCount(2)
        self.rename_tree.setHeaderHidden(True)
        self.rename_tree.setFont(self._mono_font)
        self.rename_tree.itemChanged.connect(self._update_counts)
        self.rename_tree.setAlternatingRowColors(True)
        self.rename_tree.setIndentation(14)
        self.rename_tree.setUniformRowHeights(True)
        hdr = self.rename_tree.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

        self.rename_count_label = QLabel("", rename_widget)

        # Group labels by their source file (index-preserving)
        rename_groups: Dict[str, List[tuple[int, str]]] = defaultdict(list)
        for idx, (label, src) in enumerate(zip(rename_labels, rename_sources)):
            rename_groups[str(src)].append((idx, label))

        for file_key in sorted(rename_groups.keys(), key=lambda s: _clean_group_header(s).lower()):
            top = QTreeWidgetItem(self.rename_tree)
            base_label = _clean_group_header(file_key)

            # Store group metadata for later badge updates
            top.setData(0, ROLE_GROUP, True)
            top.setData(0, ROLE_BASE_LABEL, base_label)
            top.setData(0, ROLE_FULL_PATH, file_key)

            # Display label + tooltip
            top.setText(0, base_label)
            top.setToolTip(0, file_key)
            top.setToolTip(1, file_key)

            # Header styling
            hdr_font = QFont(self._mono_font)
            hdr_font.setBold(True)
            try:
                hdr_font.setPointSize(hdr_font.pointSize() + 1)
            except Exception:
                pass
            top.setFont(0, hdr_font)
            top.setFont(1, hdr_font)

            bg = QBrush(QColor(245, 245, 245))
            top.setBackground(0, bg)
            top.setBackground(1, bg)

            # Right-column badge alignment
            top.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            top.setFlags(top.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
            top.setCheckState(0, Qt.CheckState.Checked)

            for idx, label in rename_groups[file_key]:
                child = QTreeWidgetItem(top)
                child.setText(0, label)
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked)
                child.setData(0, Qt.ItemDataRole.UserRole, idx)
                # ? Tooltip shows both the preview label and the raw rule (may contain "\\1")
                raw_label = None
                try:
                    p = self._rename_pairs_raw[idx]
                    raw_old = getattr(p, "old", "")
                    raw_new = getattr(p, "new", "")
                    if raw_old or raw_new:
                        raw_label = f"{raw_old} → {raw_new}"
                except Exception:
                    raw_label = None

                if raw_label and raw_label != label:
                    child.setToolTip(0, f"Preview:\n{label}\n\nRaw:\n{raw_label}")
                else:
                    child.setToolTip(0, label)
            # Initialize group badge as selected/total (defaults to all checked)
            total_children = top.childCount()
            top.setText(1, f"{total_children}/{total_children}")
            top.setExpanded(True)

        rename_layout.addWidget(self.rename_tree)
        rename_layout.addWidget(self.rename_count_label)
        self._add_select_buttons_tree(rename_layout, self.rename_tree)
        rename_widget.setLayout(rename_layout)
        self.tabs.addTab(rename_widget, "Renames")

        # Add-tags tab -------------------------------------------------------
        add_widget = QWidget(self)
        add_layout = QVBoxLayout(add_widget)

        self.add_tree = QTreeWidget(add_widget)
        self.add_tree.setColumnCount(2)
        self.add_tree.setHeaderHidden(True)
        self.add_tree.setFont(self._mono_font)
        self.add_tree.itemChanged.connect(self._update_counts)
        self.add_tree.setAlternatingRowColors(True)
        self.add_tree.setIndentation(14)
        self.add_tree.setUniformRowHeights(True)
        hdr = self.add_tree.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

        self.add_count_label = QLabel("", add_widget)

        add_groups: Dict[str, List[tuple[int, str]]] = defaultdict(list)
        for idx, (label, src) in enumerate(zip(add_labels, add_sources)):
            add_groups[str(src)].append((idx, label))

        for file_key in sorted(add_groups.keys(), key=lambda s: _clean_group_header(s).lower()):
            top = QTreeWidgetItem(self.add_tree)
            base_label = _clean_group_header(file_key)

            # Store group metadata for later badge updates
            top.setData(0, ROLE_GROUP, True)
            top.setData(0, ROLE_BASE_LABEL, base_label)
            top.setData(0, ROLE_FULL_PATH, file_key)

            # Display label + tooltip
            top.setText(0, base_label)
            top.setToolTip(0, file_key)
            top.setToolTip(1, file_key)

            # Header styling
            hdr_font = QFont(self._mono_font)
            hdr_font.setBold(True)
            try:
                hdr_font.setPointSize(hdr_font.pointSize() + 1)
            except Exception:
                pass
            top.setFont(0, hdr_font)
            top.setFont(1, hdr_font)

            bg = QBrush(QColor(245, 245, 245))
            top.setBackground(0, bg)
            top.setBackground(1, bg)

            # Right-column badge alignment
            top.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            top.setFlags(top.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
            top.setCheckState(0, Qt.CheckState.Checked)

            for idx, label in add_groups[file_key]:
                child = QTreeWidgetItem(top)
                child.setText(0, label)
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked)
                child.setData(0, Qt.ItemDataRole.UserRole, idx)
                child.setToolTip(0, label)
            total_children = top.childCount()
            top.setText(1, f"{total_children}/{total_children}")
            top.setExpanded(True)

        add_layout.addWidget(self.add_tree)
        add_layout.addWidget(self.add_count_label)
        self._add_select_buttons_tree(add_layout, self.add_tree)
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

    def _add_select_buttons_tree(self, layout: QVBoxLayout, tree_widget: QTreeWidget) -> None:
        """Add 'Select all' / 'Select none' buttons for a given tree widget."""
        row = QHBoxLayout()
        btn_all = QPushButton("Select all", self)
        btn_none = QPushButton("Select none", self)

        def _set_all(state: Qt.CheckState) -> None:
            root = tree_widget.invisibleRootItem()
            for i in range(root.childCount()):
                top = root.child(i)
                top.setCheckState(0, state)
            self._update_counts()

        btn_all.clicked.connect(lambda: _set_all(Qt.CheckState.Checked))
        btn_none.clicked.connect(lambda: _set_all(Qt.CheckState.Unchecked))

        row.addWidget(btn_all)
        row.addWidget(btn_none)
        row.addStretch(1)
        layout.addLayout(row)

    def _calc_tree(self, tree_widget: QTreeWidget) -> tuple[int, int]:
        """Return (selected_children, total_children) for a grouped QTreeWidget."""
        root = tree_widget.invisibleRootItem()
        total = 0
        selected = 0
        for i in range(root.childCount()):
            top = root.child(i)
            for j in range(top.childCount()):
                child = top.child(j)
                total += 1
                if child.checkState(0) == Qt.CheckState.Checked:
                    selected += 1
        return selected, total

    def _update_group_badges(self, tree_widget: QTreeWidget) -> None:
        """Update per-group right-column badges like '3/7' without changing selection."""
        root = tree_widget.invisibleRootItem()
        tree_widget.blockSignals(True)
        try:
            for i in range(root.childCount()):
                top = root.child(i)
                if not top.data(0, ROLE_GROUP):
                    continue

                base_label = top.data(0, ROLE_BASE_LABEL) or top.text(0)
                total = top.childCount()
                selected = 0
                for j in range(total):
                    child = top.child(j)
                    if child.checkState(0) == Qt.CheckState.Checked:
                        selected += 1

                # Keep header label clean; put counts in badge column
                if top.text(0) != str(base_label):
                    top.setText(0, str(base_label))

                badge = f"{selected}/{total}"
                if top.text(1) != badge:
                    top.setText(1, badge)
        finally:
            tree_widget.blockSignals(False)

    def _update_counts(self) -> None:
        """Update 'X / Y selected' labels for both tabs."""
        # Update per-group badges first (right column)
        if hasattr(self, "rename_tree"):
            self._update_group_badges(self.rename_tree)
        if hasattr(self, "add_tree"):
            self._update_group_badges(self.add_tree)
        if hasattr(self, "rename_tree"):
            sel_ren, tot_ren = self._calc_tree(self.rename_tree)
            if hasattr(self, "rename_count_label"):
                self.rename_count_label.setText(
                    f"Renames: {sel_ren} / {tot_ren} selected"
                )

        if hasattr(self, "add_tree"):
            sel_add, tot_add = self._calc_tree(self.add_tree)
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

        # Renames
        root = self.rename_tree.invisibleRootItem()
        for i in range(root.childCount()):
            top = root.child(i)
            for j in range(top.childCount()):
                child = top.child(j)
                if child.checkState(0) == Qt.CheckState.Checked:
                    idx = child.data(0, Qt.ItemDataRole.UserRole)
                    if isinstance(idx, int):
                        rename_idx.append(idx)

        # Add tags
        root = self.add_tree.invisibleRootItem()
        for i in range(root.childCount()):
            top = root.child(i)
            for j in range(top.childCount()):
                child = top.child(j)
                if child.checkState(0) == Qt.CheckState.Checked:
                    idx = child.data(0, Qt.ItemDataRole.UserRole)
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

    # Gather rename rules + labels + sources
    rename_pairs, rename_labels, rename_sources, csv_files, json_files = load_all_pairs_for_ui_with_sources()
    # Gather add-tag rules + labels
    add_rules, add_labels = load_tag_add_rules_with_meta()
    add_sources = [str(r.source_file) for r in add_rules]

    if not rename_pairs and not add_rules:
        QMessageBox.information(
            mw,
            "Tag updates",
            "No tag renaming or tag addition rules were found.",
        )
        return

    dlg = TagUpdatesDialog(mw, rename_pairs, rename_labels, [str(s) for s in rename_sources], add_labels, add_sources)
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