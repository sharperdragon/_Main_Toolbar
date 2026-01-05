# pyright: reportMissingImports=false
# mypy: disable_error_code=import

# Load all tools and config dialogs
from aqt.gui_hooks import main_window_did_init

from .Run_add_ons import load_other_configs, load_tools_from_config
from .utils import CONFIG, register_addon_tool

main_window_did_init.append(load_tools_from_config)
main_window_did_init.append(load_other_configs)


# * Cmd+Opt+I on macOS, Ctrl+Alt+I on Win/Linux
try:
    seq = qt.QKeySequence("Ctrl+Alt+I")  # macOS will map appropriately
    qt.QShortcut(
        seq,
        self.view,
        activated=lambda: SubWindowInspector(
            inspected_page=self.view.page(),
            window_widget=self,
            target_widget=(self if INSPECTOR_TARGET == "dialog" else self.view),
            insert_pos=INSPECTOR_INSERT_POS,
        ),
    )
except Exception:
    pass
