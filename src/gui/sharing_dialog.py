# Re-export from the dialogs sub-package so that
# `from src.gui.sharing_dialog import SharingDialog` works.
from src.gui.dialogs.sharing_dialog import SharingDialog  # noqa: F401

__all__ = ["SharingDialog"]
