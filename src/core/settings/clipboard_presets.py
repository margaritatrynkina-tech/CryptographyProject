"""Clipboard security presets (CFG-3)."""
from typing import Any, Dict

CLIPBOARD_PRESETS: Dict[str, Dict[str, Any]] = {
    "standard": {
        "clipboard_timeout_seconds": 30,
        "clipboard_notifications": True,
        "clipboard_enhanced_monitoring": False,
        "clipboard_paranoid_mode": False,
        "clipboard_ephemeral_mode": False,
        "clipboard_preset": "standard",
    },
    "secure": {
        "clipboard_timeout_seconds": 15,
        "clipboard_notifications": True,
        "clipboard_enhanced_monitoring": True,
        "clipboard_paranoid_mode": False,
        "clipboard_ephemeral_mode": False,
        "clipboard_preset": "secure",
    },
    "public_computer": {
        "clipboard_timeout_seconds": 5,
        "clipboard_notifications": True,
        "clipboard_enhanced_monitoring": True,
        "clipboard_paranoid_mode": True,
        "clipboard_ephemeral_mode": True,
        "clipboard_preset": "public_computer",
    },
}


def apply_preset(store, preset_name: str) -> None:
    if preset_name not in CLIPBOARD_PRESETS:
        raise ValueError(f"Unknown preset: {preset_name}")
    for key, value in CLIPBOARD_PRESETS[preset_name].items():
        store.set(key, value)


def preset_get_int(store, key: str, default: int = 0) -> int:
    if hasattr(store, "get_int"):
        return store.get_int(key, default)
    try:
        return int(store.get(key, default))
    except (TypeError, ValueError):
        return default


def preset_get_bool(store, key: str, default: bool = False) -> bool:
    if hasattr(store, "get_bool"):
        return store.get_bool(key, default)
    return str(store.get(key, default)).lower() in ("1", "true", "yes")
