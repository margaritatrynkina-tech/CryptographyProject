from src.core.clipboard.clipboard_service import ClipboardService
from src.core.events import EventSystem, EventType


class DummyAdapter:
    def __init__(self):
        self.data = ""

    def copy_to_clipboard(self, data: str) -> bool:
        self.data = data
        return True

    def clear_clipboard(self) -> bool:
        self.data = ""
        return True

    def get_clipboard_content(self):
        return self.data


class DummyConfig:
    def __init__(self):
        self.values = {"clipboard_timeout_seconds": 5}

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value


def test_clipboard_requires_unlocked_vault():
    adapter = DummyAdapter()
    events = EventSystem()
    config = DummyConfig()
    service = ClipboardService(adapter, events, config, is_vault_unlocked=lambda: False)

    try:
        service.copy_to_clipboard("secret", data_type="password")
        assert False, "Expected PermissionError for locked vault"
    except PermissionError:
        pass


def test_clipboard_auto_clear_configurable_timeout():
    adapter = DummyAdapter()
    events = EventSystem()
    config = DummyConfig()
    service = ClipboardService(adapter, events, config, is_vault_unlocked=lambda: True)

    service.set_auto_clear_timeout(5)
    assert config.get("clipboard_timeout_seconds") == 5
    assert service.get_auto_clear_timeout() == 5

    service.set_auto_clear_timeout(None)
    assert config.get("clipboard_timeout_seconds") == 0
    assert service.get_auto_clear_timeout() is None


def test_clipboard_emits_copied_and_cleared_events():
    adapter = DummyAdapter()
    events = EventSystem()
    copied = []
    cleared = []
    events.subscribe(EventType.CLIPBOARD_COPIED, lambda data: copied.append(data))
    events.subscribe(EventType.CLIPBOARD_CLEARED, lambda data: cleared.append(data))
    config = DummyConfig()
    service = ClipboardService(adapter, events, config, is_vault_unlocked=lambda: True)

    assert service.copy_to_clipboard("secret", data_type="password", source_entry_id="entry-1")
    service.clear_clipboard(reason="manual")

    assert copied and copied[0]["data_type"] == "password"
    assert cleared and cleared[0]["reason"] == "manual"
