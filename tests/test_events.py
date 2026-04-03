import pytest
import time
from src.core.events import EventSystem, EventType
class TestEventSystem:
    def test_sync_subscribe_emit(self, event_system):
        received = []
        def handler(data):
            received.append(data)
        event_system.subscribe(EventType.ENTRY_ADDED, handler)
        event_system.emit(EventType.ENTRY_ADDED, {"id": 1})
        assert len(received) == 1
        assert received[0] == {"id": 1}

    def test_async_events(self, event_system):
        received = []
        def async_handler(data):
            time.sleep(0.1)
            received.append(data)
        event_system.subscribe(EventType.ENTRY_UPDATED, async_handler, async_handler=True)
        event_system.emit(EventType.ENTRY_UPDATED, {"id": 42})
        time.sleep(0.2)
        assert len(received) == 1
        assert received[0] == {"id": 42}

    def test_multiple_handlers(self, event_system):
        results = []
        def handler1(data):
            results.append("handler1")
        def handler2(data):
            results.append("handler2")
        event_system.subscribe(EventType.USER_LOGGED_IN, handler1)
        event_system.subscribe(EventType.USER_LOGGED_IN, handler2)
        event_system.emit(EventType.USER_LOGGED_IN)
        assert len(results) == 2
        assert "handler1" in results
        assert "handler2" in results

    def test_different_event_types(self, event_system):
        received = []

        def handler(event_type):
            def inner(data):
                received.append(event_type)

            return inner
        for et in EventType:
            event_system.subscribe(et, handler(et))
        event_system.emit(EventType.ENTRY_ADDED)
        event_system.emit(EventType.USER_LOGGED_IN)
        event_system.emit(EventType.ENTRY_DELETED)
        assert len(received) == 3
        assert EventType.ENTRY_ADDED in received
        assert EventType.USER_LOGGED_IN in received
        assert EventType.ENTRY_DELETED in received

    def test_no_handler(self, event_system):
        # Не должно вызывать ошибок
        event_system.emit(EventType.ENTRY_ADDED)

    def test_handler_error(self, event_system, capsys):
        def bad_handler(data):
            raise ValueError("Test error")
        event_system.subscribe(EventType.ENTRY_ADDED, bad_handler)
        event_system.emit(EventType.ENTRY_ADDED)
        # Проверяем, что ошибка была перехвачена
        captured = capsys.readouterr()
        assert "Error" in captured.out
    def test_unsubscribe_not_implemented(self, event_system):
        """Тест: отписка (заглушка)"""
        # В текущей версии отписка не реализована
        pass
class TestEventTypes:
    def test_all_events_defined(self):
        expected_events = [
            'ENTRY_ADDED',
            'ENTRY_UPDATED',
            'ENTRY_DELETED',
            'USER_LOGGED_IN',
            'USER_LOGGED_OUT'
        ]
        for event in expected_events:
            assert hasattr(EventType, event)
    def test_event_values(self):
        assert EventType.ENTRY_ADDED.value == "entry_added"
        assert EventType.USER_LOGGED_IN.value == "user_logged_in"