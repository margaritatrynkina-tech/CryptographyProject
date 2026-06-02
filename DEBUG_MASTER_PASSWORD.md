# Отладка проблемы "Мастер-пароль не установлен"

## Что добавлено

Добавлены DEBUG-сообщения в следующих местах:

1. **main_window.py → show_export_dialog()**: Проверка `self.master_password` перед созданием диалога
2. **main_window.py → show_import_dialog()**: Проверка `self.master_password` перед созданием диалога
3. **export_dialog.py → __init__()**: Проверка получения параметра `master_password`
4. **export_dialog.py → _do_export()**: Проверка `self.master_password` перед экспортом
5. **import_dialog.py → __init__()**: Проверка получения параметра `master_password`
6. **import_dialog.py → _do_import()**: Проверка `self.master_password` перед импортом

## Как диагностировать

### 1. Запустите программу с логированием

```bash
python main.py 2>&1 | tee debug.log
```

или просто:

```bash
python main.py
```

### 2. Войдите в систему

Создайте новый vault или откройте существующий, введя мастер-пароль.

### 3. Попробуйте экспортировать

Откройте меню **File → Экспорт** (или нажмите Ctrl+E) и выберите формат JSON.

### 4. Проверьте консоль

Вы должны увидеть следующие сообщения:

```
[DEBUG] show_export_dialog: master_password установлен = True
[DEBUG] ExportDialog.__init__: master_password получен = True
[DEBUG] _do_export: self.master_password установлен = True
[DEBUG] Запрашиваем пароль экспорта для формата: json
```

### 5. Анализ результатов

####  Если все TRUE:
Мастер-пароль передаётся правильно. Диалог запроса пароля экспорта должен появиться.

####  Если первое сообщение FALSE:
```
[DEBUG] show_export_dialog: master_password установлен = False
```

**Проблема**: `self.master_password` не установлен в `main_window.py` после входа.

**Проверьте**:
1. Успешно ли выполнен вход? Проверьте метод, который устанавливает `self.master_password`
2. Не перезаписывается ли `self.master_password` в `None` где-то в коде

**Решение**: Найдите место, где устанавливается `self.master_password` после успешной аутентификации.

####  Если второе сообщение FALSE:
```
[DEBUG] show_export_dialog: master_password установлен = True
[DEBUG] ExportDialog.__init__: master_password получен = False
```

**Проблема**: Параметр не передаётся при создании `ExportDialog`.

**Проверьте**: Вызов `ExportDialog(...)` в `show_export_dialog` содержит `master_password=self.master_password`.

####  Если третье сообщение FALSE:
```
[DEBUG] ExportDialog.__init__: master_password получен = True
[DEBUG] _do_export: self.master_password установлен = False
```

**Проблема**: `self.master_password` не сохраняется в конструкторе `ExportDialog`.

**Проверьте**: Есть ли строка `self.master_password = master_password` в `__init__`.

## Дополнительные проверки

### Проверка установки мастер-пароля при входе

Найдите в коде место, где происходит вход (например, метод `on_login` или `authenticate`).

Добавьте DEBUG-сообщение:

```python
def on_login_success(self, password):
    self.master_password = password
    print(f"[DEBUG] Мастер-пароль установлен при входе: {bool(self.master_password)}")
```

### Проверка сохранения мастер-пароля

Поиск всех мест, где изменяется `self.master_password`:

```bash
grep -n "self.master_password" src/gui/main_window.py
```

Убедитесь, что:
1. Пароль устанавливается при успешном входе
2. Пароль не сбрасывается в `None` непреднамеренно

## Возможные причины проблемы

### 1. Пароль не устанавливается при входе

Если вы используете аутентификацию через отдельное окно, убедитесь, что после успешного входа выполняется:

```python
self.master_password = user_entered_password
```

### 2. Пароль сбрасывается при logout

Если есть метод выхода (`logout`), убедитесь, что вы не вызываете его случайно.

### 3. Неправильная инициализация

В конструкторе `MainWindow.__init__` должно быть:

```python
self.master_password = None  # Будет установлен при входе
```

## Следующие шаги

1. Запустите программу с DEBUG-сообщениями
2. Войдите в систему
3. Попробуйте экспорт
4. Найдите, где впервые появляется `False`
5. Исправьте проблему в этом месте

После исправления все DEBUG-сообщения можно удалить или заменить на логирование через `logging` модуль.
