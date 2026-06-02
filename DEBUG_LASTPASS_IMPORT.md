# Отладка импорта зашифрованного LastPass CSV

## Добавлены DEBUG-сообщения

### 1. В `import_dialog.py` → `_do_import()`:

```python
[DEBUG] _do_import starting
[DEBUG] Format: lastpass
[DEBUG] File path: C:\path\to\file.csv
[DEBUG] Strategy: skip
[DEBUG] Пароль файла для формата lastpass: True
[DEBUG] Длина пароля: X символов
[DEBUG] run() thread started for format: lastpass
[DEBUG] Calling importer.import_lastpass...
[DEBUG] import_lastpass completed successfully
[DEBUG] Import completed, scheduling success callback
```

### 2. В `importer.py` → `import_lastpass()`:

```python
[DEBUG] VaultImporter.import_lastpass called
[DEBUG] file_path: C:\path\to\file.csv
[DEBUG] master_password: True
[DEBUG] file_password: True
[DEBUG] conflict_strategy: skip
[DEBUG] Calling LastPassHandler.import_file...
[DEBUG] LastPassHandler.import_file returned X entries
[DEBUG] Calling _import_entries...
[DEBUG] _import_entries completed: X successful, 0 failed
```

### 3. В `lastpass_handler.py` → `import_file()`:

```python
[DEBUG] LastPassHandler.import_file called
[DEBUG] File path: C:\path\to\file.csv
[DEBUG] Password provided: True
[DEBUG] File content length: XXX chars
[DEBUG] First 50 chars: ENCRYPTED:c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==...
[DEBUG] Encrypted file detected
[DEBUG] Attempting decryption...
[DEBUG] Decryption successful, new length: XXX chars
[DEBUG] Decrypted first 100 chars: url,username,password,totp,extra,name,grouping,fav...
[DEBUG] Calling import_csv to parse content...
[DEBUG] import_csv returned X entries, 0 warnings
```

### 4. В `lastpass_handler.py` → `import_csv()`:

```python
[DEBUG] import_csv called with XXX chars
[DEBUG] CSV fieldnames: ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav']
[DEBUG] Normalised fields: ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav']
[DEBUG] import_csv parsed X entries with 0 warnings
```

---

##  Как тестировать:

### Шаг 1: Запустите программу
```bash
python main.py
```

### Шаг 2: Попробуйте импортировать зашифрованный LastPass CSV

1. Откройте диалог импорта (Ctrl+I)
2. Выберите зашифрованный .csv файл
3. Введите пароль в поле "Пароль расшифровки"
4. Нажмите "Импортировать"

### Шаг 3: Проверьте консоль

**Ожидаемый поток DEBUG-сообщений:**

```
1. [DEBUG] CSV первая строка: ENCRYPTED:...
2. [DEBUG] Обнаружен зашифрованный LastPass CSV
3. [DEBUG] Определён формат файла: lastpass
4. [DEBUG] LastPass файл зашифрован, пропускаем детальную валидацию
5. [DEBUG] LastPass файл зашифрован, предпросмотр недоступен
6. [DEBUG] _do_import starting
7. [DEBUG] Format: lastpass
8. [DEBUG] Пароль файла для формата lastpass: True
9. [DEBUG] run() thread started for format: lastpass
10. [DEBUG] Calling importer.import_lastpass...
11. [DEBUG] VaultImporter.import_lastpass called
12. [DEBUG] Calling LastPassHandler.import_file...
13. [DEBUG] LastPassHandler.import_file called
14. [DEBUG] Password provided: True
15. [DEBUG] Encrypted file detected
16. [DEBUG] Attempting decryption...
17. [DEBUG] Decryption successful
18. [DEBUG] Calling import_csv to parse content...
19. [DEBUG] import_csv called with XXX chars
20. [DEBUG] CSV fieldnames: [...]
21. [DEBUG] import_csv parsed X entries
22. [DEBUG] LastPassHandler.import_file returned X entries
23. [DEBUG] Calling _import_entries...
24. [DEBUG] _import_entries completed: X successful, 0 failed
25. [DEBUG] import_lastpass completed successfully
26. [DEBUG] Import completed, scheduling success callback
```

---

##  Диагностика проблем:

### Проблема 1: Импорт не запускается

**Проверьте:**
- Есть ли сообщение `[DEBUG] _do_import starting`?
- Если нет - проблема в UI (кнопка не вызывает метод)
- Если есть - проверьте следующие сообщения

### Проблема 2: Пароль не передаётся

**Ищите:**
```
[DEBUG] Пароль файла для формата lastpass: False
```

**Причина:** Поле пароля пустое

**Решение:** Убедитесь, что пароль введён в поле диалога

### Проблема 3: Ошибка расшифровки

**Ищите:**
```
[DEBUG] Attempting decryption...
[DEBUG] Decryption failed: ...
```

**Причины:**
- Неверный пароль
- Файл повреждён
- Неправильный формат шифрования

**Решение:** 
- Проверьте правильность пароля
- Проверьте первые 50 символов файла в логах

### Проблема 4: CSV не парсится

**Ищите:**
```
[DEBUG] import_csv called with XXX chars
[DEBUG] CSV fieldnames: None
```

**Причина:** После расшифровки получен не CSV

**Решение:** Проверьте "Decrypted first 100 chars" в логах

### Проблема 5: Записи не импортируются

**Ищите:**
```
[DEBUG] import_csv parsed 0 entries
```

**Причины:**
- Все записи пропущены из-за отсутствия title
- Файл пустой после расшифровки

**Решение:** Проверьте содержимое после расшифровки

### Проблема 6: Импорт успешен, но UI не обновляется

**Ищите:**
```
[DEBUG] _import_entries completed: X successful, 0 failed
[DEBUG] import_lastpass completed successfully
[DEBUG] Import completed, scheduling success callback
```

**Причина:** Проблема с `dialog.after()` или `_on_success()`

**Решение:** Проверьте, вызывается ли `_on_success` и обновляется ли main window

---

##  Контрольный список:

- [ ] DEBUG-сообщения появляются в консоли
- [ ] Формат определяется как `lastpass`
- [ ] Пароль передаётся (`True`)
- [ ] Файл определяется как зашифрованный
- [ ] Расшифровка выполняется успешно
- [ ] CSV парсится (fieldnames найдены)
- [ ] Записи извлекаются (> 0 entries)
- [ ] `_import_entries` завершается успешно
- [ ] Вызывается `_on_success`
- [ ] UI обновляется (показывается сообщение об успехе)

---

## 🛠 Дополнительные проверки:

### Проверка формата шифрования:

```python
# Зашифрованный файл должен начинаться с:
ENCRYPTED:c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==

# Где:
# - c2FsdA== - salt (base64)
# - bm9uY2U= - nonce (base64)
# - Y2lwaGVydGV4dA== - ciphertext (base64)
```

### Проверка расшифрованного содержимого:

После расшифровки должен получиться обычный CSV:
```csv
url,username,password,totp,extra,name,grouping,fav
http://example.com,user1,pass123,,My note,Example Site,Work,0
```

### Тестовый зашифрованный файл:

Для быстрой проверки создайте тестовый файл с простым паролем "test123".

---

Все DEBUG-сообщения добавлены! Запустите импорт и отправьте логи для анализа. 🎉
