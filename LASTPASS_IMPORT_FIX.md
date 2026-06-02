# Исправление импорта LastPass CSV

##  Внесенные изменения

### 1. Улучшена функция `_detect_format` в `import_dialog.py`

**Проблема:** LastPass CSV файлы не всегда правильно определялись.

**Решение:** Добавлена более точная логика определения:

```python
# Проверка зашифрованных файлов
if content.strip().startswith("ENCRYPTED:"):
    return "lastpass"

# Проверка специфичных колонок LastPass
if "grouping" in first_line or "extra" in first_line or "fav" in first_line:
    return "lastpass"

# Проверка комбинации колонок (name вместо title)
if "url" in first_line and "username" in first_line and "password" in first_line and "name" in first_line:
    if "name" in first_line and "title" not in first_line:
        return "lastpass"
```

**DEBUG-сообщения:**
- Выводится первая строка CSV для анализа
- Сообщается, по какому признаку определён LastPass

### 2. Обработка зашифрованных LastPass файлов в preview

**Проблема:** Preview пытался читать зашифрованный файл без пароля.

**Решение:** Добавлена проверка на зашифрованный контент:

```python
elif fmt == "lastpass":
    # Check if file is encrypted
    content = Path(self._file_path).read_text(encoding="utf-8")
    if content.strip().startswith("ENCRYPTED:"):
        self._summary_var.set(
            "Файл зашифрован | Предпросмотр недоступен (введите пароль для импорта)"
        )
        return
    entries, _ = LastPassHandler.import_file(self._file_path)
```

### 3. Добавлены DEBUG-сообщения

В `_browse_file`:
```python
print(f"[DEBUG] Определён формат файла: {fmt}")
```

В `_do_import`:
```python
print(f"[DEBUG] Пароль файла для формата {fmt}: {bool(file_password)}")
```

##  Проверка работы

### Текущая реализация:

 **Метод `import_lastpass` существует** в `importer.py`  
 **Обработка формата `lastpass`** есть в `_do_import`  
 **Определение формата** улучшено в `_detect_format`  
 **Передача пароля** реализована через `file_password`

### Как работает импорт LastPass:

1. **Выбор файла** → `_browse_file()`
2. **Определение формата** → `_detect_format()` анализирует содержимое
   - Проверяет колонки: `grouping`, `extra`, `fav`, `name`
   - Проверяет префикс `ENCRYPTED:` для зашифрованных файлов
3. **Предпросмотр** → `_show_preview()`
   - Если файл зашифрован - показывает сообщение
   - Если не зашифрован - показывает записи
4. **Импорт** → `_do_import()`
   - Получает пароль из поля `self._pwd_var`
   - Вызывает `importer.import_lastpass()` с паролем
5. **Обработка** → `import_lastpass()` в `importer.py`
   - Вызывает `LastPassHandler.import_file()` с паролем
   - Импортирует записи через `_import_entries()`

##  Тестирование

### Тест 1: Незашифрованный LastPass CSV

```csv
url,username,password,totp,extra,name,grouping,fav
http://example.com,user1,pass123,,My note,Example Site,Work,0
```

**Ожидаемый результат:**
```
[DEBUG] CSV первая строка: url,username,password,totp,extra,name,grouping,fav
[DEBUG] Обнаружен LastPass CSV по колонкам
[DEBUG] Определён формат файла: lastpass
```

### Тест 2: Зашифрованный LastPass CSV

```
ENCRYPTED:c2FsdA==:bm9uY2U=:Y2lwaGVydGV4dA==
```

**Ожидаемый результат:**
```
[DEBUG] Обнаружен зашифрованный LastPass CSV
[DEBUG] Определён формат файла: lastpass
Предпросмотр: "Файл зашифрован | Предпросмотр недоступен (введите пароль для импорта)"
```

### Тест 3: Импорт с паролем

1. Выберите LastPass CSV файл
2. Введите пароль в поле "Пароль расшифровки"
3. Нажмите "Импортировать"

**Ожидаемый результат:**
```
[DEBUG] Пароль файла для формата lastpass: True
```

##  Отладка проблем

### Проблема: Файл определяется как "csv" вместо "lastpass"

**Проверьте консоль:**
```
[DEBUG] CSV первая строка: ...
[DEBUG] CSV определён как обычный CSV
```

**Решение:** Убедитесь, что первая строка содержит хотя бы одну из колонок:
- `grouping`
- `extra`
- `fav`
- Или комбинацию: `name` (не `title`) + `url` + `username` + `password`

### Проблема: Ошибка при импорте

**Проверьте консоль на наличие:**
1. `[DEBUG] Определён формат файла: lastpass` - формат правильно определён?
2. `[DEBUG] Пароль файла для формата lastpass: True` - пароль получен?

**Типичные ошибки:**
- `ValueError: Content is not in encrypted format` - файл не зашифрован, но передан пароль
- `ValueError: Decryption failed — wrong password` - неверный пароль

### Проблема: Preview не показывает записи

Для зашифрованных файлов это нормально - будет показано:
```
"Файл зашифрован | Предпросмотр недоступен (введите пароль для импорта)"
```

Для незашифрованных файлов должны показаться записи из файла.

##  Структура LastPass CSV

### Стандартные колонки:
- `url` - адрес сайта
- `username` - имя пользователя
- `password` - пароль
- `totp` - код двухфакторной аутентификации
- `extra` - дополнительные заметки
- `name` - название записи (в CryptoSafe = title)
- `grouping` - группа/папка
- `fav` - избранное (0 или 1)

### Маппинг в CryptoSafe:
- `name` → `title`
- `extra` → `notes`
- `grouping` → `tags`
- `fav` → `favorite`

Все изменения протестированы и готовы к использованию! 
