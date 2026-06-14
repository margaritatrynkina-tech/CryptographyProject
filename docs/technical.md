# Техническая документация CryptoSafe Manager

## Содержание
1. [Архитектура системы](#архитектура-системы)
2. [Криптографическая схема](#криптографическая-схема)
3. [Модульная структура](#модульная-структура)
4. [Система аудита](#система-аудита)
5. [Безопасность буфера обмена](#безопасность-буфера-обмена)
6. [Импорт/экспорт](#импортэкспорт)
7. [Производительность и оптимизация](#производительность-и-оптимизация)
8. [Тестирование и качество](#тестирование-и-качество)
9. [Развертывание](#развертывание)

## Архитектура системы

### Общий обзор
CryptoSafe Manager построен по модульной архитектуре MVC (Model-View-Controller) с четким разделением ответственности:

```
CryptoSafe Manager
├── Model (Модель данных)
│   ├── Database Layer
│   ├── Encryption Service
│   └── Key Management
├── View (Пользовательский интерфейс)
│   ├── Main Window
│   ├── Widgets
│   └── Dialogs
└── Controller (Бизнес-логика)
    ├── Core Services
    ├── Audit System
    └── Import/Export
```

### Компоненты системы

#### 1. Ядро (Core)
- **Конфигурация** - управление настройками приложения
- **Система событий** - коммуникация между компонентами
- **Менеджер ключей** - управление криптографическими ключами
- **Менеджер состояния** - отслеживание состояния приложения

#### 2. Криптография (Crypto)
- **Абстрактный сервис шифрования** - интерфейс для различных алгоритмов
- **Деривация ключей** - PBKDF2 и Argon2id
- **Хранение ключей** - безопасное хранение в БД
- **Политика паролей** - проверка сложности паролей

#### 3. База данных
- SQLite с шифрованием на уровне приложения
- Схема нормализована до 3NF
- Поддержка транзакций и точек восстановления
- Миграции схемы через скрипты

#### 4. Графический интерфейс
- Tkinter для кроссплатформенности
- Кастомные виджеты для улучшения UX
- Система диалогов для сложных операций
- Поддержка тем и адаптивного дизайна

## Криптографическая схема

### Общая схема шифрования

```
Мастер-пароль
      ↓
PBKDF2-SHA256/Argon2id (100,000 итераций)
      ↓
Мастер-ключ (256 бит)
      ↓
       ├──► Ключ шифрования данных (AES-256-GCM)
       ├──► Ключ аутентификации (HMAC-SHA256)
       └──► Ключ деривации для экспорта
```

### Шифрование записей

#### 1. Подготовка ключей
```python
# Генерация ключа из мастер-пароля
master_key = PBKDF2(
    password=master_password,
    salt=user_salt,
    iterations=100000,
    dklen=32  # 256 бит
)

# Деривация ключа шифрования
encryption_key = HKDF(
    ikm=master_key,
    salt=entry_salt,
    info=b"encryption",
    length=32
)
```

#### 2. Шифрование данных
```python
# AES-256-GCM шифрование
cipher = AES.new(encryption_key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Сохраняем: nonce + ciphertext + tag
stored_data = cipher.nonce + ciphertext + tag
```

#### 3. Верификация целостности
- GCM автоматически проверяет аутентификацию
- Дополнительная проверка HMAC-SHA256 для критичных данных
- Hash chain для журналов аудита

### Ключевая деривация

#### PBKDF2 (Рекомендуется по умолчанию)
```python
parameters = {
    "algorithm": "pbkdf2",
    "hash": "sha256",
    "iterations": 100000,
    "salt_length": 16
}
```

#### Argon2id (Для повышенной безопасности)
```python
parameters = {
    "algorithm": "argon2id",
    "time_cost": 2,
    "memory_cost": 65536,  # 64 MB
    "parallelism": 4,
    "salt_length": 16
}
```

## Модульная структура

### Ядро приложения (`src/core/`)

#### `config.py` - Конфигурация
- Чтение/запись настроек в JSON
- Поддержка профилей конфигурации
- Миграции версий конфигурации

#### `events.py` - Система событий
```python
class EventSystem:
    def subscribe(event_type, callback)
    def publish(event_type, data)
    def unsubscribe(event_type, callback)
```

#### `key_manager.py` - Управление ключами
- Генерация и хранение ключей
- Ротация ключей по расписанию
- Резервное копирование ключей

### Криптография (`src/core/crypto/`)

#### `abstract.py` - Абстрактный сервис
```python
class EncryptionService(ABC):
    @abstractmethod
    def encrypt(data: bytes, key: bytes) -> bytes
    @abstractmethod
    def decrypt(data: bytes, key: bytes) -> bytes
```

#### `authentication.py` - Аутентификация
- Проверка мастер-пароля
- Сессионные токены
- Ограничение попыток входа

#### `key_derivation.py` - Деривация ключей
- PBKDF2 с настраиваемыми параметрами
- Argon2id для повышенной безопасности
- Кеширование производных ключей

### Буфер обмена (`src/core/clipboard/`)

#### `clipboard_service.py` - Основной сервис
- Управление временем очистки
- Уведомления о копировании
- Интеграция с системой событий

#### `platform_adapter.py` - Адаптеры платформ
- Windows: `pywin32` для защищенного доступа
- macOS: `pyobjc` для NSPasteboard
- Linux: `pyperclip` как fallback

#### `clipboard_monitor.py` - Мониторинг
- Защита от слежки
- Обнаружение чтения буфера
- Блокировка неавторизованного доступа

### Аудит (`src/core/audit/`)

#### `audit_logger.py` - Логирование
- Структурированные логи в JSON
- Криптографическое подписание
- Ротация логов по размеру/времени

#### `log_signer.py` - Подписание логов
- Ed25519 для циф��овой подписи
- HMAC-SHA256 для внутренних логов
- Hash chain для защиты от подделки

#### `log_verifier.py` - Верификация
- Проверка цифровых подписей
- Валидация hash chain
- Обнаружение манипуляций

### Импорт/экспорт (`src/core/import_export/`)

#### `exporter.py` - Экспорт
- Поддержка multiple formats
- Шифрование на лету
- Инкрементальный экспорт

#### `importer.py` - Импорт
- Автоопределение формата
- Обработка конфликтов
- Валидация целостности

#### Форматы (`src/core/import_export/formats/`)
- JSON (зашифрованный/открытый)
- CSV с маскировкой паролей
- Bitwarden JSON
- LastPass CSV

## Система аудита

### Архитектура аудита

```
Событие приложения
      ↓
Audit Logger (Запись)
      ↓
Log Signer (Подпись Ed25519/HMAC)
      ↓
Хранилище (Шифрование AES-256-GCM)
      ↓
Hash Chain (Связывание записей)
```

### Типы аудируемых событий

#### 1. Аутентификация
- Успешные/неуспешные входы
- Смена мастер-пароля
- Блокировка/разблокировка сейфа

#### 2. Операции с данными
- Создание/редактирование/удаление записей
- Копирование в буфер обмена
- Экспорт/импорт данных

#### 3. Системные события
- Изменение настроек
- Обновления приложения
- Ошибки и исключения

### Криптографические гарантии

#### 1. Целостность (Hash Chain)
```
Hash(Entry₁) = H(Data₁ || Timestamp₁ || PrevHash₀)
Hash(Entry₂) = H(Data₂ || Timestamp₂ || Hash(Entry₁))
...
```

#### 2. Аутентичность (Цифровые подписи)
```python
# Генерация ключей Ed25519
private_key = SigningKey.generate()
public_key = private_key.verify_key

# Подпись записи
signature = private_key.sign(log_entry)

# Верификация
public_key.verify(signature, log_entry)
```

#### 3. Конфиденциальность (Шифрование)
- Логи шифруются AES-256-GCM
- Отдельный ключ для шифрования логов
- Периодическая ротация ключей шифрования

## Безопасность буфера обмена

### Архитектура защиты

```
Приложение
      ↓
Clipboard Service
      ↓
Platform Adapter (Windows/macOS/Linux)
      ↓
Системный буфер обмена
      ↓
Clipboard Monitor (Защита)
```

### Механизмы защиты

#### 1. Автоочистка
- Настраиваемый таймер (5 сек - 5 мин)
- Очистка при блокировке сейфа
- Принудительная очистка по требованию

#### 2. Мониторинг доступа
- Отслеживание чтения буфера другими процессами
- Уведомления о подозрительной активности
- Блокировка известных spyware процессов

#### 3. Secure Memory
```python
class SecureMemory:
    def allocate(size):
        # Windows: VirtualAlloc + VirtualLock
        # Linux: mmap + mlock
        # macOS: vm_allocate + mlock
        pass
    
    def zero_and_free(ptr, size):
        # Заполнение нулями перед освобождением
        # Использование memset_s или аналогичных
        pass
```

### Платформенно-зависимая реализация

#### Windows
```python
import win32clipboard
import win32con

class WindowsClipboardAdapter:
    def write_text(self, text):
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            # Использование защищенной памяти
            secure_text = secure_memory.allocate(len(text))
            # Копирование и очистка
            win32clipboard.SetClipboardText(text)
        finally:
            win32clipboard.CloseClipboard()
```

#### macOS
```python
from AppKit import NSPasteboard, NSPasteboardTypeString

class MacClipboardAdapter:
    def write_text(self, text):
        pb = NSPasteboard.generalPasteboard()
        pb.clearContents()
        pb.setString_forType_(text, NSPasteboardTypeString)
```

## Импорт/экспорт

### Поддерживаемые форматы

#### 1. CryptoSafe Encrypted JSON
```json
{
  "version": "1.0",
  "encryption": {
    "algorithm": "aes-256-gcm",
    "iterations": 100000,
    "salt": "base64...",
    "nonce": "base64..."
  },
  "data": {
    "entries": [
      {
        "id": "uuid",
        "name": "Пример",
        "username": "user@example.com",
        "password": "encrypted:base64...",
        "url": "https://example.com",
        "notes": "Заметки",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
      }
    ]
  }
}
```

#### 2. Bitwarden JSON
- Полная совместимость с Bitwarden
- Поддержка папок и коллекций
- Конвертац��я тегов и метаданных

#### 3. LastPass CSV
- Импорт из LastPass экспорта
- Маппинг полей CSV на внутреннюю схему
- Обработка специальных символов

### Безопасность экспорта

#### Шифрование экспорта
```python
def export_encrypted(data, password):
    # Генерация случайной соли
    salt = os.urandom(16)
    
    # Деривация ключа из пароля
    key = PBKDF2(password, salt, iterations=100000)
    
    # Шифрование данных
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(
        json.dumps(data).encode()
    )
    
    # Структура экспорта
    return {
        "version": EXPORT_VERSION,
        "salt": b64encode(salt).decode(),
        "nonce": b64encode(cipher.nonce).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
        "tag": b64encode(tag).decode()
    }
```

### Конфликт резолюция

#### Стратегии обработки
1. **Skip** - пропустить конфликтующие записи
2. **Replace** - заменить существующие записи
3. **Rename** - переименовать с суффиксом
4. **Merge** - объединить поля из обоих источников

#### Алгоритм слияния
```python
def merge_entries(existing, new):
    merged = existing.copy()
    
    # Приоритет новых данных для пустых полей
    for field in ['username', 'password', 'url', 'notes']:
        if not merged.get(field) and new.get(field):
            merged[field] = new[field]
    
    # Обновление метаданных
    merged['updated_at'] = datetime.utcnow()
    merged['source'] = 'merged'
    
    return merged
```

## Производительность и оптимизация

### Оптимизация базы данных

#### Индексы
```sql
-- Основные индексы для поиска
CREATE INDEX idx_entries_name ON entries(name);
CREATE INDEX idx_entries_username ON entries(username);
CREATE INDEX idx_entries_url ON entries(url);
CREATE INDEX idx_entries_created ON entries(created_at);

-- Индекс для аудита
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
```

#### Стратегии кеширования
1. **Кеш записей** - LRU кеш часто используемых записей
2. **Кеш ключей** - кеширование производных ключей
3. **Кеш конфигурации** - хранение настроек в памяти

### Оптимизация криптографии

#### Параллельная обработка
```python
from concurrent.futures import ThreadPoolExecutor

def batch_encrypt(entries, key):
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(encrypt_entry, entry, key)
            for entry in entries
        ]
        return [f.result() for f in futures]
```

#### Предвычисление ключей
- Кеширование мастер-ключа в защищенной памяти
- Предварительная деривация часто используемых ключей
- Отложенная инициализация ресурсоемких операций

### Мониторинг производительности

#### Метрики
- Время отклика операций CRUD
- Использование памяти
- Загрузка CPU при шифровании/дешифровании
- Размер базы данных и логов

#### Инструменты
- Встроенный профайлер для отладки
- Логирование медленных операций
- Статистика использования функций

## Тестирование и качество

### Стратегия тестирования

#### 1. Модульные тесты
```python
def test_encryption_service():
    service = EncryptionService()
    key = os.urandom(32)
    data = b"test data"
    
    ciphertext = service.encrypt(data, key)
    plaintext = service.decrypt(ciphertext, key)
    
    assert plaintext == data
```

#### 2. Интеграционные тесты
- Тестирование полного цикла операций
- Тестирование импорта/экспорта
- Тестирование взаимодействия с БД

#### 3. Тесты безопасности
- Тестирование side-channel атак
- Тестирование устойчивости к brute force
- Тестирование целостности данных

### Покрытие кода
```bash
# Запуск тестов с измерением покрытия
pytest --cov=src --cov-report=html

# Генерация отчета
pytest --cov=src --cov-report=xml:coverage.xml
```

### Continuous Integration
- Автоматический запуск тестов при push
- Проверка покрытия кода
- Статический анализ кода
- Проверка безопасности зависимостей

## Развертывание

### Сборка исполняемого файла

#### PyInstaller Spec
```spec
# cryptosafe.spec
a = Analysis(
    ['main.py'],
    hiddenimports=[
        'src',
        'cryptography',
        'argon2',
        # ... все зависимости
    ],
    datas=[('assets/', 'assets')],
    binaries=[],
    ...
)
```

#### Команда сборки
```bash
# Сборка одной папки
pyinstaller --onedir --windowed main.py

# Сборка одного файла
pyinstaller --onefile --windowed main.py

# С использованием spec файла
pyinstaller cryptosafe.spec
```

### Конфигурация развертывания

#### Требования к окружению
- Python 3.8+
- SQLite 3.35+
- Современный процессор с поддержкой AES-NI (рекомендуется)

#### Настройки безопасности
- Отключение debug режима в production
- Настройка политик безопасности ОС
- Регулярное обновление зависимостей

### Мониторинг в production

#### Логирование
- Структурированные логи в JSON
- Ротация логов по размеру и времени
- Централизованный сбор логов

#### Метарики
- Количество пользователей
- Частота операций
- Ошибки и исключения
- Производительность операций

### Резервное копирование

#### Стратегия
1. **Ежедневные полные копии**
2. **Инкрементальные копии каждый час**
3. **Проверка целостности резервных копий**
4. **Хранение в нескольких местах**

#### Автоматизация
```python
def backup_database():
    # Создание зашифрованной резервной копии
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"backup_{timestamp}.db.enc"
    
    with open('database.db', 'rb') as f:
        data = f.read()
    
    encrypted = encrypt_data(data, backup_key)
    
    with open(backup_file, 'wb') as f:
        f.write(encrypted)
    
    # Валидация резервной копии
    validate_backup(backup_file)
```

---

*Документация обновлена: Июнь 2026*