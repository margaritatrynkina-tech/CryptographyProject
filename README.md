# CryptoSafe Manager

Безопасный менеджер паролей с открытым кодом, разрабатываемый по спринтовой методологии.

## Roadmap (8 спринтов)

### Sprint 1 — Фундамент и архитектура
- [x] Модульная структура (MVC)
- [x] Менеджер конфигурации
- [x] Схема базы данных SQLite
- [x] Абстрактный сервис шифрования
- [x] Заглушка AES (XOR для тестов)
- [x] Базовый GUI с главным окном
- [x] Мастер первоначальной настройки
- [x] Система событий

### Sprint 2 — Управление ключами
- [x] PBKDF2/Argon2 для ключевой деривации
- [x] Хранилище ключей в БД
- [x] Проверка мастер-пароля
- [x] Смена мастер-пароля

### Sprint 3 — Настоящее шифрование
- [ ] AES-256-GCM с аутентификацией
- [ ] Интеграция с cryptography
- [ ] Верификация целостности

### Sprint 4 — Буфер обмена и безопасность 
- [x] Модуль `src/core/clipboard/` (3 файла)
- [x] `ClipboardService` — основная логика с автоочисткой
- [x] `PlatformAdapter` — работа с буфером на Windows/macOS/Linux
- [x] `ClipboardMonitor` — защита от слежки за буфером
- [x] Настраиваемый таймер автоочистки (5 сек — 5 мин)
- [x] Сохранение настроек таймера в БД
- [x] Кнопки "Copy Password" / "Copy Username" в GUI
- [x] Контекстное меню "Copy All"
- [x] Копирование только при разблокированном сейфе
- [x] Уведомления о копировании/очистке
- [x] Очистка буфера при закрытии/блокировке сейфа
- [x] Поддержка `pyperclip` как fallback

### Sprint 5 — Аудит и журналы 
- [x] Модуль `src/core/audit/` (audit_logger.py, log_signer.py, log_verifier.py, log_formatters.py)
- [x] Криптографическое подписание логов (Ed25519 / HMAC-SHA256)
- [x] Hash chain для защиты от подделки
- [x] Шифрование логов в покое (AES-256-GCM)
- [x] GUI просмотрщик аудита с фильтрацией и поиском
- [x] Экспорт логов в JSON, CSV, PDF
- [x] Периодическая проверка целостности (каждые 24 часа)
- [x] Интеграция с EventSystem из Sprint 1
- [x] Все 5 тестов (Integrity, Performance, Export/Import, Recovery, Security)

### Sprint 6 — Импорт/Экспорт и шаринг 
- [x] Модуль `src/core/import_export/` (exporter.py, importer.py, sharing_service.py, key_exchange.py)
- [x] Модуль `src/core/import_export/formats/` (json_handler.py, csv_handler.py, bitwarden_handler.py, lastpass_handler.py)
- [x] Экспорт в форматы: Encrypted JSON, CSV, Bitwarden JSON, LastPass CSV
- [x] Импорт из: Encrypted JSON, CSV, Bitwarden JSON, LastPass CSV
- [x] AES-256-GCM шифрование с PBKDF2 (отдельный ключ от мастер-пароля)
- [x] Поддержка публичных ключей (RSA-2048 / ECC P-256) для экспорта
- [x] CSV экспорт с маскировкой паролей `[ENCRYPTED]`
- [x] Конфликт резолюция: Skip / Replace / Rename / Merge
- [x] Dry-run режим (предпросмотр без сохранения)
- [x] Режим эфемерного буфера (ephemeral mode)
- [x] QR код генерация и сканирование (для обмена ключами)
- [x] GUI диалоги: экспорта, импорта, шаринга
- [x] Автоопределение формата при импорте (CryptoSafe / Bitwarden / LastPass)
- [x] Интеграция с аудитом (логирование импорта/экспорта)
- [x] Все 5 тестов (Round-trip, Interoperability, Sharing security, QR code, Performance)

### Sprint 7 — Security Hardening
- [x] Защита от side-channel (`side_channel_protection.py`, constant-time сравнение)
- [x] Безопасная память (`memory_guard.py`, `ctypes.memset`, mlock/VirtualLock)
- [x] Мониторинг активности и автоблокировка (`activity_monitor.py`, `auto_lock.py`)
- [x] Panic Mode и stealth (`panic_mode.py`, горячая клавиша Ctrl+Shift+Esc)
- [x] Профили безопасности Standard / Enhanced / Paranoid (`profiles.py`)
- [x] System Tray и фоновая работа (`system_tray.py`)
- [x] Тесты Sprint 7 (`tests/test_sprint7.py`: secure_zero, auto_lock, panic_mode)

### Sprint 8 — Упаковка
- [ ] Сборка в исполняемый файл
- [ ] Docker контейнер
- [ ] Инсталлятор

---
cryptosafe-manager/
src/
├── core/                             
│   ├── __init__.py
│   ├── config.py                    
│   ├── events.py                    
│   ├── key_manager.py               
│   ├── crypto/                      
│   │   ├── __init__.py
│   │   ├── abstract.py              
│   │   ├── authentication.py        
│   │   ├── key_derivation.py        
│   │   ├── key_storage.py           
│   │   ├── password_policy.py       
│   │   └── placeholder.py           
│   ├── clipboard/                   # Sprint 4
│   │   ├── __init__.py
│   │   ├── clipboard_service.py
│   │   ├── platform_adapter.py
│   │   └── clipboard_monitor.py
│   ├── audit/                       # Sprint 5
│   │   ├── __init__.py
│   │   ├── audit_logger.py
│   │   ├── log_signer.py
│   │   ├── log_verifier.py
│   │   └── log_formatters.py
│   └── import_export/               # Sprint 6
│       ├── __init__.py
│       ├── exporter.py
│       ├── importer.py
│       ├── sharing_service.py
│       ├── key_exchange.py
│       ├── models.py
│       └── formats/
│           ├── __init__.py
│           ├── json_handler.py
│           ├── csv_handler.py
│           ├── bitwarden_handler.py
│           └── lastpass_handler.py
├── database/                        
│   ├── __init__.py
│   └── db.py                        
├── gui/                             
│   ├── __init__.py
│   ├── main_window.py
│   ├── widgets/
│   │   ├── password_entry.py
│   │   ├── toast.py
│   │   ├── clipboard_preview.py
│   │   └── audit_viewer.py
│   └── dialogs/
│       ├── export_dialog.py
│       ├── import_dialog.py
│       └── sharing_dialog.py
└── main.py

tests/                                 
├── test_sprint4_clipboard.py
├── test_sprint5_audit.py
├── test_sprint6.py
└── ...

##  Установка и запуск

### Виртуальное окружение

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
python main.py

## Тестирование

Для запуска тестов с измерением покрытия кода используйте pytest с плагином pytest-cov:

```bash
pytest --cov=src
```

Команда выполнит все тесты и покажет процент покрытия кода тестами. Для более детальной информации можно использовать:

```bash
pytest --cov=src --cov-report=html
```

Это создаст HTML отчет в папке `htmlcov/`, который можно открыть в браузере для визуального анализа покрытия кода.

Для запуска тестов конкретного модуля:
```bash
pytest tests/test_sprint4_clipboard.py --cov=src/core/clipboard
```

### Генерация исполняемого файла

Для сборки standalone .exe файла используйте pyinstaller с созданным spec файлом:

```bash
pyinstaller cryptosafe.spec
```

Или напрямую через pyinstaller:
```bash
pyinstaller --onefile --windowed --name="CryptoSafe Manager" main.py
```