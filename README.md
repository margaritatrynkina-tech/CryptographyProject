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

### Sprint 4 — Буфер обмена и безопасность ✅
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
- [ ] Генератор паролей (перенесён в Sprint 5)
- [ ] Индикатор сложности (перенесён в Sprint 5)

### Sprint 5 — Аудит и журналы
- [ ] Полный журнал действий
- [ ] Просмотрщик аудита
- [ ] Экспорт журнала
- [ ] Генератор паролей (из Sprint 4)

### Sprint 6 — Теги и организация
- [ ] Категории и теги
- [ ] Группировка записей
- [ ] Избранное

### Sprint 7 — Автоблокировка
- [ ] Таймер неактивности
- [ ] Блокировка при свертывании
- [ ] Политика паролей

### Sprint 8 — Упаковка
- [ ] Сборка в исполняемый файл
- [ ] Docker контейнер
- [ ] Инсталлятор

---

##  Установка и запуск

### Виртуальное окружение

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
python main.py

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
│   └── clipboard/                    # Sprint 4
│       ├── __init__.py
│       ├── clipboard_service.py      # Основная логика (таймер, очистка)
│       ├── platform_adapter.py       # Windows/macOS/Linux адаптеры
│       └── clipboard_monitor.py      # Защита от слежки
├── database/                        
│   ├── __init__.py
│   └── db.py                        
├── gui/                             
│   ├── __init__.py
│   ├── main_window.py               # Добавлены кнопки копирования
│   └── widgets/
│       └── password_entry.py
└── main.py                           

tests/                                 
├── test_clipboard_service.py         # Тесты для Sprint 4
├── test_argon2_params.py             
├── test_pbkdf2_consistency.py       
└── ...

requirements.txt                      # Добавлены: pyperclip, pywin32, pyobjc, argon2-cffi



pytest tests/test_clipboard_service.py -v