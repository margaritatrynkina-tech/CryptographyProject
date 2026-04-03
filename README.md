# CryptoSafe Manager

Безопасный менеджер паролей с открытым кодом, разрабатываемый по спринтовой методологии.

## Roadmap (8 спринтов)

### Sprint 1  Фундамент и архитектура
- [x] Модульная структура (MVC)
- [x] Менеджер конфигурации
- [x] Схема базы данных SQLite
- [x] Абстрактный сервис шифрования
- [x] Заглушка AES (XOR для тестов)
- [x] Базовый GUI с главным окном
- [x] Мастер первоначальной настройки
- [x] Система событий

### Sprint 2 Управление ключами
- [x] PBKDF2/Argon2 для ключевой деривации
- [x] Хранилище ключей в БД
- [x] Проверка мастер-пароля
- [x] Смена мастер-пароля

### Sprint 3 Настоящее шифрование
- [ ] AES-256-GCM с аутентификацией
- [ ] Интеграция с cryptography
- [ ] Верификация целостности

### Sprint 4 Буфер обмена и UX
- [ ] Автоматическая очистка буфера
- [ ] Генератор паролей
- [ ] Индикатор сложности
- [ ] Поиск и фильтрация

### Sprint 5 Аудит и журналы
- [ ] Полный журнал действий
- [ ] Просмотрщик аудита
- [ ] Экспорт журнала

### Sprint 6 Теги и организация
- [ ] Категории и теги
- [ ] Группировка записей
- [ ] Избранное

### Sprint 7 Автоблокировка
- [ ] Таймер неактивности
- [ ] Блокировка при свертывании
- [ ] Политика паролей

### Sprint 8 Упаковка
- [ ] Сборка в исполняемый файл
- [ ] Docker контейнер
- [ ] Инсталлятор

## Установка и запуск

### Виртуальное окружение

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
#Структура проекта
cryptosafe-manager/
src/
├── core/                             
│   ├── __init__.py
│   ├── config.py                    
│   ├── events.py                    
│   ├── key_manager.py               
│   └── crypto/                      
│       ├── __init__.py
│       ├── abstract.py              
│       ├── authentication.py        
│       ├── key_derivation.py        
│       ├── key_storage.py           
│       ├── password_policy.py       
│       └── placeholder.py           
├── database/                        
│   ├── __init__.py
│   └── db.py                        
├── gui/                             
│   ├── __init__.py
│   ├── main_window.py               
│   └── widgets/
│       └── password_entry.py
└── main.py                           

tests/                                 
├── test_argon2_params.py             
├── test_pbkdf2_consistency.py       
├── test_key_cache.py                 
└── ... (Sprint 1/3)

docs/
├── README.md                         
└── sprint2/
    └── architecture.md              
                    # Документация