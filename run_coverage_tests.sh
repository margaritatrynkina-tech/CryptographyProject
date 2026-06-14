#!/bin/bash

echo "============================================"
echo "Запуск тестов для улучшения покрытия до 80%"
echo "============================================"

echo ""
echo "1. Запуск тестов authentication.py..."
python -m pytest tests/test_authentication_extended.py -v

echo ""
echo "2. Запуск тестов password_policy.py..."
python -m pytest tests/test_password_policy_extended.py -v

echo ""
echo "3. Запуск тестов key_storage.py..."
python -m pytest tests/test_key_storage.py -v

echo ""
echo "4. Запуск тестов secure_memory.py..."
python -m pytest tests/test_secure_memory.py -v

echo ""
echo "5. Запуск тестов config.py..."
python -m pytest tests/test_config_extended.py -v

echo ""
echo "6. Запуск тестов key_manager.py..."
python -m pytest tests/test_key_manager.py -v

echo ""
echo "7. Запуск всех тестов с измерением покрытия..."
python -m pytest --cov=src --cov-report=term-missing

echo ""
echo "============================================"
echo "Тестирование завершено!"
echo "Проверьте отчет coverage выше."
echo "Для детального HTML отчета выполните:"
echo "python -m pytest --cov=src --cov-report=html"
echo "============================================"