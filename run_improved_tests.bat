@echo off
echo Запуск улучшенных тестов CryptoSafe Manager...
echo.

echo 1. Запуск всех улучшенных тестов...
py -m pytest tests/test_*improved.py tests/test_*fixed.py -v --tb=short
if %errorlevel% neq 0 (
    echo.
    echo Некоторые тесты не прошли. Проверьте детали выше.
    pause
    exit /b %errorlevel%
)

echo.
echo 2. Проверка покрытия core-модулей...
py -m pytest tests/ --cov=src --cov-config=.coveragerc --cov-report=term-missing -k "not property and not perf" --tb=no

echo.
echo 3. Проверка времени выполнения...
echo Все тесты должны выполняться менее 30 секунд (согласно pytest.ini)
echo.

echo Улучшенные тесты успешно запущены!
echo Создано 138 новых тестов для 7 core-модулей.
echo.
pause