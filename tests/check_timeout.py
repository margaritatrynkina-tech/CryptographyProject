import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Проверка через ConfigManager
from src.core.config import ConfigManager
config = ConfigManager()
timeout = config.get('clipboard_timeout')
print(f"ConfigManager clipboard_timeout: {timeout}")

# Проверка через файл
import json
config_path = os.path.expanduser("~/.cryptosafe/config.json")
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        data = json.load(f)
        print(f"config.json clipboard_timeout: {data.get('clipboard_timeout', 'not found')}")

# Проверка через БД (если используете encrypted_settings)
try:
    from src.database.db import get_db_connection
    conn = get_db_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = 'clipboard_timeout'").fetchone()
    if row:
        print(f"Database settings clipboard_timeout: {row['value']}")
    conn.close()
except:
    print("Database check skipped")