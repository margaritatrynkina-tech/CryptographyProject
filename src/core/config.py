import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
class ConfigManager:
    def __init__(self):
        self.config_dir = Path.home() / ".cryptosafe"
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "config.json"
        self._data: Dict[str, Any] = {}
        self.load()
    def load(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self._data = json.load(f)
            except:
                self._data = {}
    def save(self):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)
    def set(self, key: str, value: Any):
        self._data[key] = value
        self.save()
    @property
    def db_path(self) -> Optional[str]:
        return self.get('db_path')
    @db_path.setter
    def db_path(self, path: str):
        self.set('db_path', path)