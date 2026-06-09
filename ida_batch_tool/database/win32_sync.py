import json
import logging
import sqlite3
from pathlib import Path

import requests
from PySide6.QtCore import QThread, Signal

logger = logging.getLogger(__name__)


class Win32DatabaseSync(QThread):
    progress = Signal(str, int)
    finished = Signal(bool, str)
    error = Signal(str)

    def __init__(self, db_dir: str):
        super().__init__()
        self.db_dir = Path(db_dir)
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self.progress.emit("Загрузка сигнатур функций...", 10)
            json_url = "https://raw.githubusercontent.com/reverseame/winapi-categories/main/winapi_categories.json"
            resp_json = requests.get(json_url, timeout=30)
            resp_json.raise_for_status()
            categories_data = resp_json.json()

            self.db_dir.mkdir(parents=True, exist_ok=True)
            db_path = self.db_dir / "win32api.db"

            conn = sqlite3.connect(str(db_path))
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS functions (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE,
                    category TEXT,
                    dll_name TEXT,
                    return_type TEXT,
                    n_arguments INTEGER
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS parameters (
                    id INTEGER PRIMARY KEY,
                    function_id INTEGER,
                    idx INTEGER,
                    in_out TEXT,
                    name TEXT,
                    type TEXT,
                    FOREIGN KEY(function_id) REFERENCES functions(id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                           ("signatures_version", "latest"))

            count = 0
            for func_name, func_info in categories_data.items():
                if self._cancel:
                    conn.close()
                    return
                if not isinstance(func_info, dict):
                    continue
                category = func_info.get("category", "")
                dll_name = func_info.get("dll", "")
                return_type = func_info.get("return_type", "")
                n_arguments = func_info.get("n_arguments", 0)
                args = func_info.get("arguments", [])

                cursor.execute(
                    "INSERT OR IGNORE INTO functions (name, category, dll_name, return_type, n_arguments) VALUES (?, ?, ?, ?, ?)",
                    (func_name, category, dll_name, return_type, n_arguments)
                )
                cursor.execute("SELECT id FROM functions WHERE name = ?", (func_name,))
                row = cursor.fetchone()
                if row:
                    func_id = row[0]
                    cursor.execute("DELETE FROM parameters WHERE function_id = ?", (func_id,))
                    for idx, arg in enumerate(args):
                        if not isinstance(arg, dict):
                            continue
                        in_out = arg.get("in_out", "")
                        arg_name = arg.get("name", f"arg{idx}")
                        arg_type = arg.get("type", "unknown")
                        cursor.execute(
                            "INSERT INTO parameters (function_id, idx, in_out, name, type) VALUES (?, ?, ?, ?, ?)",
                            (func_id, idx, in_out, arg_name, arg_type)
                        )
                count += 1
                if count % 100 == 0:
                    conn.commit()
                    self.progress.emit(f"Обработано сигнатур: {count}", 50 + min(30, count // 5000))

            conn.commit()
            conn.close()
            self.progress.emit(f"Сигнатуры сохранены: {count} функций", 100)
            self.finished.emit(True, str(db_path))

        except Exception as e:
            logger.exception("Ошибка синхронизации")
            self.error.emit(str(e))
            self.finished.emit(False, str(e))