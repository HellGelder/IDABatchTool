import json
import logging
import sqlite3
from pathlib import Path

import requests
from PySide6.QtCore import QThread, Signal

logger = logging.getLogger(__name__)


class Win32DatabaseSync(QThread):
    progress = Signal(str, int)  # message, percent (0-100)
    finished = Signal(bool, str)  # success, message (path or error)
    error = Signal(str)           # error message

    def __init__(self, db_dir: str):
        super().__init__()
        self.db_dir = Path(db_dir)
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self.progress.emit("Подготовка к загрузке...", 5)

            # 1. Скачиваем готовый файл winapi_categories.json
            json_url = "https://raw.githubusercontent.com/reverseame/winapi-categories/main/winapi_categories.json"
            self.progress.emit("Скачивание winapi_categories.json...", 20)

            response = requests.get(json_url, stream=True, timeout=60)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            content = bytearray()
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                if self._cancel:
                    self.error.emit("Отменено пользователем")
                    return
                content.extend(chunk)
                downloaded += len(chunk)
                if total_size:
                    percent = 20 + int(40 * downloaded / total_size)
                    self.progress.emit("Скачивание...", percent)

            self.progress.emit("Обработка JSON...", 65)
            data = json.loads(content.decode('utf-8'))

            # 2. Создаём SQLite базу данных
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
                    description TEXT,
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
                    description TEXT,
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
                           ("version", "winapi_categories_latest"))
            cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                           ("source_url", json_url))

            count = 0
            for func_name, func_info in data.items():
                if self._cancel:
                    conn.close()
                    self.error.emit("Отменено пользователем")
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
                        description = arg.get("description", "")
                        cursor.execute(
                            "INSERT INTO parameters (function_id, idx, in_out, name, type, description) VALUES (?, ?, ?, ?, ?, ?)",
                            (func_id, idx, in_out, arg_name, arg_type, description)
                        )
                count += 1
                if count % 100 == 0:
                    conn.commit()
                    self.progress.emit(f"Обработано функций: {count}", 65 + min(30, int(count / 5000 * 30)))

            conn.commit()
            conn.close()
            self.progress.emit(f"Готово. Обработано функций: {count}", 100)
            self.finished.emit(True, str(db_path))

        except Exception as e:
            logger.exception("Ошибка синхронизации Win32 API")
            self.error.emit(str(e))
            self.finished.emit(False, str(e))