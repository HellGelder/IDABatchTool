"""SQLite-кэш для документации Microsoft Learn по системным функциям."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional


class SfaDocCache:
    """SQLite-база для кэширования результатов поиска MS Learn.

    Позволяет избежать повторных запросов к Microsoft Learn для уже
    найденных функций. Хранит markdown-документацию и HTML-версию,
    а также информационное поле dll_name (имя системного модуля).
    """

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Создаёт таблицы, если их нет."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS functions (
                        name TEXT PRIMARY KEY,
                        dll_name TEXT NOT NULL DEFAULT '',
                        fetched_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        function_name TEXT NOT NULL,
                        result_idx INTEGER NOT NULL,
                        title TEXT NOT NULL DEFAULT '',
                        url TEXT NOT NULL DEFAULT '',
                        markdown TEXT NOT NULL DEFAULT '',
                        markdown_html TEXT NOT NULL DEFAULT '',
                        FOREIGN KEY (function_name) REFERENCES functions(name),
                        UNIQUE(function_name, result_idx)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_results_fn
                    ON results(function_name)
                """)
                conn.commit()
            finally:
                conn.close()

    def has_function(self, func_name: str) -> bool:
        """Проверяет, есть ли функция в кэше."""
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                cur = conn.execute(
                    "SELECT 1 FROM functions WHERE name = ?", (func_name,)
                )
                return cur.fetchone() is not None
            finally:
                conn.close()

    def get_dll_name(self, func_name: str) -> str:
        """Возвращает сохранённое имя DLL для функции (или пустую строку)."""
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                cur = conn.execute(
                    "SELECT dll_name FROM functions WHERE name = ?", (func_name,)
                )
                row = cur.fetchone()
                return row[0] if row else ""
            finally:
                conn.close()

    def get_results(self, func_name: str) -> List[dict]:
        """Возвращает результаты для функции (или пустой список)."""
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(
                    "SELECT title, url, markdown, markdown_html "
                    "FROM results WHERE function_name = ? "
                    "ORDER BY result_idx",
                    (func_name,),
                )
                rows = cur.fetchall()
                return [
                    {
                        "title": row["title"],
                        "url": row["url"],
                        "markdown": row["markdown"],
                        "markdown_html": row["markdown_html"],
                    }
                    for row in rows
                ]
            finally:
                conn.close()

    def save_results(self, func_name: str, results: List[dict], dll_name: str = "") -> None:
        """Сохраняет результаты поиска для функции.

        Args:
            func_name: имя функции.
            results: список словарей с ключами title/url/markdown/markdown_html.
            dll_name: информационное имя системного модуля (может быть пустым).
        """
        now = datetime.now().isoformat()
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO functions (name, dll_name, fetched_at) VALUES (?, ?, ?)",
                    (func_name, dll_name, now),
                )
                conn.execute(
                    "DELETE FROM results WHERE function_name = ?", (func_name,)
                )
                for idx, r in enumerate(results):
                    conn.execute(
                        "INSERT INTO results "
                        "(function_name, result_idx, title, url, markdown, markdown_html) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            func_name,
                            idx,
                            r.get("title", ""),
                            r.get("url", ""),
                            r.get("markdown", ""),
                            r.get("markdown_html", ""),
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def count(self) -> int:
        """Количество закешированных функций."""
        with self._lock:
            conn = sqlite3.connect(str(self._db_path))
            try:
                cur = conn.execute("SELECT COUNT(*) FROM functions")
                return cur.fetchone()[0]
            finally:
                conn.close()

    def close(self) -> None:
        """Закрыть соединение (ничего не делаем — соединения открываются на запрос)."""
        pass