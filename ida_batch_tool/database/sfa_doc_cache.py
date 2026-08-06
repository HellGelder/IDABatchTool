"""SQLite-кэш для документации Microsoft Learn по системным функциям.

Содержит два класса:
  - SfaDocCache: низкоуровневый доступ к SQLite (чтение/запись).
  - DocCacheManager: потокобезопасный менеджер с очередью записи.
"""
from __future__ import annotations

import sqlite3
import threading
import queue
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable

logger = logging.getLogger(__name__)


class _WriteTask:
    """Задача на запись в очередь DocCacheManager."""
    __slots__ = ("func_name", "dll_name", "results", "done_event", "exception")

    def __init__(self, func_name: str, dll_name: str, results: List[dict]):
        self.func_name = func_name
        self.dll_name = dll_name
        self.results = results
        self.done_event = threading.Event()
        self.exception: Optional[Exception] = None

    def wait(self, timeout: float = 10.0) -> None:
        """Дождаться завершения записи."""
        self.done_event.wait(timeout)


class SfaDocCache:
    """SQLite-база для кэширования результатов поиска MS Learn.

    Непосредственная работа с SQLite. Не потокобезопасна — используйте
    DocCacheManager для многопоточного доступа.
    """

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Создаёт таблицы, если их нет."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
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
        """Сохраняет результаты поиска для функции (синхронно, не потокобезопасно).

        Args:
            func_name: имя функции.
            results: список словарей с ключами title/url/markdown/markdown_html.
            dll_name: информационное имя системного модуля.
        """
        now = datetime.now().isoformat()
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
        conn = sqlite3.connect(str(self._db_path))
        try:
            cur = conn.execute("SELECT COUNT(*) FROM functions")
            return cur.fetchone()[0]
        finally:
            conn.close()


class DocCacheManager:
    """Потокобезопасный менеджер кэша документации MS Learn.

    Чтение — напрямую из SQLite (WAL + busy_timeout=5000 позволяет
    читать одновременно с записью).
    Запись — через очередь: фоновый поток-писатель последовательно
    обрабатывает задачи, что исключает 'database is locked' при
    параллельных вызовах из разных потоков.
    """

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._raw = SfaDocCache(db_path)
        self._write_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._writer_thread = threading.Thread(
            target=self._writer_loop,
            name="DocCacheWriter",
            daemon=True,
        )
        self._writer_thread.start()

    # ─── чтение (прямой доступ к SQLite) ───────────────────────────

    def has_function(self, func_name: str) -> bool:
        return self._raw.has_function(func_name)

    def get_dll_name(self, func_name: str) -> str:
        return self._raw.get_dll_name(func_name)

    def get_results(self, func_name: str) -> List[dict]:
        return self._raw.get_results(func_name)

    def count(self) -> int:
        return self._raw.count()

    # ─── запись (через очередь) ────────────────────────────────────

    def save_results(self, func_name: str, results: List[dict], dll_name: str = "") -> None:
        """Ставит задачу на запись в очередь и сразу возвращает управление.

        Запись выполнится в фоновом потоке-писателе.
        """
        task = _WriteTask(func_name, dll_name, results)
        self._write_queue.put(task)

    def save_results_and_wait(self, func_name: str, results: List[dict], dll_name: str = "") -> bool:
        """Ставит задачу на запись и ждёт её завершения (таймаут 10 сек).

        Returns:
            True — запись успешна, False — ошибка или таймаут.
        """
        task = _WriteTask(func_name, dll_name, results)
        self._write_queue.put(task)
        task.wait(timeout=10.0)
        if task.exception:
            logger.warning(f"Cache write failed for {func_name}: {task.exception}")
            return False
        return True

    # ─── фоновый писатель ──────────────────────────────────────────

    def _writer_loop(self) -> None:
        """Фоновый поток: читает задачи из очереди и пишет в БД."""
        while not self._stop_event.is_set():
            try:
                # Ждём задачу до 1 секунды (чтобы можно было выйти по stop)
                task: _WriteTask = self._write_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._raw.save_results(task.func_name, task.results, task.dll_name)
                task.exception = None
            except Exception as e:
                logger.exception(f"DocCache writer error for {task.func_name}")
                task.exception = e
            finally:
                task.done_event.set()
                self._write_queue.task_done()

    # ─── управление жизненным циклом ───────────────────────────────

    def flush(self) -> None:
        """Дождаться завершения всех текущих задач записи."""
        self._write_queue.join()

    def close(self) -> None:
        """Остановить фоновый писатель и дождаться завершения."""
        self.flush()
        self._stop_event.set()
        if self._writer_thread.is_alive():
            self._writer_thread.join(timeout=5.0)

    def __del__(self):
        self.close()