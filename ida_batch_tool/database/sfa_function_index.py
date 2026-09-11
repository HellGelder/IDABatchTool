"""Индекс системных функций: предварительный проход по JSON-файлам.

Строит SQLite-БД уникальных функций, относящихся к системным библиотекам
выбранной платформы (по словарям классификатора). Используется для отсева
неподходящих функций перед обращением к базе знаний.

Платформа анализа сохраняется в таблице ``meta``, поэтому режим
перегенерации HTML из кэша использует тот же набор словарей, что и
исходный анализ.
"""
from __future__ import annotations

import json
import sqlite3
import logging
from pathlib import Path
from typing import List, Callable, Optional

from ida_batch_tool.classifier.categories import get_module_category
from ida_batch_tool.classifier.naming import normalize_module_name
from ida_batch_tool.classifier.system_modules import (
    is_system_module,
    normalize_platform,
)

logger = logging.getLogger(__name__)

# Значение по умолчанию, если платформа не задана (обратная совместимость).
_DEFAULT_PLATFORM = "Windows"


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS system_functions (
    func_name TEXT PRIMARY KEY,
    module_name TEXT NOT NULL,
    module_key TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS system_modules (
    module_key TEXT PRIMARY KEY,
    module_name TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS file_imports (
    json_path TEXT NOT NULL,
    file_name TEXT NOT NULL DEFAULT '',
    func_name TEXT NOT NULL,
    module_name TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (json_path, func_name)
);
CREATE INDEX IF NOT EXISTS idx_fi_jp ON file_imports(json_path);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
"""


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Добавляет отсутствующие колонки/таблицы в БД старых версий."""
    def _columns(table: str) -> list[str]:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return [row[1] for row in cur.fetchall()]

    if "file_size" not in _columns("file_imports"):
        conn.execute("ALTER TABLE file_imports ADD COLUMN file_size INTEGER NOT NULL DEFAULT 0")

    if "module_key" not in _columns("system_functions"):
        conn.execute("ALTER TABLE system_functions ADD COLUMN module_key TEXT NOT NULL DEFAULT ''")
        rows = conn.execute("SELECT func_name, module_name FROM system_functions").fetchall()
        for func_name, module_name in rows:
            conn.execute(
                "UPDATE system_functions SET module_key = ? WHERE func_name = ?",
                (normalize_module_name(module_name or ""), func_name),
            )

    # Заполняем system_modules из уже собранных функций (старые БД).
    if conn.execute("SELECT COUNT(*) FROM system_modules").fetchone()[0] == 0:
        rows = conn.execute(
            "SELECT DISTINCT module_key, module_name, category FROM system_functions "
            "WHERE module_key <> ''"
        ).fetchall()
        for module_key, module_name, category in rows:
            conn.execute(
                "INSERT OR IGNORE INTO system_modules "
                "(module_key, module_name, category) VALUES (?, ?, ?)",
                (module_key, module_name, category),
            )

    # Старые БД собирались только для Windows.
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('platform', ?)",
        (_DEFAULT_PLATFORM,),
    )


class SfaFunctionIndex:
    """Индекс системных функций, построенный из JSON-файлов экспорта.

    Двухфазное использование:
    1. ``build_from_jsons()`` — предварительный проход, сбор уникальных функций.
    2. ``is_known()`` — быстрая проверка наличия функции в индексе.

    После сборки — read-only, потокобезопасен (WAL-mode).
    """

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._available = False

    # ─── Фаза сборки ────────────────────────────────────────────────

    @classmethod
    def build_from_jsons(
        cls,
        json_files: List[Path],
        db_path: str | Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        platform: str = _DEFAULT_PLATFORM,
    ) -> "SfaFunctionIndex":
        """Сканирует JSON-файлы, собирает уникальные системные функции.

        Для каждого JSON читает ``imports[].module`` и ``imports[].name``.
        Если module относится к системной библиотеке указанной платформы
        (по словарям классификатора), пара (name, module) сохраняется
        в SQLite-индекс.

        Args:
            json_files: список путей к .export.json.
            db_path: путь к файлу SQLite БД (будет создан).
            progress_callback: (current, total) после каждого файла.
            platform: целевая платформа анализа. По умолчанию Windows
                (обратная совместимость с прежним поведением).

        Returns:
            Экземпляр SfaFunctionIndex с заполненной БД.
        """
        instance = cls(db_path)
        instance._build(json_files, progress_callback, platform)
        return instance

    def _build(
        self,
        json_files: List[Path],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        platform: str = _DEFAULT_PLATFORM,
    ) -> None:
        """Внутренний метод сборки индекса."""
        total = len(json_files)
        platform = normalize_platform(platform)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self._db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA_SQL)
            _migrate_schema(conn)

            # Пересборка всегда актуализирует платформу и результаты.
            conn.execute("DELETE FROM system_functions")
            conn.execute("DELETE FROM system_modules")
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('platform', ?)",
                (platform,),
            )

            # Множество для дедупликации функций (одна функция — один раз).
            seen: set[str] = set()

            for idx, json_path in enumerate(json_files):
                if not json_path.exists():
                    continue
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception as e:
                    logger.warning("Skipping %s: %s", json_path.name, e)
                    if progress_callback:
                        progress_callback(idx + 1, total)
                    continue

                json_path_str = str(json_path)
                file_name = data.get("file_name", "")
                imports = data.get("imports", [])

                # Размер исходного исполняемого файла (один для всех импортов)
                src_path = Path(file_name)
                if not src_path.is_absolute():
                    src_path = json_path.parent.parent / src_path
                file_size = src_path.stat().st_size if src_path.exists() else 0

                # Удаляем старые импорты для этого json_path (на случай перезапуска)
                conn.execute(
                    "DELETE FROM file_imports WHERE json_path = ?",
                    (json_path_str,),
                )

                for imp in imports:
                    func_name = imp.get("name", "")
                    module = imp.get("module", "") or ""
                    address = imp.get("address", "")
                    if not func_name or not module:
                        continue

                    # Канонический ключ модуля: без расширения, нижний регистр.
                    # Позволяет не считать KERNEL32.dll и kernel32.dll разными.
                    module_key = normalize_module_name(module)
                    if not module_key:
                        continue

                    # Всегда сохраняем импорт в file_imports (для перегенерации HTML)
                    conn.execute(
                        "INSERT OR REPLACE INTO file_imports "
                        "(json_path, file_name, func_name, module_name, address, file_size) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (json_path_str, file_name, func_name, module, address, file_size),
                    )

                    # Системность определяют словари выбранной платформы.
                    if not is_system_module(module, platform):
                        continue

                    category = get_module_category(module)

                    # Учёт системной библиотеки независимо от дедупликации
                    # функций: модуль должен попасть в счётчик, даже если все
                    # его функции совпали по имени с функциями других модулей.
                    conn.execute(
                        "INSERT OR IGNORE INTO system_modules "
                        "(module_key, module_name, category) VALUES (?, ?, ?)",
                        (module_key, module, category),
                    )

                    # Дедупликация функций: одна функция учитывается один раз.
                    if func_name in seen:
                        continue
                    seen.add(func_name)

                    conn.execute(
                        "INSERT OR IGNORE INTO system_functions "
                        "(func_name, module_name, module_key, category) VALUES (?, ?, ?, ?)",
                        (func_name, module, module_key, category),
                    )

                if progress_callback:
                    progress_callback(idx + 1, total)

            conn.commit()
        finally:
            conn.close()

        # Открываем read-only соединение для последующих запросов
        self.open_readonly()
        logger.info(
            "SfaFunctionIndex built: %d functions from %d files",
            self.total_functions,
            total,
        )

    def open_readonly(self) -> None:
        """Открывает read-only SQLite-соединение для уже существующей БД.

        Если БД создана старой версией (нет таблицы ``system_modules`` или
        колонки ``module_key``), схема сначала доводится до актуальной:
        миграция выполняется в отдельном writable-соединении, после чего
        БД открывается только для чтения.
        """
        if not self._db_path.exists():
            self._available = False
            return
        self._ensure_schema()
        try:
            conn = sqlite3.connect(f"file:{self._db_path.resolve()}?mode=ro", uri=True)
            conn.execute("PRAGMA query_only=1")
            self._conn = conn
            self._available = True
        except Exception as e:
            logger.warning("Cannot open function index: %s", e)
            self._available = False

    def _ensure_schema(self) -> None:
        """Приводит схему существующей БД к актуальной версии (если нужно)."""
        try:
            conn = sqlite3.connect(str(self._db_path))
        except Exception as e:
            logger.warning("Cannot open function index for migration: %s", e)
            return
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA_SQL)
            _migrate_schema(conn)
            conn.commit()
        except Exception as e:
            logger.warning("Schema migration failed: %s", e)
        finally:
            conn.close()

    # ─── Фаза запросов ──────────────────────────────────────────────

    def is_known(self, func_name: str) -> bool:
        """Проверяет, есть ли функция в индексе.

        Быстрый lookup по PRIMARY KEY (O(log N)). Потокобезопасен.
        Если индекс недоступен — возвращает True (пропускаем фильтр).
        """
        if not self._available or not self._conn:
            return True  # fallback: разрешаем
        try:
            cur = self._conn.execute(
                "SELECT 1 FROM system_functions WHERE func_name = ?",
                (func_name,),
            )
            return cur.fetchone() is not None
        except Exception:
            return True  # fallback

    def get_file_imports(self, json_path: str | Path) -> list[dict]:
        """Возвращает список импортов для указанного JSON-файла.

        Используется в reuse-режиме вместо повторного чтения JSON.
        """
        if not self._available or not self._conn:
            return []
        try:
            cur = self._conn.execute(
                "SELECT func_name, module_name, address, file_name "
                "FROM file_imports WHERE json_path = ? ORDER BY rowid",
                (str(json_path),),
            )
            rows = cur.fetchall()
            # Определяем file_name из первой записи (одинаков для всех)
            file_name = rows[0][3] if rows else ""
            imports = []
            for row in rows:
                imports.append({
                    "name": row[0],
                    "module": row[1],
                    "address": row[2] or "",
                })
            return imports
        except Exception:
            return []

    def get_file_name(self, json_path: str | Path) -> str:
        """Возвращает file_name для указанного JSON-файла."""
        if not self._available or not self._conn:
            return ""
        try:
            cur = self._conn.execute(
                "SELECT file_name FROM file_imports WHERE json_path = ? LIMIT 1",
                (str(json_path),),
            )
            row = cur.fetchone()
            return row[0] if row else ""
        except Exception:
            return ""

    def get_file_size(self, json_path: str | Path) -> int:
        """Возвращает размер исходного файла (или 0)."""
        if not self._available or not self._conn:
            return 0
        try:
            cur = self._conn.execute(
                "SELECT file_size FROM file_imports WHERE json_path = ? LIMIT 1",
                (str(json_path),),
            )
            row = cur.fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def get_all_json_paths(self) -> list[str]:
        """Возвращает все json_path из индекса."""
        if not self._available or not self._conn:
            return []
        try:
            cur = self._conn.execute(
                "SELECT DISTINCT json_path FROM file_imports ORDER BY json_path"
            )
            return [row[0] for row in cur.fetchall() if row[0]]
        except Exception:
            return []

    # ─── Свойства ───────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        return self._available

    @property
    def total_functions(self) -> int:
        if not self._available or not self._conn:
            return 0
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM system_functions")
            return cur.fetchone()[0]
        except Exception:
            return 0

    @property
    def total_modules(self) -> int:
        """Количество уникальных системных библиотек в индексе.

        Уникальность определяется каноническим ключом модуля
        (``normalize_module_name``), поэтому ``KERNEL32.dll`` и
        ``kernel32.dll`` считаются одной библиотекой.

        Для БД, созданных старой версией (без таблицы ``system_modules``),
        используется резервный подсчёт по ``system_functions``.
        """
        if not self._available or not self._conn:
            return 0
        for query in (
            "SELECT COUNT(*) FROM system_modules",
            "SELECT COUNT(DISTINCT module_key) FROM system_functions WHERE module_key <> ''",
            "SELECT COUNT(DISTINCT module_name) FROM system_functions",
        ):
            try:
                return self._conn.execute(query).fetchone()[0]
            except Exception:
                continue
        return 0

    @property
    def platform(self) -> str:
        """Платформа, для которой построен индекс.

        Читается из таблицы ``meta``; для старых БД возвращается Windows
        (индекс исторически собирался только по словарю Windows).
        """
        if not self._available or not self._conn:
            return _DEFAULT_PLATFORM
        try:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'platform'"
            ).fetchone()
            return normalize_platform(row[0]) if row and row[0] else _DEFAULT_PLATFORM
        except Exception:
            return _DEFAULT_PLATFORM

    def close(self) -> None:
        """Закрывает соединение с БД."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            self._available = False

    def __del__(self):
        self.close()