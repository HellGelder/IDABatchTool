"""Индекс системных Win32 функций: предварительный проход по JSON-файлам.

Строит SQLite-БД уникальных функций, относящихся к системным DLL
по классификатору WINDOWS_MODULES. Используется для отсева неподходящих
функций перед вызовом npx @microsoft/learn-cli search.
"""
from __future__ import annotations

import json
import sqlite3
import logging
from pathlib import Path
from typing import List, Callable, Optional

from ida_batch_tool.classifier.windows import WINDOWS_MODULES as _WINDOWS_MODULES
from ida_batch_tool.reporting.utils import normalize_display_name

logger = logging.getLogger(__name__)

# Нормализованный набор системных DLL (нижний регистр, без .dll)
_WIN32_SYSTEM_MODULES_NORMALIZED: set[str] = {
    dll.replace(".dll", "").lower()
    for dll in _WINDOWS_MODULES
}

# Маппинг внутренних имён переменных модуля windows.py → категории
_CATEGORY_NAMES = {
    "_WINDOWS_HAL": "HAL",
    "_WINDOWS_NATIVE_API": "Native API",
    "_WINDOWS_KERNEL_SUBSYSTEM": "Kernel subsystem",
    "_WINDOWS_USER_SUBSYSTEM": "User subsystem",
    "_WINDOWS_SECURITY_CRYPTO": "Security/Crypto",
    "_WINDOWS_NETWORK": "Network",
    "_WINDOWS_GRAPHICS": "Graphics",
    "_WINDOWS_MULTIMEDIA": "Multimedia",
    "_WINDOWS_RUNTIME": "Runtime libraries",
    "_WINDOWS_DOTNET": ".NET",
    "_WINDOWS_SYSTEM_SERVICES": "System services",
    "_WINDOWS_USB_DEVICE": "USB/HID",
    "_WINDOWS_API_SETS": "API Sets",
    "_WINDOWS_REMOTE": "Remote/Virtualization",
    "_WINDOWS_DATA_SERVICES": "ODBC/ADSI",
}

# Reverse-map: dll_name(lower, no-ext) → category (заполняется лениво)
_DLL_CATEGORY_MAP: dict[str, str] = {}


def _build_dll_category_map() -> dict[str, str]:
    """Строит reverse-map: dll_name(lower,no-ext) → category_name.

    Пробегает по внутренним словарям модуля windows.py, чтобы определить
    категорию каждой DLL. Результат кэшируется.
    """
    if _DLL_CATEGORY_MAP:
        return _DLL_CATEGORY_MAP

    import ida_batch_tool.classifier.windows as _win_mod

    for var_name, category in _CATEGORY_NAMES.items():
        dll_dict = getattr(_win_mod, var_name, {})
        if not isinstance(dll_dict, dict):
            continue
        for dll_name in dll_dict:
            key = dll_name.replace(".dll", "").lower()
            _DLL_CATEGORY_MAP[key] = category

    return _DLL_CATEGORY_MAP


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS system_functions (
    func_name TEXT PRIMARY KEY,
    module_name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS file_imports (
    json_path TEXT NOT NULL,
    file_name TEXT NOT NULL DEFAULT '',
    func_name TEXT NOT NULL,
    module_name TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (json_path, func_name)
);
CREATE INDEX IF NOT EXISTS idx_fi_jp ON file_imports(json_path);
"""


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
    ) -> "SfaFunctionIndex":
        """Сканирует JSON-файлы, собирает уникальные системные функции.

        Для каждого JSON читает ``imports[].module`` и ``imports[].name``.
        Если module относится к системной DLL (по ``WINDOWS_MODULES``),
        пара (name, module) сохраняется в SQLite-индекс.

        Args:
            json_files: список путей к .export.json.
            db_path: путь к файлу SQLite БД (будет создан).
            progress_callback: (current, total) после каждого файла.

        Returns:
            Экземпляр SfaFunctionIndex с заполненной БД.
        """
        instance = cls(db_path)
        instance._build(json_files, progress_callback)
        return instance

    def _build(
        self,
        json_files: List[Path],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Внутренний метод сборки индекса."""
        total = len(json_files)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self._db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA_SQL)

            category_map = _build_dll_category_map()

            # Множество для дедупликации: (func_name, module_name_lower)
            seen: set[tuple[str, str]] = set()

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

                    # Нормализуем имя модуля
                    mod_clean = normalize_display_name(module).lower()
                    mod_stem = Path(mod_clean).stem

                    # Проверяем по набору системных DLL — только для system_functions
                    is_system = mod_stem in _WIN32_SYSTEM_MODULES_NORMALIZED

                    # Всегда сохраняем импорт в file_imports (для перегенерации HTML)
                    conn.execute(
                        "INSERT OR REPLACE INTO file_imports "
                        "(json_path, file_name, func_name, module_name, address) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (json_path_str, file_name, func_name, module, address),
                    )

                    # В system_functions — только системные
                    if not is_system:
                        continue

                    # Дедупликация
                    key = (func_name, mod_stem)
                    if key in seen:
                        continue
                    seen.add(key)

                    # Определяем категорию DLL
                    category = category_map.get(mod_stem, "")

                    conn.execute(
                        "INSERT OR IGNORE INTO system_functions "
                        "(func_name, module_name, category) VALUES (?, ?, ?)",
                        (func_name, module, category),
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
        """Открывает read-only SQLite-соединение для уже существующей БД."""
        if not self._db_path.exists():
            self._available = False
            return
        try:
            conn = sqlite3.connect(f"file:{self._db_path.resolve()}?mode=ro", uri=True)
            conn.execute("PRAGMA query_only=1")
            self._conn = conn
            self._available = True
        except Exception as e:
            logger.warning("Cannot open function index: %s", e)
            self._available = False

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
        """Количество уникальных системных DLL в индексе."""
        if not self._available or not self._conn:
            return 0
        try:
            cur = self._conn.execute(
                "SELECT COUNT(DISTINCT module_name) FROM system_functions"
            )
            return cur.fetchone()[0]
        except Exception:
            return 0

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