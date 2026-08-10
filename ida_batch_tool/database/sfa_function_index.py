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
            conn.execute(_SCHEMA_SQL)

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

                imports = data.get("imports", [])
                for imp in imports:
                    func_name = imp.get("name", "")
                    module = imp.get("module", "") or ""
                    if not func_name or not module:
                        continue

                    # Нормализуем имя модуля
                    mod_clean = normalize_display_name(module).lower()
                    mod_stem = Path(mod_clean).stem

                    # Проверяем по набору системных DLL
                    if mod_stem not in _WIN32_SYSTEM_MODULES_NORMALIZED:
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
        self._open_readonly()
        logger.info(
            "SfaFunctionIndex built: %d functions from %d files",
            self.total_functions,
            total,
        )

    def _open_readonly(self) -> None:
        """Открывает read-only SQLite-соединение."""
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