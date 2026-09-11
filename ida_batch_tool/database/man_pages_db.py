"""Офлайн-база документации man-pages для платформы Linux.

Модуль скачивает официальный архив man-pages (kernel.org), разбирает
roff-страницы и складывает результат в SQLite. Дальше поиск документации
при генерации отчётов СФ идёт полностью офлайн — без обращений к сети.

Схема хранения разделяет страницы и имена функций: одна страница
(например ``printf.3``) описывает сразу семейство функций
(``printf``, ``fprintf``, ``sprintf``, ...), поэтому текст хранится один
раз, а таблица ``function_index`` лишь сопоставляет имя функции странице.
"""
from __future__ import annotations

import io
import logging
import re
import sqlite3
import tarfile
from pathlib import Path
from typing import Callable, Iterable, Optional

from ida_batch_tool.database.man_roff import find_alias_target, parse_man_page

logger = logging.getLogger(__name__)

# Источник: официальный архив man-pages проекта Linux.
# https://www.kernel.org/pub/linux/docs/man-pages/
MANPAGES_BASE_URL = "https://mirrors.edge.kernel.org/pub/linux/docs/man-pages"
MANPAGES_VERSION = "6.9"
MANPAGES_ARCHIVE_URL = f"{MANPAGES_BASE_URL}/man-pages-{MANPAGES_VERSION}.tar.xz"

# Секции, которые импортируются: 2 (системные вызовы) и 3 (библиотечные функции).
_SECTION_RE = re.compile(r"/man/man([23])/(.+)\.([23][a-z]*)$")

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pages (
    page_name TEXT PRIMARY KEY,
    section TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    library TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    markdown TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS function_index (
    func_name TEXT PRIMARY KEY,
    page_name TEXT NOT NULL,
    section TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_fi_page ON function_index(page_name);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
"""


class ManPagesDatabase:
    """SQLite-хранилище документации man-pages с офлайн-поиском."""

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._available = False

    # ─── жизненный цикл ─────────────────────────────────────────────

    def open(self) -> bool:
        """Открывает существующую БД. Возвращает True, если она пригодна."""
        if not self._db_path.exists():
            self._available = False
            return False
        try:
            conn = sqlite3.connect(str(self._db_path))
            conn.execute("PRAGMA query_only=1")
            self._conn = conn
            self._available = self.count() > 0
        except Exception as e:
            logger.warning("Cannot open man-pages DB: %s", e)
            self._available = False
        return self._available

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            self._available = False

    def __del__(self):
        self.close()

    # ─── импорт ─────────────────────────────────────────────────────

    @classmethod
    def import_archive(
        cls,
        db_path: str | Path,
        archive_bytes: bytes,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        arch_or_version: str = MANPAGES_VERSION,
    ) -> "ManPagesDatabase":
        """Импортирует архив man-pages (``.tar.xz``) в новую БД.

        Args:
            db_path: путь к создаваемой БД.
            archive_bytes: содержимое архива.
            progress_callback: ``(current, total, message)``.
            arch_or_version: версия архива (для метаданных).

        Returns:
            Открытый экземпляр ``ManPagesDatabase``.
        """
        instance = cls(db_path)
        instance._db_path.parent.mkdir(parents=True, exist_ok=True)

        buf = io.BytesIO(archive_bytes)
        conn = sqlite3.connect(str(instance._db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA_SQL)
            # Пересборка «с нуля»: старая документация может быть от другой версии.
            conn.execute("DELETE FROM pages")
            conn.execute("DELETE FROM function_index")

            with tarfile.open(fileobj=buf, mode="r:xz") as tar:
                members = [
                    m for m in tar.getmembers()
                    if m.isfile() and _SECTION_RE.search(m.name)
                ]
                total = len(members)
                # Сначала разбираем реальные страницы, затем раскрываем алиасы.
                aliases: list[tuple[str, str, str]] = []
                parsed = 0
                for idx, member in enumerate(members):
                    m = _SECTION_RE.search(member.name)
                    section = m.group(1)
                    base = m.group(2)
                    file = tar.extractfile(member)
                    if file is None:
                        continue
                    source = file.read().decode("utf-8", "replace")

                    target = find_alias_target(source)
                    if target:
                        # ``.so man3/printf.3`` — запомним, раскроем после.
                        target_name = Path(target).name
                        target_base = target_name.rsplit(".", 1)[0]
                        aliases.append((base, target_base, section))
                        continue

                    page = parse_man_page(source, base, section)
                    cls._store_page(conn, page)
                    parsed += 1

                    if progress_callback and (idx % 50 == 0 or idx == total - 1):
                        progress_callback(idx + 1, total, f"Разобрано страниц: {parsed}")

                # Раскрываем алиасы: имя функции -> целевая страница.
                resolved = 0
                for alias_name, target_base, _section in aliases:
                    row = conn.execute(
                        "SELECT page_name, section, title, library, summary "
                        "FROM pages WHERE page_name = ?",
                        (target_base,),
                    ).fetchone()
                    if row is None:
                        continue
                    for func in cls._names_from_title(row[2]):
                        conn.execute(
                            "INSERT OR REPLACE INTO function_index "
                            "(func_name, page_name, section) VALUES (?, ?, ?)",
                            (func, row[0], row[1]),
                        )
                        resolved += 1
                    # Само имя алиаса тоже должно находиться.
                    for func in cls._names_from_title(alias_name):
                        conn.execute(
                            "INSERT OR REPLACE INTO function_index "
                            "(func_name, page_name, section) VALUES (?, ?, ?)",
                            (func, row[0], row[1]),
                        )

                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('manpages_version', ?)",
                    (arch_or_version,),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('alias_count', ?)",
                    (str(resolved),),
                )
            conn.commit()
        finally:
            conn.close()

        instance.open()
        logger.info(
            "man-pages imported: %d functions (%s)",
            instance.count(), arch_or_version,
        )
        return instance

    @classmethod
    def _store_page(cls, conn: sqlite3.Connection, page) -> None:
        """Сохраняет страницу и регистрирует все её имена функций."""
        conn.execute(
            "INSERT OR REPLACE INTO pages "
            "(page_name, section, title, library, summary, markdown) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (page.name, page.section, page.title, page.library,
             page.summary, page.markdown),
        )
        for func in page.aliases:
            conn.execute(
                "INSERT OR REPLACE INTO function_index "
                "(func_name, page_name, section) VALUES (?, ?, ?)",
                (func, page.name, page.section),
            )

    @staticmethod
    def _names_from_title(title: str) -> Iterable[str]:
        """Извлекает имена функций из строки NAME (``printf, fprintf - ...``)."""
        if not title:
            return ()
        head = re.split(r"\s+-\s+", title, maxsplit=1)[0]
        return [n.strip() for n in head.split(",") if n.strip()]

    # ─── поиск ──────────────────────────────────────────────────────

    def available(self) -> bool:
        return self._available

    def count(self) -> int:
        """Количество имён функций в индексе."""
        if not self._conn:
            return 0
        try:
            return self._conn.execute(
                "SELECT COUNT(*) FROM function_index"
            ).fetchone()[0]
        except Exception:
            return 0

    def has_function(self, func_name: str) -> bool:
        """Есть ли документация для функции (с учётом алиасов)."""
        if not self._available or not self._conn:
            return False
        for candidate in self._candidates(func_name):
            try:
                row = self._conn.execute(
                    "SELECT 1 FROM function_index WHERE func_name = ?",
                    (candidate,),
                ).fetchone()
            except Exception:
                return False
            if row:
                return True
        return False

    def get_page(self, func_name: str) -> Optional[dict]:
        """Возвращает документацию функции в формате ``search_results``.

        Возвращаемый словарь совместим с форматом MS Learn-провайдера:
        ``title``, ``url``, ``markdown``, ``markdown_html``.
        """
        if not self._available or not self._conn:
            return None
        for candidate in self._candidates(func_name):
            try:
                row = self._conn.execute(
                    "SELECT p.page_name, p.section, p.title, p.library, p.markdown "
                    "FROM function_index f JOIN pages p ON p.page_name = f.page_name "
                    "WHERE f.func_name = ?",
                    (candidate,),
                ).fetchone()
            except Exception:
                return None
            if row:
                page_name, section, title, library, markdown = row
                url = f"https://man7.org/linux/man-pages/man{section}/{page_name}.{section}.html"
                header = f"**{title}** — man {section}" if title else f"man {section}"
                body = f"{header}\n\n{markdown}" if markdown else header
                return {
                    "title": f"{page_name}({section})",
                    "url": url,
                    "markdown": body,
                    "markdown_html": "",
                }
        return None

    @staticmethod
    def _candidates(func_name: str) -> tuple[str, ...]:
        """Варианты имени функции для поиска.

        Импорты из ELF обычно чистые (``printf``), но встречаются
        версионированные (``pthread_create@GLIBC_2.34``) и с суффиксами
        (``__libc_start_main``). Отбрасываем версию и ведущие подчёркивания.
        """
        if not func_name:
            return ()
        name = func_name.strip()
        # Версия символа: pthread_create@GLIBC_2.34 -> pthread_create
        name = name.split("@", 1)[0]
        candidates = [name]
        stripped = name.lstrip("_")
        if stripped and stripped != name:
            candidates.append(stripped)
        return tuple(dict.fromkeys(candidates))

    def version(self) -> str:
        """Версия импортированного архива man-pages."""
        if not self._conn:
            return ""
        try:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'manpages_version'"
            ).fetchone()
            return row[0] if row else ""
        except Exception:
            return ""
