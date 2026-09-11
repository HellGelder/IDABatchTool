"""Фоновая синхронизация документации man-pages.

Скачивает официальный архив man-pages и импортирует его в SQLite.
Запускается из настроек по образцу синхронизации win32-сигнатур:
работает в отдельном потоке и отдаёт прогресс в UI.
"""
from __future__ import annotations

import logging
from pathlib import Path

import requests
from PySide6.QtCore import QThread, Signal

from ida_batch_tool.database.man_pages_db import (
    MANPAGES_ARCHIVE_URL,
    MANPAGES_VERSION,
    ManPagesDatabase,
)

logger = logging.getLogger(__name__)

# Документация man-pages одна на весь проект (не зависит от входной папки).
MANPAGES_DB_FILENAME = "manpages.db"


def get_manpages_db_path(reports_root: Path) -> Path:
    """Путь к БД man-pages в корне отчётов."""
    return Path(reports_root) / MANPAGES_DB_FILENAME


class ManPagesSyncWorker(QThread):
    """Скачивает и импортирует man-pages в фоновом потоке."""

    progress = Signal(str, int)
    finished = Signal(bool, str)
    error = Signal(str)

    def __init__(self, db_path: str | Path, archive_url: str = MANPAGES_ARCHIVE_URL):
        super().__init__()
        self.db_path = Path(db_path)
        self.archive_url = archive_url
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            self.progress.emit(f"Загрузка man-pages {MANPAGES_VERSION}…", 5)
            response = requests.get(self.archive_url, timeout=180)
            response.raise_for_status()
            payload = response.content

            if self._cancel:
                self.finished.emit(False, "Отменено пользователем")
                return

            size_mb = len(payload) / (1024 * 1024)
            self.progress.emit(f"Архив получен ({size_mb:.1f} МБ). Разбор…", 30)

            def on_progress(current: int, total: int, message: str) -> None:
                if self._cancel:
                    return
                pct = 30 + int(60 * current / max(total, 1))
                self.progress.emit(message, min(pct, 95))

            ManPagesDatabase.import_archive(
                self.db_path, payload,
                progress_callback=on_progress,
                arch_or_version=MANPAGES_VERSION,
            )

            db = ManPagesDatabase(self.db_path)
            count = db.count() if db.open() else 0
            db.close()

            self.progress.emit(f"Импортировано функций: {count}", 100)
            self.finished.emit(True, str(self.db_path))

        except requests.RequestException as e:
            logger.exception("Ошибка загрузки man-pages")
            self.error.emit(f"Не удалось скачать архив man-pages: {e}")
            self.finished.emit(False, str(e))
        except Exception as e:
            logger.exception("Ошибка импорта man-pages")
            self.error.emit(f"Ошибка импорта man-pages: {e}")
            self.finished.emit(False, str(e))
