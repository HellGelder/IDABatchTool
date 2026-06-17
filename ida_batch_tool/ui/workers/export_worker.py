"""Фоновый поток для экспорта JSON из существующих .i64 баз (без предварительного анализа)."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ida.runner import IDAAnalyzer

logger = logging.getLogger(__name__)


class ExportWorker(QThread):
    """Выполняет run_script_on_batch в фоновом потоке, чтобы не блокировать GUI."""

    progress = Signal(str, int, int)
    file_started = Signal(str)
    file_completed = Signal(str, bool)
    finished = Signal(dict)  # Dict[Path, bool]
    error_occurred = Signal(str)

    def __init__(self, idb_files: list, idat_path: str, script_path: Path,
                 max_workers: int = 4, script_args: Optional[Dict[str, str]] = None,
                 parent=None):
        super().__init__(parent)
        self.idb_files = idb_files
        self.idat_path = idat_path
        self.script_path = script_path
        self.max_workers = max_workers
        self.script_args = script_args

    def run(self) -> None:
        analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
        analyzer.set_progress_callback(self._on_progress)
        analyzer.set_file_start_callback(self._on_start)
        analyzer.set_file_done_callback(self._on_done)

        try:
            results = analyzer.run_script_on_batch(
                self.idb_files, self.script_path,
                script_args=self.script_args, cancel_event=None
            )
            self.finished.emit(results)
        except Exception as e:
            logger.exception("Ошибка экспорта в воркере")
            self.error_occurred.emit(str(e))
            self.finished.emit({f: False for f in self.idb_files})

    def _on_progress(self, filename: str, current: int, total: int) -> None:
        self.progress.emit(filename, current, total)

    def _on_start(self, filename: str) -> None:
        self.file_started.emit(filename)

    def _on_done(self, filename: str, success: bool) -> None:
        self.file_completed.emit(filename, success)
