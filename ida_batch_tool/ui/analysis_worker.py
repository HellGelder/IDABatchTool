"""Фоновый поток для выполнения пакетного анализа."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ida.runner import IDAAnalyzer


class AnalysisWorker(QThread):
    progress_updated = Signal(str, int, int)
    file_started = Signal(str)
    file_completed = Signal(str, bool)
    analysis_finished = Signal(int, int)
    error_occurred = Signal(str)

    def __init__(self, files: List[Path], idat_path: str, max_workers: int,
                 output_dir: Optional[Path] = None, cleanup: bool = True,
                 temp_cleanup: bool = True, verbose: bool = False, parent=None):
        super().__init__(parent)
        self.files = files
        self.idat_path = idat_path
        self.max_workers = max_workers
        self.output_dir = output_dir
        self.cleanup = cleanup
        self.temp_cleanup = temp_cleanup
        self.verbose = verbose
        self._cancel = False

    def run(self):
        analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
        analyzer.set_progress_callback(self._on_progress)
        analyzer.set_file_start_callback(self._on_file_start)
        analyzer.set_file_done_callback(self._on_file_done)

        root_logger = logging.getLogger()
        handler = None
        try:
            handler = logging.Handler()
            handler.emit = lambda record: self.error_occurred.emit(handler.format(record))
            handler.setLevel(logging.ERROR)
            handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            if self.verbose:
                root_logger.setLevel(logging.DEBUG)
            root_logger.addHandler(handler)

            results = analyzer.analyze_batch(
                self.files,
                output_dir=self.output_dir,
                cleanup_temp=self.cleanup,
                temp_cleanup=self.temp_cleanup
            )
        except Exception as e:
            self.error_occurred.emit(f"Критическая ошибка: {e}")
            results = {f: False for f in self.files}
        finally:
            if handler:
                root_logger.removeHandler(handler)

        succeeded = sum(1 for v in results.values() if v)
        total = len(results)
        self.analysis_finished.emit(succeeded, total)

    def _on_progress(self, filename: str, current: int, total: int):
        if not self._cancel:
            self.progress_updated.emit(filename, current, total)

    def _on_file_start(self, filename: str):
        if not self._cancel:
            self.file_started.emit(filename)

    def _on_file_done(self, filename: str, success: bool):
        if not self._cancel:
            self.file_completed.emit(filename, success)

    def cancel(self):
        self._cancel = True