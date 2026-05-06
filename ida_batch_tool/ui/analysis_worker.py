"""Фоновый поток для выполнения пакетного анализа."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ida.runner import IDAAnalyzer


class AnalysisWorker(QThread):
    progress_updated = Signal(str, int, int)      # текущий файл, номер, всего
    file_started = Signal(str)                     # имя файла, анализ начат
    file_completed = Signal(str, bool)            # имя файла, успех/ошибка
    analysis_finished = Signal(int, int)           # успешно, всего
    error_occurred = Signal(str)                   # сообщение только об ошибках

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
        self._started_files: set = set()

    def run(self):
        analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
        analyzer.set_progress_callback(self._on_progress)

        root_logger = logging.getLogger()
        old_handlers = root_logger.handlers[:]

        class SignalHandler(logging.Handler):
            def __init__(self, signal):
                super().__init__()
                self.signal = signal

            def emit(self, record):
                msg = self.format(record)
                self.signal.emit(msg)

        handler = SignalHandler(self.error_occurred)
        handler.setLevel(logging.ERROR)
        handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        if self.verbose:
            root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(handler)

        try:
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
            root_logger.removeHandler(handler)
            root_logger.handlers = old_handlers

        succeeded = sum(1 for v in results.values() if v)
        total = len(results)

        for f, success in results.items():
            self.file_completed.emit(f.name, success)

        self.analysis_finished.emit(succeeded, total)

    def _on_progress(self, filename: str, current: int, total: int):
        if not self._cancel:
            self.progress_updated.emit(filename, current, total)
            if filename not in self._started_files:
                self._started_files.add(filename)
                self.file_started.emit(filename)

    def cancel(self):
        self._cancel = True