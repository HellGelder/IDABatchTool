"""Воркер экспорта JSON."""
from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ida.runner import IDAAnalyzer


class ExportWorker(QThread):
    progress_updated = Signal(str, int, int)
    finished = Signal(int, int)
    error_occurred = Signal(str)

    def __init__(self, idb_files: List[Path], script_path: Path,
                 idat_path: str, max_workers: int,
                 script_args: Optional[Dict[str, str]] = None,
                 parent=None):
        super().__init__(parent)
        self.idb_files = idb_files
        self.script_path = script_path
        self.idat_path = idat_path
        self.max_workers = max_workers
        self.script_args = script_args or {}
        self.results: Dict[Path, bool] = {}
        self._cancel = False

    def run(self):
        analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
        analyzer.set_progress_callback(self._on_progress)
        try:
            self.results = analyzer.run_script_on_batch(
                self.idb_files, self.script_path,
                script_args=self.script_args
            )
            succeeded = sum(1 for v in self.results.values() if v)
            self.finished.emit(succeeded, len(self.results))
        except Exception as e:
            self.error_occurred.emit(str(e))
            self.finished.emit(0, len(self.idb_files))

    def _on_progress(self, filename: str, current: int, total: int):
        if not self._cancel:
            self.progress_updated.emit(filename, current, total)

    def cancel(self):
        self._cancel = True