"""Воркер генерации сводного отчёта."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.reporting.generator import ReportGenerator


class IndexWorker(QThread):
    finished = Signal(bool)
    error_occurred = Signal(str)

    def __init__(self, generator: ReportGenerator, reports_dir: Path,
                 input_dir: Path, report_links: List[dict],
                 sorted_modules: List[str], ida_info: Optional[dict],
                 elf_sections: List[str] = None, parent=None):
        super().__init__(parent)
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.report_links = report_links
        self.sorted_modules = sorted_modules
        self.ida_info = ida_info
        self.elf_sections = elf_sections or []

    def run(self):
        try:
            self.generator.generate_index(
                self.reports_dir,
                self.input_dir,
                self.report_links,
                self.sorted_modules,
                self.ida_info,
                self.elf_sections
            )
            self.finished.emit(True)
        except Exception as e:
            self.error_occurred.emit(str(e))
            self.finished.emit(False)