"""Фоновый поток для выполнения пакетного анализа и последующего JSON-экспорта."""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import List, Optional, Dict

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ida.runner import IDAAnalyzer
from ida_batch_tool.ui.constants import SCRIPTS_DIR


class AnalysisWorker(QThread):
    # Сигналы для фазы анализа
    analysis_progress = Signal(str, int, int)
    analysis_file_started = Signal(str)
    analysis_file_completed = Signal(str, bool)

    # Сигналы для фазы экспорта
    export_progress = Signal(str, int, int)
    export_file_started = Signal(str)
    export_file_completed = Signal(str, bool)

    # Общие сигналы
    phase_changed = Signal(str)                 # "analysis" или "export"
    finished = Signal(int, int)                 # успешно обработано, всего
    error_occurred = Signal(str)

    def __init__(self, files: List[Path], idat_path: str, max_workers: int,
                 output_dir: Optional[Path] = None, cleanup: bool = True,
                 temp_cleanup: bool = True, pseudocode: bool = False,
                 delete_json: bool = True, export_only: bool = False, parent=None):
        super().__init__(parent)
        self.files = files
        self.idat_path = idat_path
        self.max_workers = max_workers
        self.output_dir = output_dir
        self.cleanup = cleanup
        self.temp_cleanup = temp_cleanup
        self.pseudocode = pseudocode
        self.delete_json = delete_json
        self.export_only = export_only
        self._cancel_event = threading.Event()

    def run(self):
        succeeded_files = []
        if not self.export_only:
            # Фаза 1: анализ файлов
            self.phase_changed.emit("analysis")
            analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
            analyzer.set_progress_callback(self._on_analysis_progress)
            analyzer.set_file_start_callback(self._on_analysis_start)
            analyzer.set_file_done_callback(self._on_analysis_done)

            root_logger = logging.getLogger()
            handler = None
            analysis_results: Dict[Path, bool] = {}
            try:
                handler = logging.Handler()
                handler.emit = lambda record: self.error_occurred.emit(handler.format(record))
                handler.setLevel(logging.ERROR)
                handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
                root_logger.addHandler(handler)

                analysis_results = analyzer.analyze_batch(
                    self.files,
                    output_dir=self.output_dir,
                    cleanup_temp=self.cleanup,
                    temp_cleanup=self.temp_cleanup,
                    cancel_event=self._cancel_event
                )
            except Exception as e:
                self.error_occurred.emit(f"Критическая ошибка при анализе: {e}")
                analysis_results = {f: False for f in self.files}
            finally:
                if handler:
                    root_logger.removeHandler(handler)

            succeeded_files = [f for f, ok in analysis_results.items() if ok]
        else:
            self.phase_changed.emit("export")
            idb_files = []
            for f in self.files:
                out_dir = self.output_dir or f.parent
                i64_path = out_dir / (f.name + ".i64")
                if i64_path.exists():
                    idb_files.append(i64_path)
                else:
                    idb_path = out_dir / (f.name + ".idb")
                    if idb_path.exists():
                        idb_files.append(idb_path)
                    else:
                        self.error_occurred.emit(f"База данных не найдена для {f.name} (режим export_only).")
            if not idb_files:
                self.finished.emit(0, len(self.files))
                return
            succeeded_files = idb_files

        # Фаза 2: экспорт в JSON
        if succeeded_files and not self._cancel_event.is_set():
            self.phase_changed.emit("export")
            script_path = SCRIPTS_DIR / "export_data.py"
            if not script_path.exists():
                self.error_occurred.emit(f"Скрипт экспорта не найден: {script_path}")
                self.finished.emit(0, len(self.files) if not self.export_only else len(self.files))
                return

            script_args = {}
            if self.pseudocode:
                script_args["pseudocode"] = "1"
            if self.output_dir:
                script_args["inputdir"] = str(self.output_dir)

            analyzer = IDAAnalyzer(idat_path=self.idat_path, max_workers=self.max_workers)
            analyzer.set_progress_callback(self._on_export_progress)
            analyzer.set_file_start_callback(self._on_export_start)
            analyzer.set_file_done_callback(self._on_export_done)

            export_results = analyzer.run_script_on_batch(
                succeeded_files, script_path, script_args=script_args,
                cancel_event=self._cancel_event
            )
            for idb, ok in export_results.items():
                if not ok:
                    self.error_occurred.emit(f"Ошибка экспорта для {idb.name}")
        else:
            if not self.export_only:
                self.error_occurred.emit("Нет успешно проанализированных файлов для экспорта.")
            else:
                self.error_occurred.emit("Нет доступных баз данных для экспорта.")

        # Вычисляем количество успешно обработанных исходных файлов
        if not self.export_only:
            success_original_count = 0
            for f in self.files:
                out_dir = self.output_dir or f.parent
                if (out_dir / (f.name + ".i64")).exists():
                    success_original_count += 1
        else:
            success_original_count = 0
            for f in self.files:
                out_dir = self.output_dir or f.parent
                if (out_dir / (f.name + ".i64")).exists():
                    success_original_count += 1

        self.finished.emit(success_original_count, len(self.files))

    # --- Обработчики для фазы анализа ---
    def _on_analysis_progress(self, filename: str, current: int, total: int):
        if not self._cancel_event.is_set():
            self.analysis_progress.emit(filename, current, total)

    def _on_analysis_start(self, filename: str):
        if not self._cancel_event.is_set():
            self.analysis_file_started.emit(filename)

    def _on_analysis_done(self, filename: str, success: bool):
        if not self._cancel_event.is_set():
            self.analysis_file_completed.emit(filename, success)

    # --- Обработчики для фазы экспорта ---
    def _on_export_progress(self, filename: str, current: int, total: int):
        if not self._cancel_event.is_set():
            self.export_progress.emit(filename, current, total)

    def _on_export_start(self, filename: str):
        if not self._cancel_event.is_set():
            self.export_file_started.emit(filename)

    def _on_export_done(self, filename: str, success: bool):
        if not self._cancel_event.is_set():
            self.export_file_completed.emit(filename, success)

    def cancel(self):
        """Установить флаг отмены и запросить остановку."""
        self._cancel_event.set()