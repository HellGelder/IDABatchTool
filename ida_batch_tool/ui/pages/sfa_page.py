# ida_batch_tool/ui/pages/sfa_page.py
"""Страница «Анализ СФ» (системных функций)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional
from collections import Counter

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QProgressBar,
    QTextEdit, QGroupBox, QFileDialog, QLineEdit, QSlider, QRadioButton,
    QButtonGroup, QGridLayout, QCheckBox, QMessageBox, QApplication
)
from PySide6.QtCore import Qt

from ida_batch_tool.config.loader import load_config, get_ida_executable, get_default_inputdir, get_sf_db_path
from ida_batch_tool.discovery.finder import find_executables
from ida_batch_tool.ui.constants import AnalysisStatus, PLATFORM_EXTENSIONS, SCRIPTS_DIR
from ida_batch_tool.ui.workers.analysis_worker import AnalysisWorker
from ida_batch_tool.ui.workers.sfa_html_generation import SfaHtmlGeneratorWorker
from ida_batch_tool.archive_handler import extract_archive, ARCHIVE_EXTENSIONS, find_7z
from ida_batch_tool.ida.runner import IDAAnalyzer
from ida_batch_tool.database.win32_sync import Win32DatabaseSync

import logging
logger = logging.getLogger(__name__)


class SfaPage(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.analysis_in_progress = False
        self.html_in_progress = False
        self.worker: Optional[AnalysisWorker] = None
        self.html_worker: Optional[SfaHtmlGeneratorWorker] = None
        self._cached_files: List[Path] = []
        self._export_all_after_analysis = False
        self._build_ui()
        self._connect_signals()
        self._refresh_file_list()

    def is_analysis_running(self) -> bool:
        return self.analysis_in_progress or self.html_in_progress

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Источник файлов
        source_grp = QGroupBox("Источник файлов")
        src_layout = QVBoxLayout(source_grp)
        dir_row = QHBoxLayout()
        self.inputdir_edit = QLineEdit()
        self.inputdir_edit.setPlaceholderText(
            "Путь к папке с бинарными файлами или к архиву (.apk, .ipa, .dmg)..."
        )
        self.browse_dir_btn = QPushButton("Обзор...")
        dir_row.addWidget(self.inputdir_edit, 1)
        dir_row.addWidget(self.browse_dir_btn)
        src_layout.addLayout(dir_row)
        layout.addWidget(source_grp)

        # Treemap
        from ida_batch_tool.ui.widgets.treemap import TreemapWidget
        treemap_grp = QGroupBox("Графическое отображение директории")
        treemap_layout = QVBoxLayout(treemap_grp)
        self.treemap = TreemapWidget()
        self.treemap.setMinimumHeight(40)
        treemap_layout.addWidget(self.treemap)
        layout.addWidget(treemap_grp)

        # Параметры сканирования
        scan_grp = QGroupBox("Параметры сканирования")
        scan_layout = QHBoxLayout(scan_grp)
        left_col = QVBoxLayout()
        right_col = QVBoxLayout()

        # Платформа
        platform_grp = QGroupBox("Целевая платформа")
        plat_layout = QVBoxLayout(platform_grp)
        self.platform_buttons = QButtonGroup(self)
        self.platform_buttons.setExclusive(True)
        self.radio_to_platform: dict[QRadioButton, str] = {}
        grid = QGridLayout()
        row, col = 0, 0
        for key, info in PLATFORM_EXTENSIONS.items():
            radio = QRadioButton(info["label"])
            self.platform_buttons.addButton(radio)
            self.radio_to_platform[radio] = key
            ext_list = ", ".join(info["exts"])
            help_btn = self._create_help_button(
                f"Платформа: {info['label']}\nАнализируемые расширения: {ext_list}"
            )
            item_layout = QHBoxLayout()
            item_layout.setContentsMargins(0, 0, 0, 0)
            item_layout.addWidget(radio)
            item_layout.addWidget(help_btn)
            item_layout.addStretch()
            grid.addLayout(item_layout, row, col)
            col += 1
            if col == 2:
                col = 0
                row += 1
        plat_layout.addLayout(grid)
        left_col.addWidget(platform_grp)

        # Потоки IDA
        self.max_ida_slider_container, self.max_ida_slider, _ = self._create_slider_with_label(4)
        slider_row = QHBoxLayout()
        slider_row.addWidget(QLabel("Потоков IDA:"))
        slider_row.addWidget(self.max_ida_slider_container)
        slider_row.addWidget(self._create_help_button(
            "Максимальное количество одновременно работающих экземпляров IDA."
        ))
        left_col.addLayout(slider_row)
        left_col.addStretch()

        # Флаги анализа
        flags_grp = QGroupBox("Флаги анализа")
        flags_layout = QVBoxLayout(flags_grp)
        self.cleanup_check = QCheckBox("Удалять .asm и .log после успешного анализа")
        self.cleanup_check.setChecked(True)
        flags_layout.addWidget(self.cleanup_check)
        self.temp_cleanup_check = QCheckBox("Удалять временные файлы IDA (.id0, .id1, .nam, .til)")
        self.temp_cleanup_check.setChecked(True)
        flags_layout.addWidget(self.temp_cleanup_check)
        self.pseudocode_check = QCheckBox("Включить псевдокод в JSON-экспорт")
        self.pseudocode_check.setChecked(True)
        flags_layout.addWidget(self.pseudocode_check)
        self.delete_json_check = QCheckBox("Удалить JSON-файлы после создания отчётов")
        self.delete_json_check.setChecked(True)
        flags_layout.addWidget(self.delete_json_check)
        right_col.addWidget(flags_grp)
        right_col.addStretch()

        scan_layout.addLayout(left_col, 1)
        scan_layout.addLayout(right_col, 1)
        layout.addWidget(scan_grp)

        # Процесс
        process_grp = QGroupBox("Процесс анализа СФ")
        process_layout = QVBoxLayout(process_grp)
        self.process_label = QLabel("Готов к запуску")
        self.process_progress = QProgressBar()
        self.process_progress.setRange(0, 100)
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Запустить анализ СФ")
        self.start_btn.setFixedHeight(40)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.setFixedHeight(40)
        self.cancel_btn.setEnabled(False)
        self.html_generate_btn = QPushButton("Сгенерировать HTML-отчёт СФ")
        self.html_generate_btn.setFixedHeight(40)
        self.html_generate_btn.setEnabled(False)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.html_generate_btn)
        process_layout.addWidget(self.process_label)
        process_layout.addWidget(self.process_progress)
        process_layout.addLayout(btn_row)
        layout.addWidget(process_grp)

        # Ошибки
        self.error_text = QTextEdit()
        self.error_text.setReadOnly(True)
        self.error_text.setMaximumHeight(150)
        self.error_text.setPlaceholderText("Здесь будут появляться сообщения об ошибках...")
        layout.addWidget(self.error_text)

        layout.addStretch()

    def _create_help_button(self, tooltip: str) -> QPushButton:
        btn = QPushButton("i")
        btn.setFixedSize(22, 22)
        btn.setFlat(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setToolTip("Нажмите для пояснения")
        btn.setStyleSheet(
            "QPushButton { border-radius: 11px; background-color: #007aff; color: white; "
            "font-weight: bold; font-size: 14px; text-align: center; padding: 0; }"
            "QPushButton:hover { background-color: #005bb5; }"
        )
        def show_tooltip():
            from PySide6.QtWidgets import QToolTip
            QToolTip.showText(btn.mapToGlobal(btn.rect().center()), tooltip, btn)
        btn.clicked.connect(show_tooltip)
        return btn

    def _create_slider_with_label(self, initial: int, min_val: int = 1, max_val: int = 32) -> tuple:
        container = QWidget()
        lay = QHBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        slider = QSlider(Qt.Horizontal)
        slider.setRange(min_val, max_val)
        slider.setValue(initial)
        lbl = QLabel(str(initial))
        lbl.setFixedWidth(40)
        lbl.setAlignment(Qt.AlignCenter)
        slider.valueChanged.connect(lambda v: lbl.setText(str(v)))
        lay.addWidget(slider)
        lay.addWidget(lbl)
        return container, slider, lbl

    def _browse_input_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для анализа СФ")
        if path:
            self.inputdir_edit.setText(path)
            self._refresh_file_list()

    def _on_input_dir_changed(self) -> None:
        self._refresh_file_list()

    def _selected_extensions(self) -> List[str]:
        checked = self.platform_buttons.checkedButton()
        if checked and checked in self.radio_to_platform:
            platform_key = self.radio_to_platform[checked]
            return PLATFORM_EXTENSIONS[platform_key]["exts"]
        all_exts = []
        for info in PLATFORM_EXTENSIONS.values():
            for ext in info["exts"]:
                if ext not in all_exts:
                    all_exts.append(ext)
        return all_exts

    def _detect_platform_by_files(self, files: List[Path]) -> str:
        if not files:
            return "Windows"
        ext_counts = Counter(f.suffix.lower() for f in files)
        scores = {
            "Windows": sum(ext_counts.get(e, 0) for e in PLATFORM_EXTENSIONS["Windows"]["exts"]),
            "Linux / Android": sum(ext_counts.get(e, 0) for e in PLATFORM_EXTENSIONS["Linux / Android"]["exts"]),
            "macOS / iOS": sum(ext_counts.get(e, 0) for e in PLATFORM_EXTENSIONS["macOS / iOS"]["exts"]),
        }
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "Windows"

    def _set_platform_radio(self, platform_key: str) -> None:
        for radio, key in self.radio_to_platform.items():
            if key == platform_key:
                radio.setChecked(True)
                return

    def _refresh_file_list(self) -> None:
        input_dir = self.inputdir_edit.text().strip()
        if not input_dir or not os.path.isdir(input_dir):
            self._cached_files = []
            self.treemap.set_data([])
            self.html_generate_btn.setEnabled(False)
            return

        extensions = self._selected_extensions()
        files = find_executables(input_dir, extensions=extensions)

        # Обработка архивов
        for ext in ARCHIVE_EXTENSIONS:
            for archive_path in Path(input_dir).glob(f'*{ext}'):
                extracted_dir = extract_archive(archive_path)
                if extracted_dir and extracted_dir.is_dir():
                    archive_files = find_executables(str(extracted_dir), extensions=extensions)
                    files.extend(archive_files)
                    logger.info(f"Архив {archive_path.name}: добавлено {len(archive_files)} файлов")
                else:
                    if ext == '.dmg':
                        self.error_text.append(
                            f"Не удалось извлечь {archive_path.name}. Убедитесь, что 7z установлен и доступен в PATH.")

        self._cached_files = files
        if not files:
            self.treemap.set_data([])
            self.html_generate_btn.setEnabled(False)
            return

        detected = self._detect_platform_by_files(files)
        self._set_platform_radio(detected)

        items = []
        for f in files:
            size = f.stat().st_size if f.exists() else 0
            status = AnalysisStatus.NOT_ANALYZED
            i64_path = self._get_expected_i64_path(f)
            if i64_path.exists():
                status = AnalysisStatus.SUCCESS
            items.append({'name': f.name, 'size': size, 'status': status.value, 'path': str(f)})
        self.treemap.set_data(items)

        any_i64 = any(self._get_expected_i64_path(f).exists() for f in files)
        self.html_generate_btn.setEnabled(any_i64)

    def _get_expected_i64_path(self, file_path: Path) -> Path:
        return file_path.parent / (file_path.name + ".i64")

    def _start_analysis(self) -> None:
        if self.analysis_in_progress:
            return

        idat_path = get_ida_executable()
        if not Path(idat_path).is_file():
            QMessageBox.warning(self, "Утилита IDA не найдена",
                                f"Исполняемый файл '{idat_path}' не найден.\n"
                                "Проверьте путь в разделе «Конфигурация».")
            return

        input_dir = self.inputdir_edit.text().strip()
        if not input_dir:
            input_dir = get_default_inputdir()
            self.inputdir_edit.setText(input_dir)

        if not os.path.isdir(input_dir):
            QMessageBox.warning(self, "Ошибка", f"Указанная директория не существует: {input_dir}")
            return

        files = self._cached_files
        if not files:
            QMessageBox.information(self, "Информация", "Не найдено подходящих файлов.")
            return

        # Проверка 7z для DMG
        if any(f.suffix.lower() == '.dmg' for f in files):
            if not find_7z():
                QMessageBox.warning(self, "Требуется 7z",
                                    "Для обработки .dmg файлов необходим 7-Zip.\n"
                                    "Убедитесь, что '7z' доступен в системном PATH.")
                return

        # Логика работы с существующими базами (аналогично analysis_page)
        files_with_idb = [f for f in files if self._get_expected_i64_path(f).exists()]
        files_without_idb = [f for f in files if not self._get_expected_i64_path(f).exists()]

        export_only = False
        if files_with_idb:
            msg = QMessageBox(self)
            msg.setWindowTitle("Обнаружены существующие базы данных")
            msg.setText(f"Готово баз: {len(files_with_idb)} из {len(files)}\n"
                        f"Требуют анализа: {len(files_without_idb)}")
            btn_continue = msg.addButton("Доанализировать новые", QMessageBox.ButtonRole.AcceptRole)
            btn_overwrite = msg.addButton("Перезаписать всё", QMessageBox.ButtonRole.DestructiveRole)
            btn_export = msg.addButton("Экспортировать существующие", QMessageBox.ButtonRole.ActionRole)
            btn_cancel = msg.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
            msg.setDefaultButton(btn_continue)
            msg.exec()
            clicked = msg.clickedButton()
            if clicked == btn_cancel:
                return
            elif clicked == btn_continue:
                if not files_without_idb:
                    QMessageBox.information(self, "Информация", "Все файлы уже проанализированы.")
                    files = files_with_idb
                    export_only = True
                else:
                    files = files_without_idb
                    self._export_all_after_analysis = True
            elif clicked == btn_overwrite:
                files = files
                export_only = False
            elif clicked == btn_export:
                files = files_with_idb
                export_only = True
        else:
            pass

        if not files:
            QMessageBox.information(self, "Информация", "Нет файлов для обработки.")
            return

        self.analysis_in_progress = True
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.html_generate_btn.setEnabled(False)
        self.process_label.setText("Фаза: анализ файлов..." if not export_only else "Фаза: экспорт в JSON...")
        self.process_progress.setValue(0)
        self.error_text.clear()

        self.worker = AnalysisWorker(
            files, idat_path, self.max_ida_slider.value(),
            output_dir=None,
            cleanup=self.cleanup_check.isChecked(),
            temp_cleanup=self.temp_cleanup_check.isChecked(),
            pseudocode=self.pseudocode_check.isChecked(),
            delete_json=self.delete_json_check.isChecked(),
            export_only=export_only
        )
        self.worker.analysis_progress.connect(self._on_analysis_progress)
        self.worker.analysis_file_started.connect(self._on_analysis_file_started)
        self.worker.analysis_file_completed.connect(self._on_analysis_file_completed)
        self.worker.export_progress.connect(self._on_export_progress)
        self.worker.export_file_started.connect(self._on_export_file_started)
        self.worker.export_file_completed.connect(self._on_export_file_completed)
        self.worker.phase_changed.connect(self._on_phase_changed)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.finished.connect(self._on_analysis_finished)
        self.worker.start()

    def _cancel_analysis(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.process_label.setText("Отмена...")
            self.cancel_btn.setEnabled(False)

    def _on_phase_changed(self, phase: str) -> None:
        self.process_label.setText("Фаза: анализ файлов..." if phase == "analysis" else "Фаза: экспорт в JSON...")

    def _on_analysis_progress(self, filename: str, current: int, total: int) -> None:
        self.process_label.setText(f"Анализ: {current}/{total} – {filename}")
        self.process_progress.setValue(int(100 * current / total))

    def _on_analysis_file_started(self, filename: str) -> None:
        for f in self._cached_files:
            if f.name == filename:
                self.treemap.update_status(str(f), AnalysisStatus.IN_PROGRESS)
                break

    def _on_analysis_file_completed(self, filename: str, success: bool) -> None:
        for f in self._cached_files:
            if f.name == filename:
                self.treemap.update_status(str(f), AnalysisStatus.SUCCESS if success else AnalysisStatus.ERROR)
                break

    def _on_export_progress(self, filename: str, current: int, total: int) -> None:
        self.process_label.setText(f"Экспорт: {current}/{total} – {filename}")
        self.process_progress.setValue(int(100 * current / total))

    def _on_export_file_started(self, filename: str) -> None:
        pass

    def _on_export_file_completed(self, filename: str, success: bool) -> None:
        if not success:
            self.error_text.append(f"Ошибка экспорта для {filename}")

    def _on_error(self, message: str) -> None:
        self.error_text.append(message)

    def _on_analysis_finished(self, succeeded: int, total: int) -> None:
        self.analysis_in_progress = False
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.process_label.setText(f"Завершено. Обработано: {succeeded}/{total}")
        self.process_progress.setValue(100)

        if self._export_all_after_analysis and succeeded > 0:
            self._export_all_after_analysis = False
            self.process_label.setText("Автоматический экспорт всех баз...")
            QApplication.processEvents()
            all_idb_files = [self._get_expected_i64_path(f) for f in self._cached_files if self._get_expected_i64_path(f).exists()]
            if all_idb_files:
                self._start_export_only(all_idb_files)
            else:
                self.process_label.setText("Нет готовых баз для экспорта")
            return

        input_dir = self.inputdir_edit.text().strip()
        if input_dir:
            any_json = any(Path(input_dir).rglob("*.export.json"))
            self.html_generate_btn.setEnabled(any_json)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None
        self._refresh_file_list()

    def _start_export_only(self, idb_files: List[Path]) -> None:
        idat_path = get_ida_executable()
        script_path = SCRIPTS_DIR / "export_data.py"
        if not script_path.exists():
            self.error_text.append(f"Скрипт экспорта не найден: {script_path}")
            return
        script_args = {}
        if self.pseudocode_check.isChecked():
            script_args["pseudocode"] = "1"
        analyzer = IDAAnalyzer(idat_path=idat_path, max_workers=self.max_ida_slider.value())
        analyzer.set_progress_callback(self._on_export_progress)
        analyzer.set_file_start_callback(self._on_export_file_started)
        analyzer.set_file_done_callback(self._on_export_file_completed)
        self.process_label.setText("Фаза: экспорт в JSON...")
        self.process_progress.setValue(0)
        QApplication.processEvents()
        export_results = analyzer.run_script_on_batch(
            idb_files, script_path, script_args=script_args,
            cancel_event=None
        )
        succeeded = sum(1 for ok in export_results.values() if ok)
        self.process_label.setText(f"Экспорт завершён. Успешно: {succeeded}/{len(idb_files)}")
        self._refresh_file_list()

    def _start_html_generation(self) -> None:
        if self.html_in_progress:
            return
        input_dir = Path(self.inputdir_edit.text().strip())
        if not input_dir.is_dir():
            QMessageBox.warning(self, "Ошибка", "Папка не найдена.")
            return

        json_files = list(input_dir.rglob("*.export.json"))
        if not json_files:
            QMessageBox.warning(self, "Ошибка", "Нет JSON-файлов экспорта. Сначала выполните анализ.")
            return

        # Проверка наличия базы данных Win32 API
        db_dir = Path(get_sf_db_path())
        db_path = db_dir / "win32api.db"
        if not db_path.exists():
            # Предложить синхронизировать
            reply = QMessageBox.question(
                self, "База данных не найдена",
                "База данных системных функций (win32api.db) не найдена.\n"
                "Хотите синхронизировать её сейчас? (потребуется интернет)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                # Запускаем синхронизацию в отдельном потоке, затем продолжаем
                self.sync_thread = Win32DatabaseSync(str(db_dir))
                self.sync_thread.progress.connect(self._on_sync_progress)
                self.sync_thread.finished.connect(lambda success, msg: self._on_sync_finished(success, msg, input_dir, json_files))
                self.sync_thread.error.connect(self._on_sync_error)
                self.sync_thread.start()
                self.process_label.setText("Синхронизация базы данных...")
                self.start_btn.setEnabled(False)
                self.cancel_btn.setEnabled(False)
                self.html_generate_btn.setEnabled(False)
                return
            else:
                QMessageBox.warning(self, "Нет базы", "Невозможно выполнить анализ СФ без базы данных Win32 API.")
                return

        # База есть, запускаем генерацию
        self._do_generate_html(input_dir, json_files)

    def _on_sync_progress(self, message: str, percent: int):
        self.process_label.setText(f"Синхронизация: {message} ({percent}%)")

    def _on_sync_error(self, error_msg: str):
        self.process_label.setText(f"Ошибка синхронизации: {error_msg}")
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.html_generate_btn.setEnabled(False)
        QMessageBox.critical(self, "Ошибка синхронизации", error_msg)

    def _on_sync_finished(self, success: bool, result: str, input_dir: Path, json_files: List[Path]):
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        if not success:
            self.process_label.setText("Синхронизация не удалась")
            QMessageBox.critical(self, "Ошибка", f"Не удалось синхронизировать базу данных: {result}")
            return
        # Синхронизация успешна, продолжаем
        self._do_generate_html(input_dir, json_files)

    def _do_generate_html(self, input_dir: Path, json_files: List[Path]):
        from ida_batch_tool.reporting.sfa_generator import SfaReportGenerator
        generator = SfaReportGenerator()
        sfa_reports = input_dir / "SFAReports"
        sfa_reports.mkdir(parents=True, exist_ok=True)

        self.html_in_progress = True
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.html_generate_btn.setEnabled(False)
        self.process_progress.setValue(0)
        self.process_label.setText("Генерация HTML-отчётов СФ...")
        self.error_text.clear()

        self.html_worker = SfaHtmlGeneratorWorker(
            {json_path: True for json_path in json_files},
            generator, sfa_reports, input_dir,
            delete_json=self.delete_json_check.isChecked()
        )
        self.html_worker.progress_updated.connect(self._on_html_progress)
        self.html_worker.error_occurred.connect(self._on_error)
        self.html_worker.finished.connect(self._on_html_finished)
        self.html_worker.start()

    def _on_html_progress(self, current: int, total: int, message: str) -> None:
        self.process_label.setText(f"Генерация HTML: {current}/{total} {message}")
        self.process_progress.setValue(int(100 * current / total))

    def _on_html_finished(self, generated_count: int, report_links: list, ida_info: dict, sfa_reports: Path, input_dir: Path, total_files: int, total_size_bytes: int) -> None:
        self.process_label.setText("Создание сводного отчёта СФ...")
        QApplication.processEvents()
        from datetime import datetime
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        from ida_batch_tool.reporting.sfa_generator import SfaReportGenerator
        generator = SfaReportGenerator()
        try:
            index_path = generator.generate_index(
                sfa_reports, input_dir, report_links, ida_info,
                total_files=total_files, total_size_bytes=total_size_bytes,
                generation_time=gen_time
            )
            self.html_in_progress = False
            self.start_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)
            self.html_generate_btn.setEnabled(True)
            self.process_progress.setValue(100)
            self.process_label.setText("Готово")
            QMessageBox.information(self, "Готово", f"Отчёты СФ сохранены в {sfa_reports}\nИндекс: {index_path}")
        except Exception as e:
            self.error_text.append(f"Ошибка создания индексного отчёта: {e}")
            self.html_in_progress = False
            self.start_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)
            self.html_generate_btn.setEnabled(True)
            self.process_label.setText("Ошибка при создании индекса")

    # Сигналы подключения
    def _connect_signals(self) -> None:
        self.browse_dir_btn.clicked.connect(self._browse_input_dir)
        self.start_btn.clicked.connect(self._start_analysis)
        self.cancel_btn.clicked.connect(self._cancel_analysis)
        self.html_generate_btn.clicked.connect(self._start_html_generation)
        self.inputdir_edit.textChanged.connect(self._on_input_dir_changed)