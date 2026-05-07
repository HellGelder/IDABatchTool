"""Главное окно приложения с новым дизайном и объединённым процессом анализа/экспорта."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from collections import Counter

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QSizePolicy,
    QPushButton, QLabel, QProgressBar, QTextEdit, QGroupBox,
    QFileDialog, QStackedWidget, QMessageBox, QApplication, QLineEdit,
    QSlider, QRadioButton, QButtonGroup, QGridLayout,
    QCheckBox, QFrame, QWhatsThis, QStyle, QSplitter
)
from PySide6.QtCore import Qt, QPoint

from ida_batch_tool.config.loader import load_config, get_ida_executable, get_default_inputdir, get_max_ida
from ida_batch_tool.discovery.finder import find_executables
from ida_batch_tool.ida.runner import IDAAnalyzer
from ida_batch_tool.reporting.generator import ReportGenerator, _build_internal_set
from ida_batch_tool.ui.constants import AnalysisStatus, PLATFORM_EXTENSIONS, SCRIPTS_DIR
from ida_batch_tool.ui.theme import apply_theme
from ida_batch_tool.ui.settings_dialog import SettingsPage
from ida_batch_tool.ui.widgets.treemap import TreemapWidget
from ida_batch_tool.ui.workers.html_generation import HtmlGeneratorWorker
from ida_batch_tool.ui.analysis_worker import AnalysisWorker


class MainWindow(QMainWindow):
    WINDOW_WIDTH = 1200
    WINDOW_HEIGHT = 800
    SIDEBAR_WIDTH = 200
    MAX_IDA_THREADS = 32

    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDA Batch Tool")
        self.resize(self.WINDOW_WIDTH, self.WINDOW_HEIGHT)
        self.cfg: Dict[str, Any] = load_config()
        self.current_theme: str = self.cfg.get("theme", "light")
        self.analysis_in_progress = False
        self.html_in_progress = False
        self.worker: Optional[AnalysisWorker] = None
        self.html_worker: Optional[HtmlGeneratorWorker] = None
        self.active_page = 0
        self._cached_files: List[Path] = []

        self._build_ui()
        self._connect_signals()
        apply_theme(QApplication.instance(), self.current_theme)
        self.btn_analysis.setChecked(True)
        self.btn_settings.setChecked(False)
        self._update_menu_styles()
        self._refresh_file_list()

    # ------------------------------------------------------------------
    # Стили
    # ------------------------------------------------------------------
    def _update_menu_styles(self):
        self.btn_analysis.setStyleSheet(self._menu_button_style(self.btn_analysis.isChecked(), self.current_theme))
        self.btn_settings.setStyleSheet(self._menu_button_style(self.btn_settings.isChecked(), self.current_theme))

    @staticmethod
    def _create_help_button(tooltip_text: str) -> QPushButton:
        btn = QPushButton()
        btn.setIcon(btn.style().standardIcon(QStyle.SP_MessageBoxQuestion))
        btn.setFixedSize(20, 20)
        btn.setFlat(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setToolTip("Нажмите для пояснения")
        btn.clicked.connect(
            lambda checked, b=btn, t=tooltip_text: QWhatsThis.showText(
                b.mapToGlobal(QPoint(0, b.height())), t
            )
        )
        return btn

    @staticmethod
    def _menu_button_style(active: bool, theme: str = "light") -> str:
        base = """
            QPushButton {
                text-align: left;
                padding: 8px 12px;
                border-radius: 8px;
                font-weight: 500;
                border: none;
            }
        """
        if active:
            if theme == "dark":
                base += "background-color: #3a3a3c; color: #ffffff;"
            else:
                base += "background-color: #e8e8ed; color: #000;"
        else:
            if theme == "dark":
                base += "background-color: transparent; color: #cccccc;"
                base += " hover { background-color: #3a3a3c; }"
            else:
                base += "background-color: transparent; color: #505050;"
                base += " hover { background-color: #f0f0f5; }"
        return base

    def _create_slider_with_label(self, initial_value: int,
                                  range_min: int = 1,
                                  range_max: int = None) -> tuple[QWidget, QSlider, QLabel]:
        if range_max is None:
            range_max = self.MAX_IDA_THREADS
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        slider = QSlider(Qt.Horizontal)
        slider.setRange(range_min, range_max)
        slider.setValue(initial_value)
        value_label = QLabel(str(initial_value))
        value_label.setFixedWidth(40)
        value_label.setAlignment(Qt.AlignCenter)
        slider.valueChanged.connect(lambda v: value_label.setText(str(v)))
        layout.addWidget(slider)
        layout.addWidget(value_label)
        return container, slider, value_label

    # ------------------------------------------------------------------
    # Построение UI
    # ------------------------------------------------------------------
    def _build_ui(self):
        central = QWidget(objectName="central")
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Боковая панель (без изменений)
        sidebar = QWidget(objectName="sidebar")
        sidebar.setFixedWidth(self.SIDEBAR_WIDTH)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        sidebar_layout.setSpacing(6)

        title_label = QLabel("IDA Batch")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: 700; margin-bottom: 15px;")
        sidebar_layout.addWidget(title_label)

        self.btn_analysis = QPushButton("  Анализ")
        self.btn_analysis.setCheckable(True)
        self.btn_analysis.setChecked(True)
        sidebar_layout.addWidget(self.btn_analysis)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sidebar_layout.addWidget(spacer)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        sidebar_layout.addWidget(line)

        self.btn_settings = QPushButton("  Конфигурация")
        self.btn_settings.setCheckable(True)
        self.btn_settings.setChecked(False)
        sidebar_layout.addWidget(self.btn_settings)

        self.pages = QStackedWidget()
        self.analysis_page = self._create_analysis_page()
        self.settings_page = SettingsPage()
        self.settings_page.config_changed.connect(self._on_config_changed)
        self.pages.addWidget(self.analysis_page)
        self.pages.addWidget(self.settings_page)
        self.pages.setCurrentIndex(0)
        self.active_page = 0

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.pages, 1)

    def _create_analysis_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # 1. Источник файлов
        source_group = QGroupBox("Источник файлов")
        source_layout = QVBoxLayout(source_group)
        dir_row = QHBoxLayout()
        self.inputdir_edit: QLineEdit = QLineEdit()
        self.inputdir_edit.setPlaceholderText("Путь к папке с бинарными файлами...")
        self.inputdir_edit.setText(get_default_inputdir())
        self.browse_dir_btn: QPushButton = QPushButton("Обзор...")
        dir_row.addWidget(self.inputdir_edit, 1)
        dir_row.addWidget(self._create_help_button("Папка, в которой находятся исполняемые файлы для анализа."))
        dir_row.addWidget(self.browse_dir_btn)
        source_layout.addLayout(dir_row)
        layout.addWidget(source_group)

        # 2. Графическое отображение директории
        treemap_group = QGroupBox("Графическое отображение директории")
        treemap_layout = QVBoxLayout(treemap_group)
        self.treemap = TreemapWidget()
        self.treemap.setMinimumHeight(40)
        treemap_layout.addWidget(self.treemap)
        layout.addWidget(treemap_group)

        # 3. Параметры сканирования (разделены на две колонки)
        scan_group = QGroupBox("Параметры сканирования")
        scan_layout = QHBoxLayout(scan_group)
        # Левая колонка
        left_column = QVBoxLayout()
        # Целевая платформа
        platform_group = QGroupBox("Целевая платформа")
        platform_layout = QVBoxLayout(platform_group)
        self.platform_buttons = QButtonGroup(self)
        self.platform_buttons.setExclusive(True)
        self.radio_to_platform: Dict[QRadioButton, str] = {}
        grid = QGridLayout()
        row, col = 0, 0
        for key, info in PLATFORM_EXTENSIONS.items():
            radio = QRadioButton(info["label"])
            self.platform_buttons.addButton(radio)
            self.radio_to_platform[radio] = key
            ext_list = ", ".join(info["exts"])
            help_btn = self._create_help_button(f"Платформа: {info['label']}\nАнализируемые расширения: {ext_list}")
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
        platform_layout.addLayout(grid)
        left_column.addWidget(platform_group)
        # Потоки IDA
        self.max_ida_slider_container, self.max_ida_slider, self.max_ida_label = \
            self._create_slider_with_label(min(get_max_ida(), self.MAX_IDA_THREADS))
        slider_row = QHBoxLayout()
        slider_row.addWidget(QLabel("Потоков IDA:"))
        slider_row.addWidget(self.max_ida_slider_container)
        slider_row.addWidget(self._create_help_button(
            "Максимальное количество одновременно работающих экземпляров IDA.\n"
            "Больше потоков – быстрее анализ, но выше нагрузка на процессор."
        ))
        left_column.addLayout(slider_row)
        left_column.addStretch()

        # Правая колонка: флаги анализа
        right_column = QVBoxLayout()
        flags_group = QGroupBox("Флаги анализа")
        flags_layout = QVBoxLayout(flags_group)
        self.cleanup_check = QCheckBox("Удалять .asm и .log после успешного анализа")
        self.temp_cleanup_check = QCheckBox("Удалять временные файлы IDA (.id0, .id1, .nam, .til)")
        self.pseudocode_check = QCheckBox("Включить псевдокод в JSON-экспорт")
        self.pseudocode_check.setToolTip(
            "Если включено, псевдокод будет сгенерирован только для экспортируемых функций."
        )
        pseudocode_help = self._create_help_button(
            "При включении псевдокод будет получен только для функций, "
            "присутствующих в таблице экспорта.\n"
            "Это значительно ускоряет экспорт и уменьшает размер JSON."
        )
        pseudocode_row = QHBoxLayout()
        pseudocode_row.addWidget(self.pseudocode_check)
        pseudocode_row.addWidget(pseudocode_help)
        pseudocode_row.addStretch()
        flags_layout.addWidget(self.cleanup_check)
        flags_layout.addWidget(self.temp_cleanup_check)
        flags_layout.addLayout(pseudocode_row)
        self.delete_json_check = QCheckBox("Удалить JSON-файлы после создания отчётов")
        self.delete_json_check.setToolTip(
            "После успешной генерации HTML-отчётов и сводного индекса, JSON-файлы экспорта будут удалены."
        )
        flags_layout.addWidget(self.delete_json_check)
        right_column.addWidget(flags_group)
        right_column.addStretch()

        scan_layout.addLayout(left_column, 1)
        scan_layout.addLayout(right_column, 1)
        layout.addWidget(scan_group)

        # 4. Процесс анализа (объединённый)
        process_group = QGroupBox("Процесс анализа")
        process_layout = QVBoxLayout(process_group)
        self.process_label = QLabel("Готов к запуску")
        self.process_progress = QProgressBar()
        self.process_progress.setRange(0, 100)
        buttons_row = QHBoxLayout()
        self.start_btn = QPushButton("Запустить анализ")
        self.start_btn.setFixedHeight(40)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.setEnabled(False)
        buttons_row.addWidget(self.start_btn)
        buttons_row.addWidget(self.cancel_btn)
        buttons_row.addStretch()
        process_layout.addWidget(self.process_label)
        process_layout.addWidget(self.process_progress)
        process_layout.addLayout(buttons_row)
        layout.addWidget(process_group)

        # 5. HTML-отчёт
        html_group = QGroupBox("HTML-отчёт")
        html_layout = QVBoxLayout(html_group)
        html_progress_row = QHBoxLayout()
        self.html_progress_bar = QProgressBar()
        self.html_progress_bar.setRange(0, 100)
        self.html_generate_btn = QPushButton("Сгенерировать HTML-отчёты")
        self.html_generate_btn.setEnabled(False)
        html_progress_row.addWidget(self.html_progress_bar, 1)
        html_progress_row.addWidget(self.html_generate_btn)
        html_layout.addLayout(html_progress_row)
        layout.addWidget(html_group)

        # 6. Окно ошибок
        self.error_text = QTextEdit()
        self.error_text.setReadOnly(True)
        self.error_text.setMaximumHeight(150)
        self.error_text.setPlaceholderText("Здесь будут появляться сообщения об ошибках...")
        layout.addWidget(self.error_text)

        layout.addStretch()
        return page

    # ------------------------------------------------------------------
    # Сигналы и слоты
    # ------------------------------------------------------------------
    def _connect_signals(self):
        self.btn_analysis.clicked.connect(lambda: self.switch_page(0))
        self.btn_settings.clicked.connect(lambda: self.switch_page(1))
        self.browse_dir_btn.clicked.connect(self._browse_input_dir)
        self.start_btn.clicked.connect(self._start_analysis)
        self.cancel_btn.clicked.connect(self._cancel_analysis)
        self.html_generate_btn.clicked.connect(self._start_html_generation)
        self.inputdir_edit.textChanged.connect(self._on_input_dir_changed)

    def switch_page(self, index: int):
        if self.analysis_in_progress and index != 0:
            return
        self.active_page = index
        self.btn_analysis.setChecked(index == 0)
        self.btn_settings.setChecked(index == 1)
        self._update_menu_styles()
        self.pages.setCurrentIndex(index)

    def _browse_input_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для анализа")
        if path:
            self.inputdir_edit.setText(path)
            self._refresh_file_list()

    def _on_input_dir_changed(self):
        self._refresh_file_list()

    def _selected_extensions(self) -> List[str]:
        checked = self.platform_buttons.checkedButton()
        if checked and checked in self.radio_to_platform:
            return PLATFORM_EXTENSIONS[self.radio_to_platform[checked]]["exts"]
        return PLATFORM_EXTENSIONS["All platforms"]["exts"]

    def _detect_platform_by_files(self, files: List[Path]) -> str:
        """Определяет платформу по расширениям файлов."""
        if not files:
            return "All platforms"
        ext_counts = Counter(f.suffix.lower() for f in files)
        # Веса для платформ
        platform_scores = {
            "Windows": sum(ext_counts.get(ext, 0) for ext in ['.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.drv', '.efi']),
            "Linux / Android": sum(ext_counts.get(ext, 0) for ext in ['.elf', '.so', '.o', '.ko', '.dex']),
            "macOS / iOS": sum(ext_counts.get(ext, 0) for ext in ['.mach-o', '.dylib', '.bundle', '.app']),
        }
        best = max(platform_scores, key=lambda k: platform_scores[k])
        if platform_scores[best] == 0:
            return "All platforms"
        return best

    def _set_platform_radio(self, platform_key: str):
        for radio, key in self.radio_to_platform.items():
            if key == platform_key:
                radio.setChecked(True)
                return
        # Если не нашли, ставим All platforms
        for radio, key in self.radio_to_platform.items():
            if key == "All platforms":
                radio.setChecked(True)
                break

    def _refresh_file_list(self):
        input_dir = self.inputdir_edit.text().strip()
        if not input_dir or not os.path.isdir(input_dir):
            self._cached_files = []
            self.files_found_label = QLabel("")  # но мы убрали этот лейбл, надо создать или убрать
            # У нас нет такого лейбла в новом интерфейсе, поэтому просто очистим treemap
            self.treemap.set_data([])
            self.html_generate_btn.setEnabled(False)
            return

        extensions = self._selected_extensions()
        files = find_executables(input_dir, extensions=extensions)
        self._cached_files = files
        if not files:
            self.treemap.set_data([])
            self.html_generate_btn.setEnabled(False)
            return

        # Автоопределение платформы и установка радиокнопки
        detected_platform = self._detect_platform_by_files(files)
        self._set_platform_radio(detected_platform)
        # Если после смены платформы расширения изменились, нужно пересканировать?
        # Но мы уже использовали текущие расширения. Лучше перечитать с новыми расширениями, если они изменились.
        new_extensions = self._selected_extensions()
        if set(new_extensions) != set(extensions):
            files = find_executables(input_dir, extensions=new_extensions)
            self._cached_files = files

        items = []
        for f in files:
            size = f.stat().st_size if f.exists() else 0
            status = AnalysisStatus.NOT_ANALYZED
            idb_path = self._get_expected_idb_path(f)
            if idb_path.exists():
                status = AnalysisStatus.SUCCESS
            items.append({'name': f.name, 'size': size, 'status': status.value, 'path': str(f)})
        self.treemap.set_data(items)

        any_idb = any(self._get_expected_idb_path(f).exists() for f in files)
        self.html_generate_btn.setEnabled(any_idb)

    def _get_expected_idb_path(self, file_path: Path) -> Path:
        # IDA 9.x всегда использует .i64
        return file_path.parent / (file_path.name + ".i64")

    # ------------------------------------------------------------------
    # Запуск объединённого анализа
    # ------------------------------------------------------------------
    def _start_analysis(self):
        idat_path = get_ida_executable()
        if not shutil.which(idat_path):
            QMessageBox.warning(
                self, "Утилита IDA не найдена",
                f"Исполняемый файл '{idat_path}' не найден в системном PATH.\n\n"
                "Пожалуйста, проверьте путь к idat.exe в разделе «Конфигурация» или "
                "добавьте папку с IDA в переменную PATH."
            )
            return

        input_dir = self.inputdir_edit.text().strip()
        if not input_dir or not os.path.isdir(input_dir):
            QMessageBox.warning(self, "Ошибка", "Укажите существующую директорию.")
            return

        files = self._cached_files
        if not files:
            QMessageBox.information(self, "Информация", "Не найдено подходящих файлов.")
            return

        # Спросить, если все базы уже есть, но теперь анализ и экспорт всё равно запустятся
        # Можно пропустить, но оставим как есть
        all_idbs = all(self._get_expected_idb_path(f).exists() for f in files)
        if all_idbs:
            reply = QMessageBox.question(
                self, "Базы данных уже существуют",
                "Для всех файлов уже есть .i64 базы. Запустить экспорт в JSON?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if reply == QMessageBox.No:
                return

        self.analysis_in_progress = True
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.html_generate_btn.setEnabled(False)
        self.process_label.setText("Фаза: анализ файлов...")
        self.process_progress.setValue(0)
        self.error_text.clear()

        self.worker = AnalysisWorker(
            files, idat_path, self.max_ida_slider.value(),
            output_dir=None,
            cleanup=self.cleanup_check.isChecked(),
            temp_cleanup=self.temp_cleanup_check.isChecked(),
            pseudocode=self.pseudocode_check.isChecked(),
            delete_json=self.delete_json_check.isChecked()
        )
        # Сигналы для фазы анализа
        self.worker.analysis_progress.connect(self._on_analysis_progress)
        self.worker.analysis_file_started.connect(self._on_analysis_file_started)
        self.worker.analysis_file_completed.connect(self._on_analysis_file_completed)
        # Сигналы для фазы экспорта
        self.worker.export_progress.connect(self._on_export_progress)
        self.worker.export_file_started.connect(self._on_export_file_started)
        self.worker.export_file_completed.connect(self._on_export_file_completed)
        self.worker.phase_changed.connect(self._on_phase_changed)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.finished.connect(self._on_analysis_finished)
        self.worker.start()

    def _on_phase_changed(self, phase: str):
        if phase == "analysis":
            self.process_label.setText("Фаза: анализ файлов...")
        else:
            self.process_label.setText("Фаза: экспорт в JSON...")

    def _on_analysis_progress(self, filename: str, current: int, total: int):
        self.process_label.setText(f"Анализ: {current}/{total} – {filename}")
        self.process_progress.setValue(int(100 * current / total))

    def _on_analysis_file_started(self, filename: str):
        for f in self._cached_files:
            if f.name == filename:
                self.treemap.update_status(str(f), AnalysisStatus.IN_PROGRESS)
                break

    def _on_analysis_file_completed(self, filename: str, success: bool):
        for f in self._cached_files:
            if f.name == filename:
                self.treemap.update_status(str(f), AnalysisStatus.SUCCESS if success else AnalysisStatus.ERROR)
                break

    def _on_export_progress(self, filename: str, current: int, total: int):
        self.process_label.setText(f"Экспорт: {current}/{total} – {filename}")
        self.process_progress.setValue(int(100 * current / total))

    def _on_export_file_started(self, filename: str):
        # В treemap обновляем статус? Экспорт не меняет статус файла.
        pass

    def _on_export_file_completed(self, filename: str, success: bool):
        if not success:
            self.error_text.append(f"Ошибка экспорта для {filename}")

    def _on_error(self, message: str):
        self.error_text.append(message)

    def _on_analysis_finished(self, succeeded: int, total: int):
        self.analysis_in_progress = False
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.process_label.setText(f"Завершено. Проанализировано: {succeeded}/{total}")
        self.process_progress.setValue(100)
        # Активируем кнопку HTML-отчёта, если есть хотя бы один успешный экспорт
        # Для этого нужно знать, были ли успешные экспорты. Пока просто активируем, если есть .json файлы
        input_dir = self.inputdir_edit.text().strip()
        if input_dir:
            any_json = any(Path(input_dir).rglob("*.export.json"))
            self.html_generate_btn.setEnabled(any_json)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None
        self._refresh_file_list()

    def _cancel_analysis(self):
        if self.worker:
            self.worker.cancel()
            self.process_label.setText("Отмена...")
            self.cancel_btn.setEnabled(False)

    # ------------------------------------------------------------------
    # Генерация HTML-отчётов
    # ------------------------------------------------------------------
    def _start_html_generation(self):
        if self.html_in_progress:
            return

        input_dir = Path(self.inputdir_edit.text().strip())
        if not input_dir.is_dir():
            QMessageBox.warning(self, "Ошибка", "Папка не найдена.")
            return

        # Собираем все JSON-файлы экспорта
        json_files = list(input_dir.rglob("*.export.json"))
        if not json_files:
            QMessageBox.warning(self, "Ошибка", "Нет JSON-файлов экспорта. Сначала выполните анализ.")
            return

        generator = ReportGenerator()
        ida_reports = input_dir.parent / "IDAReports"
        ida_reports.mkdir(parents=True, exist_ok=True)
        internal_set = _build_internal_set(input_dir)

        self.html_in_progress = True
        self.html_generate_btn.setEnabled(False)
        self.html_progress_bar.setValue(0)
        self.error_text.clear()

        self.html_worker = HtmlGeneratorWorker(
            {json_path: True for json_path in json_files},  # фиктивный results
            generator, ida_reports, input_dir,
            delete_json=self.delete_json_check.isChecked(),
            internal_set=internal_set
        )
        self.html_worker.progress_updated.connect(self._on_html_progress)
        self.html_worker.error_occurred.connect(self._on_error)
        self.html_worker.finished.connect(self._on_html_finished)
        self.html_worker.start()

    def _on_html_progress(self, current: int, total: int, message: str):
        self.html_progress_bar.setValue(int(100 * current / total))

    def _on_html_finished(self, generated_count: int, report_links: list,
                          global_modules_set: set, global_elf_set: set,
                          ida_info: dict, ida_reports: Path, input_dir: Path):
        self.html_in_progress = False
        self.html_generate_btn.setEnabled(True)
        self.html_progress_bar.setValue(100)
        QMessageBox.information(self, "Готово", f"Отчёты сохранены в {ida_reports}")

    # ------------------------------------------------------------------
    # Прочие методы
    # ------------------------------------------------------------------
    def _on_config_changed(self, new_config: Dict[str, Any]):
        self.cfg = new_config
        new_theme = new_config.get("theme", "light")
        if new_theme != self.current_theme:
            self.current_theme = new_theme
            apply_theme(QApplication.instance(), new_theme)
            self._update_menu_styles()