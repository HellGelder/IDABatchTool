"""Виджет страницы сравнения директорий с помощью BinDiff."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, List, Tuple

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QProgressBar, QTextEdit, QGroupBox, QFileDialog,
    QLineEdit, QMessageBox, QFrame, QSizePolicy
)
from PySide6.QtCore import Signal, Qt

from ida_batch_tool.config.loader import get_ida_executable, get_bindiff_executable
from ida_batch_tool.ui.workers.diff_worker import DiffWorker


class DiffPage(QWidget):
    """Страница для запуска сравнения двух директорий с BinDiff и генерации отчёта."""

    diff_started = Signal()
    diff_finished = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._diff_in_progress = False
        self._worker: Optional[DiffWorker] = None
        self._output_dir: Optional[Path] = None

        self._init_ui()

    def is_diff_running(self) -> bool:
        return self._diff_in_progress

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # --- Выбор директорий ---
        dir_group = QGroupBox("Директории для сравнения")
        dir_layout = QVBoxLayout(dir_group)

        left_layout = QHBoxLayout()
        left_layout.addWidget(QLabel("Левая (эталонная):"))
        self.left_edit = QLineEdit()
        self.left_edit.setPlaceholderText("Путь к папке с .i64 файлами...")
        self.left_browse = QPushButton("Обзор...")
        left_layout.addWidget(self.left_edit, 1)
        left_layout.addWidget(self.left_browse)
        dir_layout.addLayout(left_layout)

        right_layout = QHBoxLayout()
        right_layout.addWidget(QLabel("Правая (текущая):"))
        self.right_edit = QLineEdit()
        self.right_edit.setPlaceholderText("Путь к папке с .i64 файлами...")
        self.right_browse = QPushButton("Обзор...")
        right_layout.addWidget(self.right_edit, 1)
        right_layout.addWidget(self.right_browse)
        dir_layout.addLayout(right_layout)

        # --- Выходная папка ---
        out_layout = QHBoxLayout()
        out_layout.addWidget(QLabel("Папка результатов:"))
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Автоматически: DiffResults в левой папке")
        self.output_browse = QPushButton("Обзор...")
        out_layout.addWidget(self.output_edit, 1)
        out_layout.addWidget(self.output_browse)
        dir_layout.addLayout(out_layout)

        main_layout.addWidget(dir_group)

        # --- Динамическое сопоставление файлов ---
        map_group = QGroupBox("Сопоставление файлов")
        map_layout = QVBoxLayout(map_group)

        self.map_status_label = QLabel("Укажите обе директории для анализа.")
        self.map_status_label.setWordWrap(True)
        map_layout.addWidget(self.map_status_label)

        # Таблица несоответствий (скрываемая)
        self.mismatch_text = QTextEdit()
        self.mismatch_text.setReadOnly(True)
        self.mismatch_text.setMaximumHeight(100)
        self.mismatch_text.setVisible(False)
        map_layout.addWidget(self.mismatch_text)

        main_layout.addWidget(map_group)

        # --- Запуск и прогресс ---
        run_group = QGroupBox("Процесс сравнения")
        run_layout = QVBoxLayout(run_group)

        self.process_label = QLabel("Готов к запуску")
        self.process_progress = QProgressBar()
        self.process_progress.setRange(0, 100)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Запустить сравнение")
        self.start_btn.setFixedHeight(40)
        self.start_btn.setEnabled(False)   # будет включено только при наличии пар
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.setFixedHeight(40)
        self.cancel_btn.setEnabled(False)
        self.generate_report_btn = QPushButton("Сгенерировать HTML-отчёт")
        self.generate_report_btn.setFixedHeight(40)
        self.generate_report_btn.setEnabled(False)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.generate_report_btn)

        run_layout.addWidget(self.process_label)
        run_layout.addWidget(self.process_progress)
        run_layout.addLayout(btn_layout)
        main_layout.addWidget(run_group)

        # --- Ошибки ---
        self.error_text = QTextEdit()
        self.error_text.setReadOnly(True)
        self.error_text.setMaximumHeight(150)
        self.error_text.setPlaceholderText("Здесь будут появляться сообщения об ошибках...")
        main_layout.addWidget(self.error_text)

        main_layout.addStretch()

        # Подключаем сигналы
        self.left_browse.clicked.connect(lambda: self._browse_dir(self.left_edit))
        self.right_browse.clicked.connect(lambda: self._browse_dir(self.right_edit))
        self.output_browse.clicked.connect(self._browse_output_dir)
        self.start_btn.clicked.connect(self._start_comparison)
        self.cancel_btn.clicked.connect(self._cancel_comparison)
        self.generate_report_btn.clicked.connect(self._generate_report)

        # Автоматический анализ при изменении путей
        self.left_edit.textChanged.connect(self._analyze_directories)
        self.right_edit.textChanged.connect(self._analyze_directories)

        # Первоначальное обновление
        self._analyze_directories()

    def _browse_dir(self, line_edit: QLineEdit) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if path:
            line_edit.setText(path)

    def _browse_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для результатов")
        if path:
            self.output_edit.setText(path)

    # ----------------------------------------------------------------
    # Анализ директорий и отображение статуса сопоставления
    # ----------------------------------------------------------------
    def _analyze_directories(self) -> None:
        """Анализирует левую и правую папки, обновляет метки и кнопку запуска."""
        left_dir = self.left_edit.text().strip()
        right_dir = self.right_edit.text().strip()

        if not left_dir or not os.path.isdir(left_dir) or not right_dir or not os.path.isdir(right_dir):
            self.map_status_label.setText("Укажите обе директории для анализа.")
            self.mismatch_text.setVisible(False)
            self.start_btn.setEnabled(False)
            return

        left_i64 = sorted(Path(left_dir).glob("*.i64"))
        right_i64 = sorted(Path(right_dir).glob("*.i64"))

        left_names = {p.stem for p in left_i64}
        right_names = {p.stem for p in right_i64}

        common = left_names & right_names
        only_left = left_names - right_names
        only_right = right_names - left_names

        # Статусная строка
        if len(common) == len(left_names) == len(right_names) and len(left_names) > 0:
            status_text = (
                f"✅ <b>Зеркальные директории</b> — все файлы имеют пару "
                f"({len(left_names)} .i64 в каждой папке, {len(common)} пар)."
            )
            self.start_btn.setEnabled(True)
        elif common:
            status_text = (
                f"⚠️ <b>Частичное совпадение</b>: {len(common)} пар из "
                f"{len(left_names)} файлов слева и {len(right_names)} справа."
            )
            self.start_btn.setEnabled(True)
        else:
            status_text = (
                f"❌ <b>Нет совпадений</b>: {len(left_names)} файлов слева, "
                f"{len(right_names)} справа. Проверьте директории."
            )
            self.start_btn.setEnabled(False)

        self.map_status_label.setText(status_text)

        # Список отсутствующих файлов
        mismatch_lines = []
        if only_left:
            mismatch_lines.append(
                f"<span style='color:#c62828;'>Только в левой папке ({len(only_left)}): "
                + ", ".join(sorted(only_left)) + "</span>"
            )
        if only_right:
            mismatch_lines.append(
                f"<span style='color:#c62828;'>Только в правой папке ({len(only_right)}): "
                + ", ".join(sorted(only_right)) + "</span>"
            )

        if mismatch_lines:
            self.mismatch_text.setHtml("<br>".join(mismatch_lines))
            self.mismatch_text.setVisible(True)
        else:
            self.mismatch_text.setVisible(False)

    # ----------------------------------------------------------------
    # Логика сравнения (осталась без изменений)
    # ----------------------------------------------------------------
    def _start_comparison(self) -> None:
        if self._diff_in_progress:
            return

        left_dir = self.left_edit.text().strip()
        right_dir = self.right_edit.text().strip()

        if not left_dir or not os.path.isdir(left_dir):
            QMessageBox.warning(self, "Ошибка", "Укажите корректную левую директорию.")
            return
        if not right_dir or not os.path.isdir(right_dir):
            QMessageBox.warning(self, "Ошибка", "Укажите корректную правую директорию.")
            return

        # Определяем выходную папку
        output_dir = self.output_edit.text().strip()
        if output_dir:
            output_path = Path(output_dir)
        else:
            output_path = Path(left_dir) / "DiffResults"
        output_path.mkdir(parents=True, exist_ok=True)

        idat_path = get_ida_executable()
        if not Path(idat_path).is_file():
            QMessageBox.warning(
                self, "Утилита IDA не найдена",
                f"Исполняемый файл '{idat_path}' не найден.\n"
                "Проверьте путь в разделе «Конфигурация»."
            )
            return

        bindiff_path = get_bindiff_executable()
        if not Path(bindiff_path).is_file():
            QMessageBox.warning(
                self, "Утилита BinDiff не найдена",
                f"Исполняемый файл '{bindiff_path}' не найден.\n"
                "Поместите bindiff.exe в корень проекта или укажите путь в config.yaml."
            )
            return

        # Поиск .i64 в левой директории
        left_i64 = sorted(Path(left_dir).glob("*.i64"))
        if not left_i64:
            QMessageBox.warning(
                self, "Нет баз данных",
                "Не найдено файлов .i64 в левой директории."
            )
            return

        # Сопоставление с правой директорией по имени
        right_i64_map = {p.stem: p for p in Path(right_dir).glob("*.i64")}
        pairs: List[Tuple[Path, Path]] = []
        for left_path in left_i64:
            stem = left_path.stem
            if stem in right_i64_map:
                pairs.append((left_path, right_i64_map[stem]))

        if not pairs:
            QMessageBox.warning(self, "Нет совпадений", "Ни один файл из левой директории не имеет пары в правой.")
            return

        self._diff_in_progress = True
        self._output_dir = output_path
        self.diff_started.emit()
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.generate_report_btn.setEnabled(False)
        self.process_label.setText("Подготовка к сравнению...")
        self.process_progress.setValue(0)
        self.error_text.clear()

        self._worker = DiffWorker(pairs, idat_path, bindiff_path, output_path, max_workers=2)
        self._worker.progress_updated.connect(self._on_diff_progress)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.finished.connect(self._on_diff_finished)
        self._worker.start()

    def _cancel_comparison(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.process_label.setText("Отмена...")
            self.cancel_btn.setEnabled(False)

    def _on_diff_progress(self, current: int, total: int, message: str) -> None:
        self.process_label.setText(f"Сравнение: {current}/{total} {message}")
        self.process_progress.setValue(int(100 * current / total))

    def _on_error(self, message: str) -> None:
        self.error_text.append(message)

    def _on_diff_finished(self, success_count: int, total: int) -> None:
        self._diff_in_progress = False
        self.diff_finished.emit()
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.process_label.setText(f"Завершено. Успешно: {success_count}/{total}")
        self.process_progress.setValue(100)

        # Проверяем наличие .diff.json в выходной папке
        any_json = bool(list(self._output_dir.glob("*.diff.json"))) if self._output_dir else False
        self.generate_report_btn.setEnabled(any_json)
        self._worker = None

    def _generate_report(self) -> None:
        from ida_batch_tool.reporting.generator import DiffReportGenerator, _build_internal_set
        import logging
        logger = logging.getLogger(__name__)

        if not self._output_dir or not self._output_dir.is_dir():
            QMessageBox.warning(self, "Ошибка", "Выходная папка не существует.")
            return

        json_files = list(self._output_dir.glob("*.diff.json"))
        if not json_files:
            QMessageBox.warning(self, "Ошибка", "Нет JSON-файлов с результатами сравнения.")
            return

        reports_dir = self._output_dir / "Reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        gen = DiffReportGenerator()
        left_dir = Path(self.left_edit.text().strip())
        right_dir = Path(self.right_edit.text().strip())
        internal_set = _build_internal_set(left_dir).union(_build_internal_set(right_dir))

        logger.info(f"Генерация отчётов из {len(json_files)} JSON файлов в {reports_dir}")
        try:
            for jf in json_files:
                html_path = reports_dir / (jf.stem.replace(".diff", "") + ".html")
                logger.info(f"  {jf.name} -> {html_path}")
                gen.generate_from_json(
                    jf,
                    output_html=html_path,
                    reports_dir=reports_dir,
                    input_dir=left_dir,
                    internal_set=internal_set
                )
            # Генерация сводного индекса
            from datetime import datetime
            generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Попытка получить версию IDA из первого попавшегося .export.json в левой папке
            ida_version = ""
            export_jsons = list(left_dir.glob("*.export.json"))
            if export_jsons:
                try:
                    import json
                    with open(export_jsons[0], "r", encoding="utf-8") as f:
                        analysis_data = json.load(f)
                    ida_version = analysis_data.get("ida_info", {}).get("kernel_version", "")
                except Exception:
                    pass
            index_path = gen.generate_diff_index(
                reports_dir, json_files, left_dir, right_dir,
                generation_time=generation_time,
                ida_version=ida_version
            )
            QMessageBox.information(self, "Готово",
                                    f"Отчёты сохранены в {reports_dir}\nСводный индекс: {index_path}")
        except Exception as e:
            logger.exception("Ошибка генерации отчётов")
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать отчёты:\n{e}")