"""Виджет страницы сравнения директорий с помощью BinDiff + Diaphora."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, List, Tuple

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QProgressBar, QTextEdit, QGroupBox, QFileDialog,
    QLineEdit, QMessageBox, QCheckBox, QButtonGroup, QRadioButton,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import Signal, Qt

from ida_batch_tool.config.loader import get_ida_executable, get_bindiff_executable
from ida_batch_tool.ui.workers.diff_worker import DiffWorker, _safe_filename

import logging
logger = logging.getLogger(__name__)


class DiffPage(QWidget):
    """Страница для запуска сравнения двух директорий с BinDiff и генерации отчёта."""

    diff_started = Signal()
    diff_finished = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._diff_in_progress = False
        self._worker: Optional[DiffWorker] = None
        self._output_dir: Optional[Path] = None
        self._all_pairs: List[Tuple[Path, Path, str]] = []

        self._init_ui()

    def is_diff_running(self) -> bool:
        return self._diff_in_progress

    # ----------------------------------------------------------------
    # UI
    # ----------------------------------------------------------------
    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # ---------- Верхний ряд: директории + движок ----------
        top_row = QHBoxLayout()

        # --- Каталоги ---
        dir_group = QGroupBox("Директория для сравнения")
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

        out_layout = QHBoxLayout()
        out_layout.addWidget(QLabel("Папка результатов:"))
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Автоматически: DiffResults в левой папке")
        self.output_browse = QPushButton("Обзор...")
        out_layout.addWidget(self.output_edit, 1)
        out_layout.addWidget(self.output_browse)
        dir_layout.addLayout(out_layout)

        top_row.addWidget(dir_group, 3)

        # --- Движок сравнения ---
        engine_group = QGroupBox("Движок сравнения")
        engine_layout = QVBoxLayout(engine_group)
        self.engine_group = QButtonGroup(self)
        self.rb_bindiff = QRadioButton("Только BinDiff")
        self.rb_bindiff.setChecked(True)
        self.rb_diaphora = QRadioButton("Только Diaphora")
        self.rb_both = QRadioButton("Оба движка")
        self.engine_group.addButton(self.rb_bindiff, 1)
        self.engine_group.addButton(self.rb_diaphora, 2)
        self.engine_group.addButton(self.rb_both, 3)
        engine_layout.addWidget(self.rb_bindiff)
        engine_layout.addWidget(self.rb_diaphora)
        engine_layout.addWidget(self.rb_both)
        engine_layout.addStretch()

        top_row.addWidget(engine_group)
        main_layout.addLayout(top_row)

        # ---------- Таблица сопоставленных пар ----------
        map_group = QGroupBox("Сопоставленные пары (отметьте для сравнения)")
        map_layout = QVBoxLayout(map_group)

        self.pairs_table = QTableWidget(0, 6)
        self.pairs_table.setHorizontalHeaderLabels(
            ["", "Файл", "Размер", "Статус", "BinDiff", "Diaphora"]
        )
        self.pairs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.pairs_table.setColumnWidth(0, 30)
        self.pairs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.pairs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.pairs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.pairs_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.pairs_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.pairs_table.verticalHeader().setVisible(False)
        self.pairs_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.pairs_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pairs_table.setMinimumHeight(120)
        map_layout.addWidget(self.pairs_table, 1)

        self.map_status_label = QLabel("Укажите обе директории для анализа.")
        map_layout.addWidget(self.map_status_label)

        main_layout.addWidget(map_group, 1)

        # ---------- Прогресс выполнения ----------
        progress_group = QGroupBox("Прогресс выполнения")
        progress_layout = QVBoxLayout(progress_group)
        self.progress_label = QLabel("Прогресс выполнения: ожидание...")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        main_layout.addWidget(progress_group)

        # ---------- Кнопки управления ----------
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Запустить сравнение")
        self.start_btn.setFixedHeight(40)
        self.start_btn.setEnabled(False)
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

        main_layout.addLayout(btn_layout)

        # ---------- Ошибки ----------
        self.error_text = QTextEdit()
        self.error_text.setReadOnly(True)
        self.error_text.setMaximumHeight(60)
        self.error_text.setPlaceholderText("Здесь будут появляться сообщения об ошибках...")
        main_layout.addWidget(self.error_text)

        # Подключаем сигналы
        self.left_browse.clicked.connect(lambda: self._browse_dir(self.left_edit))
        self.right_browse.clicked.connect(lambda: self._browse_dir(self.right_edit))
        self.output_browse.clicked.connect(self._browse_output_dir)
        self.start_btn.clicked.connect(self._start_comparison)
        self.cancel_btn.clicked.connect(self._cancel_comparison)
        self.generate_report_btn.clicked.connect(self._generate_report)

        self.left_edit.textChanged.connect(self._analyze_directories)
        self.right_edit.textChanged.connect(self._analyze_directories)

        self._analyze_directories()

    # ----------------------------------------------------------------
    # Вспомогательные методы UI
    # ----------------------------------------------------------------
    def _browse_dir(self, line_edit: QLineEdit) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if path:
            line_edit.setText(path)

    def _browse_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для результатов")
        if path:
            self.output_edit.setText(path)

    # ----------------------------------------------------------------
    # Анализ директорий и заполнение таблицы пар
    # ----------------------------------------------------------------
    def _analyze_directories(self) -> None:
        left_dir = self.left_edit.text().strip()
        right_dir = self.right_edit.text().strip()

        self.pairs_table.setRowCount(0)
        self._all_pairs.clear()

        if not left_dir or not os.path.isdir(left_dir) or not right_dir or not os.path.isdir(right_dir):
            self.map_status_label.setText("Укажите обе директории для анализа.")
            self.start_btn.setEnabled(False)
            return

        left_roots = list(Path(left_dir).rglob("*.i64"))
        right_roots = list(Path(right_dir).rglob("*.i64"))

        left_map = {}
        for p in left_roots:
            rel = p.relative_to(Path(left_dir))
            left_map[str(rel)] = p

        right_map = {}
        for p in right_roots:
            rel = p.relative_to(Path(right_dir))
            right_map[str(rel)] = p

        left_rel_set = set(left_map.keys())
        right_rel_set = set(right_map.keys())
        common = sorted(left_rel_set & right_rel_set)
        only_left = left_rel_set - right_rel_set
        only_right = right_rel_set - left_rel_set

        self._all_pairs = []
        self.pairs_table.setRowCount(len(common) + 1)  # +1 для мастер-строки

        # Строка 0: мастер-чекбокс
        master_cb = QCheckBox()
        master_cb.setChecked(True)
        master_cb.stateChanged.connect(self._on_header_checkbox_changed)
        master_widget = QWidget()
        master_cb_layout = QHBoxLayout(master_widget)
        master_cb_layout.addWidget(master_cb)
        master_cb_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        master_cb_layout.setContentsMargins(0, 0, 0, 0)
        self.pairs_table.setCellWidget(0, 0, master_widget)

        master_name = QTableWidgetItem("Все пары")
        master_name.setFlags(master_name.flags() & ~Qt.ItemFlag.ItemIsEditable)
        font = master_name.font()
        font.setBold(True)
        master_name.setFont(font)
        self.pairs_table.setItem(0, 1, master_name)
        self.pairs_table.setItem(0, 2, QTableWidgetItem(""))
        self.pairs_table.setItem(0, 3, QTableWidgetItem(""))
        self.pairs_table.setItem(0, 4, QTableWidgetItem(""))
        self.pairs_table.setItem(0, 5, QTableWidgetItem(""))

        for row, rel in enumerate(common, start=1):
            left_path = left_map[rel]
            right_path = right_map[rel]

            # Чекбокс
            cb = QCheckBox()
            cb.setChecked(True)
            cb.stateChanged.connect(self._on_checkbox_changed)
            cb_widget = QWidget()
            cb_layout = QHBoxLayout(cb_widget)
            cb_layout.addWidget(cb)
            cb_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cb_layout.setContentsMargins(0, 0, 0, 0)
            self.pairs_table.setCellWidget(row, 0, cb_widget)

            # Имя
            name_item = QTableWidgetItem(rel)
            name_item.setToolTip(f"{left_path}\n{right_path}")
            self.pairs_table.setItem(row, 1, name_item)

            # Размер
            try:
                size = left_path.stat().st_size
                size_str = f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
            except OSError:
                size_str = "?"
            self.pairs_table.setItem(row, 2, QTableWidgetItem(size_str))

            # Статус (есть ли готовый diff.json)
            stem = _safe_filename(rel)
            diff_json = (Path(self.output_edit.text().strip() or Path(left_dir) / "DiffResults") / f"{stem}.diff.json")
            status = "✅ Есть" if diff_json.is_file() else "—"
            self.pairs_table.setItem(row, 3, QTableWidgetItem(status))

            # BinDiff/Diaphora колонки — по умолчанию прочерк
            self.pairs_table.setItem(row, 4, QTableWidgetItem("—"))
            self.pairs_table.setItem(row, 5, QTableWidgetItem("—"))

            self._all_pairs.append((left_path, right_path, rel))

        # Статусная строка
        if common:
            selected = sum(1 for i in range(1, self.pairs_table.rowCount())
                          if self.pairs_table.cellWidget(i, 0).findChild(QCheckBox).isChecked())
            msg = f"✅ {len(common)} пар сопоставлено, выбрано: {selected}"
            if only_left:
                msg += f" (+{len(only_left)} только слева)"
            if only_right:
                msg += f" (+{len(only_right)} только справа)"
            self.map_status_label.setText(msg)
            self.start_btn.setEnabled(selected > 0)
        else:
            msg = f"❌ Нет совпадений: {len(left_rel_set)} слева, {len(right_rel_set)} справа."
            self.start_btn.setEnabled(False)
            self.map_status_label.setText(msg)

    def _on_checkbox_changed(self) -> None:
        self._update_selected_count()

    def _update_selected_count(self) -> None:
        total = self.pairs_table.rowCount() - 1
        selected = sum(
            1 for i in range(1, self.pairs_table.rowCount())
            if self.pairs_table.cellWidget(i, 0).findChild(QCheckBox).isChecked()
        )
        self.start_btn.setEnabled(selected > 0)
        current_text = self.map_status_label.text()
        base = re.sub(r', выбрано: \d+', '', current_text).rstrip()
        self.map_status_label.setText(f"{base}, выбрано: {selected}")

    def _set_all_checkboxes(self, checked: bool) -> None:
        for i in range(1, self.pairs_table.rowCount()):
            cb_widget = self.pairs_table.cellWidget(i, 0)
            if cb_widget:
                cb = cb_widget.findChild(QCheckBox)
                if cb:
                    cb.blockSignals(True)
                    cb.setChecked(checked)
                    cb.blockSignals(False)
        self._update_selected_count()

    def _on_header_checkbox_changed(self, state: int) -> None:
        self._set_all_checkboxes(bool(state))

    # ----------------------------------------------------------------
    # Логика сравнения
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

        # Собираем выбранные пары
        selected_pairs = []
        for row in range(1, self.pairs_table.rowCount()):
            cb = self.pairs_table.cellWidget(row, 0).findChild(QCheckBox)
            if cb and cb.isChecked():
                selected_pairs.append(self._all_pairs[row - 1])

        if not selected_pairs:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одной пары для сравнения.")
            return

        output_dir = self.output_edit.text().strip()
        if output_dir:
            output_path = Path(output_dir)
        else:
            output_path = Path(left_dir) / "DiffResults"
        output_path.mkdir(parents=True, exist_ok=True)

        # Папка для доанализа Diaphora (только для engine=bindiff)
        engine = self._get_engine()
        add_output_path = None
        if engine == "bindiff":
            add_output_path = output_path.parent / "AddDiffResults"
            add_output_path.mkdir(parents=True, exist_ok=True)

        idat_path = get_ida_executable()
        if not Path(idat_path).is_file():
            QMessageBox.warning(self, "IDA не найдена",
                f"Исполняемый файл '{idat_path}' не найден.\nПроверьте настройки (config.yaml).")
            return

        bindiff_path = get_bindiff_executable()
        if engine in ("bindiff", "both") and not Path(bindiff_path).is_file():
            QMessageBox.warning(
                self, "Утилита BinDiff не найдена",
                f"Исполняемый файл '{bindiff_path}' не найден.\n"
                "Поместите bindiff.exe в корень проекта или укажите путь в config.yaml."
            )
            return

        pairs = selected_pairs
        existing_stems = set()
        new_pairs = []
        for primary, secondary, rel in pairs:
            stem = _safe_filename(rel)
            diff_json = output_path / f"{stem}.diff.json"
            if diff_json.is_file():
                existing_stems.add(stem)
            else:
                new_pairs.append((primary, secondary, rel))

        if existing_stems:
            msg = (f"В выходной папке уже найдены результаты сравнения для {len(existing_stems)} пар.\n\n"
                   "Нажмите «Да», чтобы досравнять только новые пары.\n"
                   "Нажмите «Нет», чтобы выполнить полное сравнение заново.\n"
                   "Нажмите «Отмена» для отмены.")
            reply = QMessageBox.question(self, "Обнаружены существующие результаты", msg,
                                          QMessageBox.StandardButton.Yes
                                          | QMessageBox.StandardButton.No
                                          | QMessageBox.StandardButton.Cancel)
            if reply == QMessageBox.StandardButton.Yes:
                pairs = new_pairs if new_pairs else []
                if not pairs:
                    QMessageBox.information(self, "Готово", "Все пары уже обработаны. Сравнение не требуется.")
                    return
            elif reply == QMessageBox.StandardButton.No:
                for p in output_path.glob("*.diff.json"):
                    p.unlink(missing_ok=True)
            else:
                return

        self._diff_in_progress = True
        self._output_dir = output_path
        self.diff_started.emit()
        self.start_btn.setEnabled(False)

        # Единый прогресс: фаз = экспорт (1 или 2) + пост-анализ + HTML
        use_bindiff = engine in ("bindiff", "both")
        use_diaphora = engine in ("diaphora", "both")
        total_steps = len(pairs) * (2 + int(use_bindiff) + int(use_diaphora))
        self.progress_bar.setRange(0, total_steps)
        self.progress_bar.setValue(0)
        self.progress_label.setText(f"Прогресс выполнения: 0 / {total_steps}")

        # Очищаем колонки статусов BinDiff / Diaphora
        for row in range(1, self.pairs_table.rowCount()):
            # BinDiff: всегда есть для engine=bindiff/both, прочерк для diaphora
            bd_status = "" if engine in ("bindiff", "both") else "—"
            self.pairs_table.setItem(row, 4, QTableWidgetItem(bd_status))
            # Diaphora: прочерк для bindiff (обновится доанализом), иначе пусто
            dp_status = "—" if engine == "bindiff" else ("" if engine in ("diaphora", "both") else "—")
            self.pairs_table.setItem(row, 5, QTableWidgetItem(dp_status))

        self.error_text.clear()

        self._worker = DiffWorker(pairs, idat_path, bindiff_path, output_path,
                                   engine=engine, left_dir=left_dir, right_dir=right_dir,
                                   add_output_dir=add_output_path)
        self._worker.stage_updated.connect(self._on_stage_updated)
        self._worker.global_progress_updated.connect(self._on_global_progress)
        self._worker.pair_status_updated.connect(self._on_pair_status)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.finished.connect(self._on_diff_finished)
        self.cancel_btn.setEnabled(True)
        self._worker.start()

    def _get_engine(self) -> str:
        if self.rb_diaphora.isChecked():
            return "diaphora"
        elif self.rb_both.isChecked():
            return "both"
        return "bindiff"

    def _cancel_comparison(self) -> None:
        if self._worker:
            self._worker.cancel()
            self.progress_label.setText("Прогресс выполнения: отменён")
            self.cancel_btn.setEnabled(False)

    # ----------------------------------------------------------------
    # Обработчики сигналов воркера
    # ----------------------------------------------------------------
    def _on_global_progress(self, step: int, total_steps: int, desc: str) -> None:
        self.progress_bar.setValue(step)
        self.progress_label.setText(f"Прогресс выполнения: {step} / {total_steps} — {desc}")

    def _on_pair_status(self, rel_key: str, engine: str, status: str) -> None:
        """Обновляет колонку BinDiff (4) или Diaphora (5) для строки с rel_key."""
        col = 4 if engine == "bindiff" else 5
        for row in range(1, self.pairs_table.rowCount()):
            item = self.pairs_table.item(row, 1)
            if item and item.text() == rel_key:
                self.pairs_table.setItem(row, col, QTableWidgetItem(status))
                break

    def _on_stage_updated(self, stage_name: str, current: int, total: int,
                           file_stem: str, substage: str) -> None:
        """Сохраняем для обратной совместимости — используется _on_global_progress."""
        pass

    def _on_error(self, message: str) -> None:
        self.error_text.append(message)

    def _on_diff_finished(self, success_count: int, total: int) -> None:
        self._diff_in_progress = False
        self.diff_finished.emit()
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_label.setText(f"Прогресс выполнения: завершён ({success_count}/{total})")

        # Обновляем статусы в таблице
        self._analyze_directories()

        # Отчёты: основной (DiffResults)
        reports_dir = self._output_dir / "Reports"
        index_html = reports_dir / "index.html"

        # Отчёты: доанализ (AddDiffResults)
        add_reports_dir = None
        add_index_html = None
        if self._output_dir:
            add_dir = self._output_dir.parent / "AddDiffResults"
            add_reports_dir = add_dir / "Reports"
            add_index_html = add_reports_dir / "index.html"

        has_main_reports = index_html.is_file()
        has_add_reports = add_index_html and add_index_html.is_file()

        if has_main_reports or has_add_reports:
            self.generate_report_btn.setEnabled(True)
            from PySide6.QtWidgets import QMessageBox
            msg_lines = []
            if has_main_reports:
                msg_lines.append(f"Основные отчёты: {reports_dir}")
            if has_add_reports:
                msg_lines.append(f"Доанализ (Diaphora): {add_reports_dir}")
            msg = QMessageBox()
            msg.setWindowTitle("Сравнение завершено")
            msg.setText(f"Все этапы завершены.\n" + "\n".join(msg_lines))
            msg.setInformativeText(f"Открыть основной сводный отчёт?")
            msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            msg.setDefaultButton(QMessageBox.StandardButton.Yes)
            if msg.exec() == QMessageBox.StandardButton.Yes:
                import subprocess
                target = str(index_html) if has_main_reports else str(add_index_html)
                subprocess.Popen(["start", "", target], shell=True)
        else:
            any_json = bool(list(self._output_dir.glob("*.diff.json"))) if self._output_dir else False
            self.generate_report_btn.setEnabled(any_json)

        self._worker = None

    def _generate_report(self) -> None:
        from ida_batch_tool.reporting.generator import DiffReportGenerator, _build_internal_set

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
            from datetime import datetime
            generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                f"Отчёт сгенерирован:\n{index_path}")
            import subprocess
            subprocess.Popen(["start", "", str(index_path)], shell=True)
        except Exception as e:
            logger.exception("Ошибка генерации отчёта")
            QMessageBox.critical(self, "Ошибка", f"Не удалось сгенерировать отчёт:\n{e}")
