"""Виджет страницы конфигурации."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QGroupBox, QMessageBox,
    QFileDialog, QLabel
)
from PySide6.QtCore import Signal, Qt

from ida_batch_tool.config.loader import (
    load_config, save_config, get_ida_executable, get_bindiff_executable, get_sf_db_path
)
from ida_batch_tool.database.win32_sync import Win32DatabaseSync


class SettingsPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.cfg = load_config()
        self.sync_thread: Win32DatabaseSync | None = None
        self._init_ui()
        self._load_to_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # --- Группа IDA ---
        ida_group = QGroupBox("Путь к IDA (idat)")
        ida_layout = QFormLayout(ida_group)
        ida_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        ida_layout.setSpacing(12)

        self.idat_edit = QLineEdit()
        self.idat_edit.setPlaceholderText("idat (или idat.exe на Windows)")
        self.browse_ida_btn = QPushButton("Обзор...")
        self.auto_ida_btn = QPushButton("Автопоиск")

        ida_hbox = QHBoxLayout()
        ida_hbox.addWidget(self.idat_edit, 1)
        ida_hbox.addWidget(self.browse_ida_btn)
        ida_hbox.addWidget(self.auto_ida_btn)
        ida_layout.addRow("Исполняемый файл:", ida_hbox)

        # --- Группа BinDiff ---
        bindiff_group = QGroupBox("Путь к BinDiff")
        bindiff_layout = QFormLayout(bindiff_group)
        bindiff_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        bindiff_layout.setSpacing(12)

        self.bindiff_edit = QLineEdit()
        self.bindiff_edit.setPlaceholderText("bindiff (или bindiff.exe на Windows)")
        self.browse_bindiff_btn = QPushButton("Обзор...")
        self.auto_bindiff_btn = QPushButton("Автопоиск")

        bindiff_hbox = QHBoxLayout()
        bindiff_hbox.addWidget(self.bindiff_edit, 1)
        bindiff_hbox.addWidget(self.browse_bindiff_btn)
        bindiff_hbox.addWidget(self.auto_bindiff_btn)
        bindiff_layout.addRow("Исполняемый файл:", bindiff_hbox)

        # --- Группа БД функций СФ ---
        sf_db_group = QGroupBox("База данных системных функций (СФ)")
        sf_db_layout = QFormLayout(sf_db_group)
        sf_db_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        sf_db_layout.setSpacing(12)

        self.sf_db_path_edit = QLineEdit()
        self.sf_db_path_edit.setPlaceholderText("Папка для хранения баз данных (по умолчанию: databases)")
        self.browse_sf_db_btn = QPushButton("Обзор...")
        self.sync_sf_db_btn = QPushButton("Синхронизация (Win32 API)")
        self.sf_db_status_label = QLabel("Статус: не синхронизировано")
        self.sf_db_status_label.setWordWrap(True)

        sf_db_hbox = QHBoxLayout()
        sf_db_hbox.addWidget(self.sf_db_path_edit, 1)
        sf_db_hbox.addWidget(self.browse_sf_db_btn)

        sf_db_layout.addRow("Папка для БД:", sf_db_hbox)
        sf_db_layout.addRow("", self.sync_sf_db_btn)
        sf_db_layout.addRow("", self.sf_db_status_label)

        # --- Группа темы ---
        theme_group = QGroupBox("Оформление")
        theme_layout = QFormLayout(theme_group)

        self.theme_light_btn = QPushButton("Светлая")
        self.theme_light_btn.setCheckable(True)
        self.theme_dark_btn = QPushButton("Тёмная")
        self.theme_dark_btn.setCheckable(True)

        theme_hbox = QHBoxLayout()
        theme_hbox.addWidget(self.theme_light_btn)
        theme_hbox.addWidget(self.theme_dark_btn)
        theme_layout.addRow("Тема:", theme_hbox)

        # Добавляем все группы
        main_layout.addWidget(ida_group)
        main_layout.addWidget(bindiff_group)
        main_layout.addWidget(sf_db_group)
        main_layout.addWidget(theme_group)

        # Кнопка сохранения
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.save_btn = QPushButton("Сохранить настройки")
        self.save_btn.setFixedWidth(200)
        btn_layout.addWidget(self.save_btn)
        main_layout.addLayout(btn_layout)
        main_layout.addStretch()

        # Сигналы
        self.browse_ida_btn.clicked.connect(self._browse_ida)
        self.auto_ida_btn.clicked.connect(self._autodetect_ida)
        self.browse_bindiff_btn.clicked.connect(self._browse_bindiff)
        self.auto_bindiff_btn.clicked.connect(self._autodetect_bindiff)
        self.browse_sf_db_btn.clicked.connect(self._browse_sf_db_dir)
        self.sync_sf_db_btn.clicked.connect(self._sync_win32_database)
        self.save_btn.clicked.connect(self._save_settings)

        self.theme_light_btn.clicked.connect(lambda: self._switch_theme("light"))
        self.theme_dark_btn.clicked.connect(lambda: self._switch_theme("dark"))

    def _load_to_ui(self):
        ida = self.cfg.get("ida", {})
        self.idat_edit.setText(ida.get("executable", "idat"))

        bindiff = self.cfg.get("bindiff", {})
        self.bindiff_edit.setText(bindiff.get("executable", "bindiff"))

        sf_db_path = self.cfg.get("sf_db_path", "databases")
        self.sf_db_path_edit.setText(sf_db_path)

        theme = self.cfg.get("theme", "light")
        self.theme_light_btn.setChecked(theme == "light")
        self.theme_dark_btn.setChecked(theme == "dark")

        # Проверяем наличие БД
        self._update_sf_db_status()

    def _update_sf_db_status(self):
        db_dir = self.sf_db_path_edit.text().strip()
        if db_dir:
            db_path = Path(db_dir) / "win32api.db"
            if db_path.exists():
                self.sf_db_status_label.setText(f"Статус: БД существует ({db_path})")
            else:
                self.sf_db_status_label.setText("Статус: БД не найдена. Нажмите «Синхронизация» для загрузки.")
        else:
            self.sf_db_status_label.setText("Статус: не указана папка для БД")

    def _switch_theme(self, theme: str):
        new_cfg = {**self.cfg, "theme": theme}
        save_config(new_cfg)
        self.cfg = new_cfg
        self.theme_light_btn.setChecked(theme == "light")
        self.theme_dark_btn.setChecked(theme == "dark")
        self.config_changed.emit(new_cfg)

    def _save_settings(self):
        new_cfg = {
            **self.cfg,
            "ida": {
                "executable": self.idat_edit.text().strip() or "idat"
            },
            "bindiff": {
                "executable": self.bindiff_edit.text().strip() or "bindiff"
            },
            "sf_db_path": self.sf_db_path_edit.text().strip() or "databases",
        }
        try:
            save_config(new_cfg)
            self.cfg = new_cfg
            QMessageBox.information(self, "Успех", "Настройки сохранены.")
            self._update_sf_db_status()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить конфиг:\n{e}")

    def _browse_ida(self):
        current = self.idat_edit.text()
        filter_str = "idat (idat.exe);;Все файлы (*)" if sys.platform == "win32" else "Все файлы (*)"
        path, _ = QFileDialog.getOpenFileName(
            self, "Укажите исполняемый файл IDA (idat)", current, filter_str
        )
        if path:
            self.idat_edit.setText(path)

    def _autodetect_ida(self):
        found = get_ida_executable()
        if not found or not Path(found).exists():
            QMessageBox.information(
                self, "Не найдено",
                "Не удалось автоматически найти idat.\nПроверьте PATH или укажите путь вручную."
            )
            return
        self.idat_edit.setText(found)
        QMessageBox.information(self, "Найдено", f"IDAT найден:\n{found}")

    def _browse_bindiff(self):
        current = self.bindiff_edit.text()
        if sys.platform == "win32":
            filter_str = "bindiff (bindiff.exe);;Все файлы (*)"
        else:
            filter_str = "Все файлы (*)"
        path, _ = QFileDialog.getOpenFileName(
            self, "Укажите исполняемый файл BinDiff", current, filter_str
        )
        if path:
            self.bindiff_edit.setText(path)

    def _autodetect_bindiff(self):
        found = get_bindiff_executable()
        if not found or not Path(found).exists():
            QMessageBox.information(
                self, "Не найдено",
                "Не удалось автоматически найти bindiff.\nПроверьте PATH или поместите файл в корень проекта."
            )
            return
        self.bindiff_edit.setText(found)
        QMessageBox.information(self, "Найдено", f"BinDiff найден:\n{found}")

    def _browse_sf_db_dir(self):
        current = self.sf_db_path_edit.text().strip()
        if not current:
            current = "."
        path = QFileDialog.getExistingDirectory(self, "Выберите папку для хранения БД системных функций", current)
        if path:
            self.sf_db_path_edit.setText(path)
            self._update_sf_db_status()

    def _sync_win32_database(self):
        db_dir = self.sf_db_path_edit.text().strip()
        if not db_dir:
            QMessageBox.warning(self, "Ошибка", "Укажите папку для хранения базы данных.")
            return

        # Проверяем, не выполняется ли уже синхронизация
        if self.sync_thread and self.sync_thread.isRunning():
            QMessageBox.warning(self, "Синхронизация", "Процесс синхронизации уже запущен.")
            return

        self.sync_sf_db_btn.setEnabled(False)
        self.sf_db_status_label.setText("Статус: синхронизация...")
        self.sync_thread = Win32DatabaseSync(db_dir)
        self.sync_thread.progress.connect(self._on_sync_progress)
        self.sync_thread.error.connect(self._on_sync_error)
        self.sync_thread.finished.connect(self._on_sync_finished)
        self.sync_thread.start()

    def _on_sync_progress(self, message: str, percent: int):
        self.sf_db_status_label.setText(f"Статус: {message} ({percent}%)")

    def _on_sync_error(self, error_msg: str):
        self.sync_sf_db_btn.setEnabled(True)
        self.sf_db_status_label.setText(f"Статус: ошибка - {error_msg}")
        QMessageBox.critical(self, "Ошибка синхронизации", error_msg)

    def _on_sync_finished(self, success: bool, result: str):
        self.sync_sf_db_btn.setEnabled(True)
        if success:
            self.sf_db_status_label.setText(f"Статус: синхронизировано (БД: {result})")
            QMessageBox.information(self, "Успех", f"База данных Win32 API успешно создана.\n{result}")
        else:
            self.sf_db_status_label.setText(f"Статус: ошибка - {result}")
            QMessageBox.critical(self, "Ошибка синхронизации", result)