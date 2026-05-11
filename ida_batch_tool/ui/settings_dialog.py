"""Виджет страницы конфигурации."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QGroupBox, QMessageBox,
    QFileDialog
)
from PySide6.QtCore import Signal, Qt

from ida_batch_tool.config.loader import (
    load_config, save_config, get_ida_executable, get_bindiff_executable
)


class SettingsPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.cfg = load_config()
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

        # --- Тема ---
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

        main_layout.addWidget(ida_group)
        main_layout.addWidget(bindiff_group)
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
        self.save_btn.clicked.connect(self._save_settings)

        self.theme_light_btn.clicked.connect(lambda: self._switch_theme("light"))
        self.theme_dark_btn.clicked.connect(lambda: self._switch_theme("dark"))

    def _load_to_ui(self):
        ida = self.cfg.get("ida", {})
        self.idat_edit.setText(ida.get("executable", "idat"))

        bindiff = self.cfg.get("bindiff", {})
        self.bindiff_edit.setText(bindiff.get("executable", "bindiff"))

        theme = self.cfg.get("theme", "light")
        self.theme_light_btn.setChecked(theme == "light")
        self.theme_dark_btn.setChecked(theme == "dark")

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
        }
        try:
            save_config(new_cfg)
            self.cfg = new_cfg
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