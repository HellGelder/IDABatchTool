"""Виджет страницы конфигурации."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QGroupBox, QMessageBox,
    QFileDialog
)
from PySide6.QtCore import Signal, Qt

from ida_batch_tool.config.loader import load_config, save_config


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
        ida_group = QGroupBox("Пути к утилитам IDA")
        ida_layout = QFormLayout(ida_group)
        ida_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        ida_layout.setSpacing(12)

        self.idat64_edit = QLineEdit()
        self.browse_idat64_btn = QPushButton("Обзор...")
        hbox64 = QHBoxLayout()
        hbox64.addWidget(self.idat64_edit, 1)
        hbox64.addWidget(self.browse_idat64_btn)

        self.idat32_edit = QLineEdit()
        self.browse_idat32_btn = QPushButton("Обзор...")
        hbox32 = QHBoxLayout()
        hbox32.addWidget(self.idat32_edit, 1)
        hbox32.addWidget(self.browse_idat32_btn)

        ida_layout.addRow("idat64.exe:", hbox64)
        ida_layout.addRow("idat32.exe:", hbox32)

        # --- Тема ---
        theme_group = QGroupBox("Оформление")
        theme_layout = QFormLayout(theme_group)

        self.theme_light_btn = QPushButton("Светлая")
        self.theme_light_btn.setCheckable(True)
        self.theme_dark_btn = QPushButton("Тёмная")
        self.theme_dark_btn.setCheckable(True)

        hbox_theme = QHBoxLayout()
        hbox_theme.addWidget(self.theme_light_btn)
        hbox_theme.addWidget(self.theme_dark_btn)
        theme_layout.addRow("Тема:", hbox_theme)

        main_layout.addWidget(ida_group)
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
        self.browse_idat64_btn.clicked.connect(
            lambda: self._browse_file(self.idat64_edit, "idat64.exe"))
        self.browse_idat32_btn.clicked.connect(
            lambda: self._browse_file(self.idat32_edit, "idat32.exe"))
        self.save_btn.clicked.connect(self._save_settings)

        # Мгновенное переключение темы
        self.theme_light_btn.clicked.connect(lambda: self._switch_theme("light"))
        self.theme_dark_btn.clicked.connect(lambda: self._switch_theme("dark"))

    def _load_to_ui(self):
        ida = self.cfg.get("ida", {})
        self.idat64_edit.setText(ida.get("idat64", "idat64.exe"))
        self.idat32_edit.setText(ida.get("idat32", "idat32.exe"))
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
            "ida": {
                "idat64": self.idat64_edit.text().strip(),
                "idat32": self.idat32_edit.text().strip(),
            },
            "max_ida": self.cfg.get("max_ida", 4),
            "default_inputdir": self.cfg.get("default_inputdir", "."),
            "theme": self.cfg.get("theme", "light"),
        }
        try:
            save_config(new_cfg)
            self.cfg = new_cfg
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить конфиг:\n{e}")

    def _browse_file(self, lineedit: QLineEdit, filename_hint: str):
        path, _ = QFileDialog.getOpenFileName(
            self, f"Укажите {filename_hint}", lineedit.text(),
            "Исполняемые файлы (*.exe);;Все файлы (*.*)")
        if path:
            lineedit.setText(path)