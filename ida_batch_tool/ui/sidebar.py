"""Боковая панель с кнопками навигации."""
from __future__ import annotations

from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QFrame, QSizePolicy
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QFont


class Sidebar(QWidget):
    navigate_requested = Signal(int)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(200)
        self._buttons: dict[int, QPushButton] = {}
        self._build_ui()
        self.apply_theme("light")

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 20, 10, 20)
        layout.setSpacing(6)

        title = QLabel("IDA Batch")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI Variable", 16, QFont.Weight.DemiBold))
        layout.addWidget(title)

        btn_analysis = self._create_button("Общий анализ", 0)
        btn_compare = self._create_button("Сравнение", 1)
        btn_sfa = self._create_button("Анализ СФ", 2)
        btn_settings = self._create_button("Конфигурация", 3)

        self._buttons[0] = btn_analysis
        self._buttons[1] = btn_compare
        self._buttons[2] = btn_sfa
        self._buttons[3] = btn_settings

        layout.addWidget(btn_analysis)
        layout.addWidget(btn_compare)
        layout.addWidget(btn_sfa)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(spacer)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(line)

        layout.addWidget(btn_settings)

    def _create_button(self, text: str, index: int) -> QPushButton:
        btn = QPushButton(f"  {text}")
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        btn.clicked.connect(lambda: self.navigate_requested.emit(index))
        return btn

    def set_active_button(self, index: int) -> None:
        for idx, btn in self._buttons.items():
            btn.setChecked(idx == index)

    def apply_theme(self, theme: str) -> None:
        base = """
            QPushButton {
                text-align: left;
                padding: 8px 12px;
                border-radius: 12px;
                font-weight: 500;
                border: none;
                font-family: "Segoe UI Variable", "Segoe UI", sans-serif;
            }
        """
        if theme == "dark":
            base += """
                QPushButton { color: #cccccc; background: transparent; }
                QPushButton:hover { background: #3a3a3c; }
                QPushButton:checked { background: #3a3a3c; color: #ffffff; }
            """
        else:
            base += """
                QPushButton { color: #505050; background: transparent; }
                QPushButton:hover { background: #f0f0f5; }
                QPushButton:checked { background: #e8e8ed; color: #000; }
            """
        self.setStyleSheet(base)