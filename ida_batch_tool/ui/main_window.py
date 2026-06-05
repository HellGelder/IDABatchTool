"""Главное окно приложения."""
from __future__ import annotations

from PySide6.QtWidgets import QMainWindow, QHBoxLayout, QStackedWidget, QWidget, QApplication
from PySide6.QtCore import Qt

from ida_batch_tool.ui.sidebar import Sidebar
from ida_batch_tool.ui.pages.analysis_page import AnalysisPage
from ida_batch_tool.ui.pages.difff_page import DiffPage
from ida_batch_tool.ui.pages.sfa_page import SfaPage
from ida_batch_tool.ui.pages.settings_dialog import SettingsPage
from ida_batch_tool.config.loader import load_config
from ida_batch_tool.ui.theme import apply_theme


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDA Batch Tool")
        self.resize(1200, 800)
        self.cfg = load_config()
        self.current_theme = self.cfg.get("theme", "light")
        self._build_ui()
        self._connect_signals()
        apply_theme(QApplication.instance(), self.current_theme)
        self.sidebar.set_active_button(0)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = Sidebar()
        self.pages = QStackedWidget()

        self.analysis_page = AnalysisPage()
        self.diff_page = DiffPage()
        self.sfa_page = SfaPage()
        self.settings_page = SettingsPage()

        self.pages.addWidget(self.analysis_page)   # 0
        self.pages.addWidget(self.diff_page)       # 1
        self.pages.addWidget(self.sfa_page)        # 2
        self.pages.addWidget(self.settings_page)   # 3

        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.pages, 1)

    def _connect_signals(self) -> None:
        self.sidebar.navigate_requested.connect(self.switch_page)
        self.settings_page.config_changed.connect(self._on_config_changed)

    def switch_page(self, index: int) -> None:
        # Блокировки во время работы
        if index != 0 and self.analysis_page.is_analysis_running():
            return
        if index != 1 and self.diff_page.is_diff_running():
            return
        if index != 2 and self.sfa_page.is_analysis_running():
            return
        self.pages.setCurrentIndex(index)
        self.sidebar.set_active_button(index)

    def _on_config_changed(self, new_config: dict) -> None:
        self.cfg = new_config
        new_theme = new_config.get("theme", "light")
        if new_theme != self.current_theme:
            self.current_theme = new_theme
            apply_theme(QApplication.instance(), new_theme)
            self.sidebar.apply_theme(new_theme)