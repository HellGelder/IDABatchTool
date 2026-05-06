"""Менеджер тем оформления: светлая и тёмная."""
from PySide6.QtWidgets import QApplication

LIGHT_THEME = """
* {
    font-family: "Segoe UI", "San Francisco", "Helvetica Neue", sans-serif;
    font-size: 12px;
}
QMainWindow {
    background-color: #f5f5f5;
}
QWidget#central {
    background-color: #f5f5f5;
}
QWidget#sidebar {
    background-color: rgba(255, 255, 255, 0.95);
    border-right: 1px solid #c0c0c0;
}
QGroupBox {
    background-color: #ffffff;
    border-radius: 12px;
    margin: 10px;
    padding: 15px;
    border: 1px solid #d1d1d1;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 0 8px 0 8px;
    color: #303030;
    font-weight: 600;
    font-size: 13px;
}
QPushButton {
    background-color: #007aff;
    color: white;
    border-radius: 10px;
    padding: 10px 24px;
    font-weight: 500;
    font-size: 12px;
    border: none;
}
QPushButton:hover {
    background-color: #005bb5;
}
QPushButton:pressed {
    background-color: #00408b;
}
QPushButton:disabled {
    background-color: #b0b0b0;
}
QLineEdit, QSpinBox, QComboBox {
    background-color: #ffffff;
    border: 1px solid #c6c6c8;
    border-radius: 8px;
    padding: 8px;
    font-size: 12px;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1.5px solid #007aff;
    outline: none;
}
QComboBox QAbstractItemView {
    font-size: 12px;
    font-family: "Segoe UI", "San Francisco", "Helvetica Neue", sans-serif;
    background-color: #ffffff;
    border: 1px solid #c6c6c8;
    selection-background-color: #007aff;
    selection-color: white;
}
QProgressBar {
    border: none;
    border-radius: 8px;
    background-color: #e0e0e0;
    height: 10px;
    text-align: center;
    font-size: 10px;
    color: #303030;
}
QProgressBar::chunk {
    background-color: #007aff;
    border-radius: 8px;
}
QTextEdit, QPlainTextEdit {
    background-color: #ffffff;
    border: 1px solid #c6c6c8;
    border-radius: 8px;
    padding: 8px;
    font-size: 12px;
}
QTabWidget::pane {
    border: none;
    background: #f5f5f5;
}
QTabBar::tab {
    background: #e5e5ea;
    border-radius: 8px;
    padding: 8px 20px;
    margin-right: 4px;
    color: #303030;
}
QTabBar::tab:selected {
    background: #ffffff;
    border-bottom: 2px solid #007aff;
    color: #007aff;
}
QLabel {
    color: #303030;
}
"""

DARK_THEME = """
* {
    font-family: "Segoe UI", "San Francisco", "Helvetica Neue", sans-serif;
    font-size: 12px;
}
QMainWindow {
    background-color: #1c1c1e;
}
QWidget#central {
    background-color: #1c1c1e;
}
QWidget#sidebar {
    background-color: #2c2c2e;
    border-right: 1px solid #3a3a3c;
}
QGroupBox {
    background-color: #2c2c2e;
    border-radius: 12px;
    margin: 10px;
    padding: 15px;
    border: 1px solid #3a3a3c;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 0 8px 0 8px;
    color: #ffffff;
    font-weight: 600;
    font-size: 13px;
}
QPushButton {
    background-color: #0a84ff;
    color: white;
    border-radius: 10px;
    padding: 10px 24px;
    font-weight: 500;
    font-size: 12px;
    border: none;
}
QPushButton:hover {
    background-color: #409cff;
}
QPushButton:pressed {
    background-color: #0060c0;
}
QPushButton:disabled {
    background-color: #505050;
}
QCheckBox, QRadioButton {
    color: #ffffff;
}
QLineEdit, QSpinBox, QComboBox {
    background-color: #2c2c2e;
    border: 1px solid #48484a;
    border-radius: 8px;
    padding: 8px;
    font-size: 12px;
    color: #ffffff;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1.5px solid #0a84ff;
    outline: none;
}
QComboBox QAbstractItemView {
    font-size: 12px;
    font-family: "Segoe UI", "San Francisco", "Helvetica Neue", sans-serif;
    background-color: #2c2c2e;
    border: 1px solid #48484a;
    selection-background-color: #0a84ff;
    selection-color: white;
}
QProgressBar {
    border: none;
    border-radius: 8px;
    background-color: #3a3a3c;
    height: 10px;
    text-align: center;
    font-size: 10px;
    color: #ffffff;
}
QProgressBar::chunk {
    background-color: #0a84ff;
    border-radius: 8px;
}
QTextEdit, QPlainTextEdit {
    background-color: #2c2c2e;
    border: 1px solid #48484a;
    border-radius: 8px;
    padding: 8px;
    font-size: 12px;
    color: #ffffff;
}
QTabWidget::pane {
    border: none;
    background: #1c1c1e;
}
QTabBar::tab {
    background: #2c2c2e;
    border-radius: 8px;
    padding: 8px 20px;
    margin-right: 4px;
    color: #ffffff;
}
QTabBar::tab:selected {
    background: #3a3a3c;
    border-bottom: 2px solid #0a84ff;
    color: #0a84ff;
}
QLabel {
    color: #ffffff;
}
"""

def apply_theme(app: QApplication, theme: str = "light"):
    if theme == "dark":
        app.setStyleSheet(DARK_THEME)
    else:
        app.setStyleSheet(LIGHT_THEME)