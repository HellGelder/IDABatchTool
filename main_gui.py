#!/usr/bin/env python3
"""Графический интерфейс для пакетного анализа IDA."""
import sys
from PySide6.QtWidgets import QApplication
from ida_batch_tool.ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()