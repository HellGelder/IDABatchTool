#!/usr/bin/env python3
"""Графический интерфейс для пакетного анализа IDA."""
import sys
import shutil
from pathlib import Path

from PySide6.QtWidgets import QApplication
from ida_batch_tool.ui.main_window import MainWindow


def clear_pycache():
    base = Path(__file__).resolve().parent / "ida_batch_tool"
    if base.is_dir():
        for pycache in base.rglob("__pycache__"):
            if pycache.is_dir():
                shutil.rmtree(pycache, ignore_errors=True)


def main():
    clear_pycache()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()