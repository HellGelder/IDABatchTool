#!/usr/bin/env python3
"""Графический интерфейс для пакетного анализа IDA."""
import sys
import shutil
from pathlib import Path

from PySide6.QtWidgets import QApplication
from ida_batch_tool.ui.main_window import MainWindow


def clear_pycache_dirs(base: Path) -> tuple[int, int]:
    """Удаляет все папки __pycache__ в дереве base. Возвращает (удалено, ошибок)."""
    removed = 0
    failed = 0
    for pycache in base.rglob("__pycache__"):
        if pycache.is_dir():
            try:
                shutil.rmtree(pycache)
                removed += 1
            except OSError as e:
                print(f"Не удалось удалить {pycache}: {e}", file=sys.stderr)
                failed += 1
    return removed, failed


def clear_all_pycache() -> None:
    """Очищает кэш Python во всех подпапках проекта."""
    project_root = Path(__file__).resolve().parent
    base = project_root / "ida_batch_tool"
    if not base.is_dir():
        print(f"Папка проекта не найдена: {base}", file=sys.stderr)
        return

    removed, failed = clear_pycache_dirs(base)
    if removed or failed:
        print(f"Очистка кэша: удалено {removed}, ошибок {failed}", file=sys.stderr)


def main():
    # Очистка при запуске
    clear_all_pycache()

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    # Очистка при завершении
    app.aboutToQuit.connect(clear_all_pycache)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()