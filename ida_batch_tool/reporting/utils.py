"""Вспомогательные функции для генерации отчётов."""
from pathlib import Path


def compute_back_link(report_rel_path: Path) -> str:
    """
    Вычисляет относительный путь к index.html из файла отчёта.
    Корректно обрабатывает отчёты, лежащие непосредственно в корне reports_dir.
    """
    parent = report_rel_path.parent
    # Если отчёт находится в корне reports_dir, parent будет '.' или ''.
    if parent == Path('.') or parent == Path(''):
        depth = 0
    else:
        # Глубина вложенности: количество директорий в относительном пути.
        depth = len(parent.parts)
    return ("../" * depth) + "index.html"