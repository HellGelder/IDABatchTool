"""Вспомогательные функции для генерации отчётов."""
from pathlib import Path


def compute_back_link(report_rel_path: Path) -> str:
    """Вычисляет относительный путь к index.html из файла отчёта."""
    depth = len(report_rel_path.parent.parts)
    return ("../" * depth) + "index.html"