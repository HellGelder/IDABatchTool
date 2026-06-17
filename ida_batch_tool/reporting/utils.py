"""Вспомогательные функции для генерации отчётов."""
from __future__ import annotations

from pathlib import Path


def normalize_display_name(module_name: str) -> str:
    """Каноническая нормализация имени модуля для отображения в отчётах.

    Универсальная точка для всех генераторов: убирает путь, специфичные
    суффиксы платформ (.dylib, .framework), а также префикс ``@rpath/``.
    Не приводит к нижнему регистру (это задача классификатора).
    """
    if not module_name:
        return ""
    # Берём только имя файла из пути
    if '\\' in module_name or '/' in module_name:
        module_name = module_name.replace('\\', '/').split('/')[-1]
    if module_name.endswith('.dylib'):
        module_name = module_name[:-6]
    elif module_name.endswith('.framework'):
        module_name = module_name[:-10]
    elif '.dylib' in module_name:
        module_name = module_name.split('.dylib')[0]
    if module_name.startswith('@rpath/'):
        module_name = module_name[7:]
    return module_name


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
