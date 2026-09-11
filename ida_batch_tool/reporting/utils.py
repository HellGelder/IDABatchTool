"""Вспомогательные функции для генерации отчётов."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from ida_batch_tool.discovery.finder import is_executable

# Папки результатов, которые не должны попадать в подсчёт размера исходников.
_OUTPUT_DIR_NAMES = frozenset({"SFAReports", "Reports", "AddDiffResults"})

# ELF e_type: ET_REL (1) — перемещаемый объектный файл, а не исполняемый модуль.
_ELF_ET_REL = 1


def _is_executable_image(path: Path) -> bool:
    """Проверяет, что файл — исполняемый образ (PE/ELF/Mach-O), а не объектный.

    Отличается от ``is_executable`` тем, что отклоняет перемещаемые ELF-объекты
    (``.o``), которые формально имеют сигнатуру ELF, но не являются модулями.
    """
    if not is_executable(path):
        return False
    try:
        with open(path, "rb") as f:
            header = f.read(18)
    except OSError:
        return False
    if header[:4] != b"\x7fELF":
        return True
    if len(header) >= 18:
        e_type = int.from_bytes(header[16:18], "little")
        if e_type == _ELF_ET_REL:
            return False
    return True


def compute_executables_size(
    root_dir: Path,
    extensions: Optional[Iterable[str]] = None,
) -> int:
    """Суммирует размер только исполняемых модулей в директории.

    Учитываются файлы с расширением целевой платформы, являющиеся
    исполняемыми образами (PE, ELF, Mach-O), а также файлы без расширения,
    распознанные по сигнатуре. Перемещаемые ELF-объекты (``.o``) и файлы
    с посторонними расширениями (``.dex``, ``.png`` и т.п.) не учитываются.
    Папки готовых отчётов исключаются.

    Args:
        root_dir: директория с исходными модулями.
        extensions: расширения выбранной платформы; ``None`` — все
            расширения из ``PLATFORM_EXTENSIONS``.

    Returns:
        Суммарный размер в байтах (0, если директории нет).
    """
    root = Path(root_dir)
    if not root.is_dir():
        return 0

    if extensions is None:
        from ida_batch_tool.ui.constants import PLATFORM_EXTENSIONS
        exts: set[str] = set()
        for info in PLATFORM_EXTENSIONS.values():
            exts.update(info["exts"])
    else:
        exts = set(extensions)
    exts.discard("")

    total = 0
    try:
        entries = list(root.rglob("*"))
    except OSError:
        return 0

    for path in entries:
        try:
            if not path.is_file():
                continue
            rel_parents = path.relative_to(root).parts[:-1]
        except (OSError, ValueError):
            continue
        if any(part in _OUTPUT_DIR_NAMES for part in rel_parents):
            continue

        ext = path.suffix.lower()
        # Файл с расширением учитывается только если расширение принадлежит
        # выбранной платформе; без расширения — по сигнатуре.
        if ext and ext not in exts:
            continue
        if not _is_executable_image(path):
            continue
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


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
