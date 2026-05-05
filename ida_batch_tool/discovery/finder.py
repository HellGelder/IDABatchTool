"""Поиск исполняемых файлов с фильтрацией по расширениям и сигнатурам."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

MZ_SIGNATURE = b'MZ'
ELF_SIGNATURE = b'\x7fELF'


def is_executable(file_path: Path) -> bool:
    """Проверяет, является ли файл исполняемым (PE или ELF) по сигнатуре."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
        if len(header) < 4:
            return False
        if header[:2] == MZ_SIGNATURE:
            return True
        if header[:4] == ELF_SIGNATURE:
            return True
    except (OSError, PermissionError):
        pass
    return False


def find_executables(
    root_dir: str,
    extensions: Optional[List[str]] = None,
    use_signatures: bool = False
) -> List[Path]:
    """
    Рекурсивно находит все исполняемые файлы в каталоге.
    extensions – список расширений с точкой (например ['.exe', '.dll']).
    Если не указан, при use_signatures=True проверяет сигнатуры, иначе берёт все файлы.
    """
    root = Path(root_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"{root_dir} is not a valid directory")

    matched: List[Path] = []
    for entry in root.rglob('*'):
        if not entry.is_file():
            continue
        if extensions:
            if entry.suffix.lower() in extensions:
                if use_signatures and not is_executable(entry):
                    continue
                matched.append(entry)
        else:
            if use_signatures:
                if is_executable(entry):
                    matched.append(entry)
            else:
                matched.append(entry)
    return matched


def default_filter() -> str:
    """Строка фильтра по умолчанию, аналогичная idahunt."""
    return ".exe,.dll,.elf,.so,.sys,.bin"