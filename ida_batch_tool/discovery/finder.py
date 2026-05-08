"""Поиск исполняемых файлов с фильтрацией по расширениям и сигнатурам."""
from __future__ import annotations

import struct
from pathlib import Path
from typing import List, Optional

MZ_SIGNATURE = b'MZ'
ELF_SIGNATURE = b'\x7fELF'
MACHO_MAGIC_32 = 0xfeedface
MACHO_MAGIC_64 = 0xfeedfacf
MACHO_MAGIC_FAT = 0xcafebabe
MACHO_MAGIC_32_LE = 0xcefaedfe
MACHO_MAGIC_64_LE = 0xcffaedfe


def is_macho(file_path: Path) -> bool:
    """Проверяет, является ли файл Mach-O по сигнатуре."""
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            magic_int = struct.unpack('<I', magic)[0]
            if magic_int in (MACHO_MAGIC_32, MACHO_MAGIC_64, MACHO_MAGIC_FAT,
                             MACHO_MAGIC_32_LE, MACHO_MAGIC_64_LE):
                return True
    except (OSError, PermissionError, struct.error):
        pass
    return False


def is_executable(file_path: Path) -> bool:
    """Проверяет, является ли файл исполняемым (PE, ELF или Mach-O) по сигнатуре."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
        if len(header) < 4:
            return False
        if header[:2] == MZ_SIGNATURE:
            return True
        if header[:4] == ELF_SIGNATURE:
            return True
        magic_int = struct.unpack('<I', header)[0]
        if magic_int in (MACHO_MAGIC_32, MACHO_MAGIC_64, MACHO_MAGIC_FAT,
                         MACHO_MAGIC_32_LE, MACHO_MAGIC_64_LE):
            return True
    except (OSError, PermissionError, struct.error):
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
    Файлы без расширения всегда проверяются по сигнатуре.
    """
    root = Path(root_dir)
    if not root.is_dir():
        raise NotADirectoryError(f"{root_dir} is not a valid directory")

    matched: List[Path] = []
    for entry in root.rglob('*'):
        if not entry.is_file():
            continue
        ext = entry.suffix.lower()
        if extensions:
            # Файлы без расширения – только если сигнатура подходит
            if ext == '':
                if is_executable(entry):
                    matched.append(entry)
                continue
            # Обычные расширения
            if ext in extensions:
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
    return ".exe,.dll,.elf,.so,.sys,.bin,.mach-o,.dylib,.bundle,.app"