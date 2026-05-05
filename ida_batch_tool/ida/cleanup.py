"""Функции для очистки временных файлов после анализа."""
from pathlib import Path
from typing import List, Optional


def clean_directory(root_dir: str, patterns: Optional[List[str]] = None) -> None:
    """Рекурсивно удаляет файлы, соответствующие заданным шаблонам."""
    if patterns is None:
        patterns = ["*.asm", "*.log", "*.id0", "*.id1", "*.nam", "*.til"]
    root = Path(root_dir)
    if not root.is_dir():
        return
    for pattern in patterns:
        for file_path in root.rglob(pattern):
            try:
                file_path.unlink()
            except OSError:
                pass