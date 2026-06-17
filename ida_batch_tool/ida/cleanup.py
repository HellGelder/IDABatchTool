"""Функции для очистки временных файлов после анализа."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


def clean_directory(root_dir: str, patterns: Optional[List[str]] = None) -> None:
    """Рекурсивно удаляет файлы, соответствующие заданным шаблонам."""
    if patterns is None:
        patterns = ["*.asm", "*.log", "*.id0", "*.id1", "*.nam", "*.til"]
    root = Path(root_dir)
    if not root.is_dir():
        return
    removed = 0
    failed = 0
    for pattern in patterns:
        for file_path in root.rglob(pattern):
            try:
                file_path.unlink()
                removed += 1
            except OSError as e:
                failed += 1
                logger.warning(f"Не удалось удалить {file_path}: {e}")
    if removed or failed:
        logger.info(f"Cleanup в {root}: удалено {removed}, не удалось {failed}")
