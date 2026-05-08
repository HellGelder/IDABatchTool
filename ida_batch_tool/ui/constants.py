"""Константы интерфейса."""
from enum import Enum
from pathlib import Path
from typing import Dict, List


class AnalysisStatus(Enum):
    NOT_ANALYZED = "not_analyzed"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    ERROR = "error"


PLATFORM_EXTENSIONS: Dict[str, Dict[str, object]] = {
    "Windows": {"label": "Windows", "exts": [".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi"]},
    "Linux / Android": {"label": "Linux / Android", "exts": [".elf", ".so", ".o", ".ko", ".dex"]},
    "macOS / iOS": {"label": "macOS / iOS", "exts": [".mach-o", ".dylib", ".bundle", ".app", ""]},
    "All platforms": {"label": "Все платформы", "exts": [".exe", ".dll", ".sys", ".elf", ".so", ".o", ".mach-o", ".dylib", ".dex"]},
}

# Путь к папке scripts/ (на один уровень выше ui/)
# Путь к папке scripts/ (находится в корне проекта, рядом с ida_batch_tool)
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"