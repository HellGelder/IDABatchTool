"""Константы интерфейса."""
from enum import Enum
from pathlib import Path
from typing import Dict, List


class AnalysisStatus(Enum):
    NOT_ANALYZED = "not_analyzed"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    ERROR = "error"


PLATFORM_EXTENSIONS = {
    "Windows": {"label": "Windows", "exts": [".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi"]},
    "Linux / Android": {"label": "Linux / Android", "exts": [".elf", ".so", ".o", ".ko", ".dex"]},
    "macOS / iOS": {"label": "macOS / iOS", "exts": [".mach-o", ".dylib", ".bundle", ".app", ""]},
}
# Путь к папке scripts/ (на один уровень выше ui/)
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"