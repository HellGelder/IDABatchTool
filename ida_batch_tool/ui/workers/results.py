"""Контейнеры результатов фоновых воркеров HTML-генерации.

Используются вместо многоаргументных Qt-сигналов: один dataclass-объект
передаётся через ``Signal(object)``, что надёжнее и читаемее, чем 7-9
позиционных аргументов в сигнатуре сигнала.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set


@dataclass
class HtmlGenerationResult:
    """Результат работы HtmlGeneratorWorker (индивидуальные HTML-отчёты)."""
    generated_count: int
    report_links: List[Dict[str, str]]
    global_modules_set: Set[str]
    global_elf_set: Set[str]
    ida_info: Dict[str, Any]
    reports_dir: Path
    input_dir: Path
    total_files: int
    total_size_bytes: int


@dataclass
class SfaHtmlGenerationResult:
    """Результат работы SfaHtmlGeneratorWorker (HTML-отчёты системных функций)."""
    generated_count: int
    report_links: List[Dict[str, str]]
    ida_info: Dict[str, Any]
    reports_dir: Path
    input_dir: Path
    total_files: int
    total_size_bytes: int
