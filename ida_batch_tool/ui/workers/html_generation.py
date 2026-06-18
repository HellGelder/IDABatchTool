"""Воркер генерации индивидуальных HTML-отчётов."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Dict, Any, Set

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.reporting.generator import ReportGenerator
from ida_batch_tool.reporting.utils import normalize_display_name
from ida_batch_tool.ui.workers.results import HtmlGenerationResult


class HtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
    # Один dataclass-объект вместо 9 позиционных аргументов
    finished = Signal(object)
    error_occurred = Signal(str)

    def __init__(self, json_files: Dict[Path, bool], generator: ReportGenerator,
                 reports_dir: Path, input_dir: Path, delete_json: bool,
                 internal_set: Optional[Set[str]] = None, parent=None):
        super().__init__(parent)
        self.json_files = json_files
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.delete_json = delete_json
        self.internal_set = internal_set

    @staticmethod
    def _normalize_display_name(module_name: str) -> str:
        # Делегируем канонической реализации из reporting.utils
        return normalize_display_name(module_name)

    def run(self):
        report_links = []
        global_modules_set = set()
        global_elf_set = set()
        ida_info: Optional[Dict[str, Any]] = None
        generated_count = 0
        total = len(self.json_files)
        total_files = 0
        total_size_bytes = 0

        for i, (json_path, success) in enumerate(self.json_files.items()):
            if not success:
                continue
            if not json_path.exists():
                self.error_occurred.emit(f"JSON не найден: {json_path}")
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if ida_info is None and "ida_info" in data:
                    ida_info = data["ida_info"]

                if data.get("is_elf") or data.get("is_macho"):
                    for needed in data.get("needed_libs", []):
                        global_modules_set.add(self._normalize_display_name(needed))
                    if data.get("is_elf"):
                        for imp in data.get("imports", []):
                            mod = imp.get("module", "")
                            if mod.startswith("."):
                                global_elf_set.add(mod)
                else:
                    for imp in data.get("imports", []):
                        mod = imp.get("module")
                        if not mod or mod.lower() == "unknown":
                            continue
                        if mod.startswith("."):
                            global_elf_set.add(mod)
                        else:
                            global_modules_set.add(self._normalize_display_name(mod))

                original_file = Path(data["file_name"]).name
                source_full = Path(data["file_name"])
                if not source_full.is_absolute():
                    source_full = self.input_dir / source_full
                try:
                    rel = source_full.relative_to(self.input_dir)
                except ValueError:
                    rel = Path(original_file)
                out_rel = rel.with_suffix(rel.suffix + ".html")
                output_html = self.reports_dir / out_rel
                output_html.parent.mkdir(parents=True, exist_ok=True)

                self.generator.generate_from_json(
                    json_path, output_html,
                    reports_dir=self.reports_dir,
                    input_dir=self.input_dir,
                    internal_set=self.internal_set
                )
                link = out_rel.as_posix()
                display = rel.as_posix()
                report_links.append({"filename": link, "display_name": display})
                generated_count += 1

                if source_full.exists():
                    total_files += 1
                    total_size_bytes += source_full.stat().st_size

                if self.delete_json:
                    json_path.unlink(missing_ok=True)
            except Exception as e:
                self.error_occurred.emit(f"Ошибка генерации отчёта для {json_path.name}: {e}")
            self.progress_updated.emit(i + 1, total, "")

        self.finished.emit(HtmlGenerationResult(
            generated_count=generated_count,
            report_links=report_links,
            global_modules_set=global_modules_set,
            global_elf_set=global_elf_set,
            ida_info=ida_info or {},
            reports_dir=self.reports_dir,
            input_dir=self.input_dir,
            total_files=total_files,
            total_size_bytes=total_size_bytes,
        ))