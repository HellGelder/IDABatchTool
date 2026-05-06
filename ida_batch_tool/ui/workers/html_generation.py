"""Воркер генерации индивидуальных HTML-отчётов."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Dict, Any

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.reporting.generator import ReportGenerator


class HtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
    finished = Signal(int, list, set, set, dict, Path, Path)
    error_occurred = Signal(str)

    def __init__(self, results: dict, generator: ReportGenerator,
                 reports_dir: Path, input_dir: Path, delete_json: bool, parent=None):
        super().__init__(parent)
        self.results = results
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.delete_json = delete_json

    def run(self):
        report_links = []
        global_modules_set = set()
        global_elf_set = set()
        ida_info: Optional[Dict[str, Any]] = None
        generated_count = 0
        total = len(self.results)

        for i, (idb_path, success) in enumerate(self.results.items()):
            if not success:
                continue
            json_path = Path(str(idb_path) + ".export.json")
            if not json_path.exists():
                self.error_occurred.emit(f"JSON не найден: {json_path}")
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if ida_info is None and "ida_info" in data:
                    ida_info = data["ida_info"]

                is_elf = data.get("is_elf", False)

                # Сбор модулей и секций в зависимости от типа файла
                if is_elf:
                    # Для ELF: модули = needed_libs, секции = из импортов (начинаются с точки)
                    for needed in data.get("needed_libs", []):
                        global_modules_set.add(needed)
                    for imp in data.get("imports", []):
                        mod = imp.get("module", "")
                        if mod.startswith("."):
                            global_elf_set.add(mod)
                else:
                    # Для PE: модули из импортов, кроме секций
                    for imp in data.get("imports", []):
                        mod = imp.get("module")
                        if not mod or mod.lower() == "unknown":
                            continue
                        if mod.startswith("."):
                            global_elf_set.add(mod)
                        else:
                            global_modules_set.add(mod)

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
                self.generator.generate_from_json(json_path, output_html,
                                                  reports_dir=self.reports_dir,
                                                  input_dir=self.input_dir)
                link = out_rel.as_posix()
                display = rel.as_posix()
                report_links.append({"filename": link, "display_name": display})
                generated_count += 1
                if self.delete_json:
                    json_path.unlink(missing_ok=True)
            except Exception as e:
                self.error_occurred.emit(f"Ошибка генерации отчёта для {idb_path.name}: {e}")
            self.progress_updated.emit(i + 1, total, "")

        # Защита от None: передаём пустой словарь, если информация не собрана
        self.finished.emit(generated_count, report_links, global_modules_set,
                           global_elf_set, ida_info or {}, self.reports_dir, self.input_dir)