"""Воркер генерации индивидуальных HTML-отчётов."""
from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Set, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.reporting.generator import ReportGenerator
from ida_batch_tool.reporting.utils import normalize_display_name
from ida_batch_tool.ui.workers.results import HtmlGenerationResult

# Пути к вендоренным JS-библиотекам
_VENDOR_DIR = Path(__file__).resolve().parent.parent.parent / "reporting" / "templates" / "vendor"


class HtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
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
        return normalize_display_name(module_name)

    def run(self):
        # Копируем вендоренные JS-библиотеки в папку отчётов (offline)
        vendor_dst = self.reports_dir / "vendor"
        vendor_dst.mkdir(parents=True, exist_ok=True)
        # chart.umd.min.js пока не используется (pie удалён), но оставляем на будущее
        for fname in ():
            src = _VENDOR_DIR / fname
            dst = vendor_dst / fname
            if src.is_file() and not dst.exists():
                shutil.copy2(src, dst)

        # Собираем только реально существующие JSON
        jobs: List[Path] = [p for p, ok in self.json_files.items() if ok and p.exists()]
        total = len(jobs)
        if total == 0:
            self.finished.emit(HtmlGenerationResult(
                generated_count=0, report_links=[], global_modules_set=set(),
                global_elf_set=set(), ida_info={}, reports_dir=self.reports_dir,
                input_dir=self.input_dir, total_files=0, total_size_bytes=0,
            ))
            return

        # Жадный алгоритм: крупные JSON-файлы обрабатываем первыми
        jobs.sort(key=lambda p: p.stat().st_size, reverse=True)

        # Потокобезопасные агрегаты
        lock = threading.Lock()
        report_links: list = []
        global_modules_set: Set[str] = set()
        global_elf_set: Set[str] = set()
        ida_info: Optional[Dict[str, Any]] = None
        generated_count = 0
        total_files = 0
        total_size_bytes = 0
        completed = 0

        def process_one(json_path: Path):
            """Генерирует один отчёт. Возвращает кортеж с результатами или None."""
            if not json_path.exists():
                return None
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                self.error_occurred.emit(f"Ошибка чтения {json_path.name}: {e}")
                return None

            local_ida = data.get("ida_info") if "ida_info" in data else None

            modules = set()
            elf_sec = set()
            if data.get("is_elf") or data.get("is_macho"):
                for needed in data.get("needed_libs", []):
                    modules.add(self._normalize_display_name(needed))
                if data.get("is_elf"):
                    for imp in data.get("imports", []):
                        mod = imp.get("module", "")
                        if mod.startswith("."):
                            elf_sec.add(mod)
            else:
                for imp in data.get("imports", []):
                    mod = imp.get("module")
                    if not mod or mod.lower() == "unknown":
                        continue
                    if mod.startswith("."):
                        elf_sec.add(mod)
                    else:
                        modules.add(self._normalize_display_name(mod))

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

            file_size = source_full.stat().st_size if source_full.exists() else 0
            file_exists = 1 if source_full.exists() else 0

            if self.delete_json:
                json_path.unlink(missing_ok=True)

            return (link, display, modules, elf_sec, local_ida, file_exists, file_size)

        # Многопоточная генерация индивидуальных отчётов
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_path = {executor.submit(process_one, p): p for p in jobs}

            for future in as_completed(future_to_path):
                json_path = future_to_path[future]
                try:
                    result = future.result()
                except Exception as e:
                    self.error_occurred.emit(f"Ошибка генерации для {json_path.name}: {e}")
                    result = None

                with lock:
                    completed += 1
                    if result is not None:
                        link, display, modules, elf_sec, local_ida, f_exists, f_size = result
                        report_links.append({"filename": link, "display_name": display})
                        generated_count += 1
                        global_modules_set.update(modules)
                        global_elf_set.update(elf_sec)
                        if local_ida is not None and ida_info is None:
                            ida_info = local_ida
                        total_files += f_exists
                        total_size_bytes += f_size

                self.progress_updated.emit(completed, total, "")

        # Эмитим результат. Сводный index.html генерируется в main-потоке (analysis_page._on_html_finished)
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