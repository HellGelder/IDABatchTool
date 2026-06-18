import json
import shutil
import threading
from pathlib import Path
from typing import Set, Optional, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtCore import QThread, Signal

from ida_batch_tool.reporting.sfa_generator import SfaReportGenerator
from ida_batch_tool.ui.workers.results import SfaHtmlGenerationResult

# Путь к вендоренному marked.min.js
_MARKED_SRC = Path(__file__).resolve().parent.parent.parent / "reporting" / "templates" / "vendor" / "marked.min.js"


class SfaHtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
    finished = Signal(object)
    error_occurred = Signal(str)

    def __init__(self, json_files: dict, generator: SfaReportGenerator,
                 reports_dir: Path, input_dir: Path, delete_json: bool):
        super().__init__()
        self.json_files = json_files
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.delete_json = delete_json

    def run(self):
        # Копируем marked.min.js offline
        vendor_dir = self.reports_dir / "vendor"
        vendor_dir.mkdir(parents=True, exist_ok=True)
        marked_dst = vendor_dir / "marked.min.js"
        if _MARKED_SRC.is_file() and not marked_dst.exists():
            shutil.copy2(_MARKED_SRC, marked_dst)

        jobs: List[Path] = [p for p in self.json_files if p.exists()]
        total = len(jobs)
        if total == 0:
            self.finished.emit(SfaHtmlGenerationResult(
                generated_count=0, report_links=[], ida_info={},
                reports_dir=self.reports_dir, input_dir=self.input_dir,
                total_files=0, total_size_bytes=0,
            ))
            return

        # Жадный алгоритм: крупные файлы первыми
        jobs.sort(key=lambda p: p.stat().st_size, reverse=True)

        lock = threading.Lock()
        report_links: list = []
        ida_info: Dict[str, Any] = {}
        generated_count = 0
        total_files = 0
        total_size_bytes = 0
        completed = 0

        def process_one(json_path: Path):
            if not json_path.exists():
                return None
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                self.error_occurred.emit(f"Ошибка чтения {json_path.name}: {e}")
                return None

            local_ida = data.get("ida_info", {})

            original_file = Path(data["file_name"]).name
            source_full = Path(data["file_name"])
            if not source_full.is_absolute():
                source_full = self.input_dir / source_full
            try:
                rel = source_full.relative_to(self.input_dir)
            except ValueError:
                rel = Path(original_file)
            out_rel = rel.with_suffix(".sfa.html")
            output_html = self.reports_dir / out_rel
            output_html.parent.mkdir(parents=True, exist_ok=True)

            self.generator.generate_report_from_json(json_path, output_html, self.reports_dir)
            link = out_rel.as_posix()
            display = rel.as_posix()
            file_size = source_full.stat().st_size if source_full.exists() else 0
            file_exists = 1 if source_full.exists() else 0

            if self.delete_json:
                json_path.unlink(missing_ok=True)

            return (link, display, local_ida, file_exists, file_size)

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_path = {executor.submit(process_one, p): p for p in jobs}

            for future in as_completed(future_to_path):
                json_path = future_to_path[future]
                try:
                    result = future.result()
                except Exception as e:
                    self.error_occurred.emit(f"Ошибка генерации СФ для {json_path.name}: {e}")
                    result = None

                with lock:
                    completed += 1
                    if result is not None:
                        link, display, local_ida, f_exists, f_size = result
                        report_links.append({"filename": link, "display_name": display})
                        generated_count += 1
                        if local_ida and not ida_info:
                            ida_info = local_ida
                        total_files += f_exists
                        total_size_bytes += f_size

                self.progress_updated.emit(completed, total, "")

        # Сводный SFA index генерируется в main-потоке через _on_html_finished
        self.finished.emit(SfaHtmlGenerationResult(
            generated_count=generated_count,
            report_links=report_links,
            ida_info=ida_info,
            reports_dir=self.reports_dir,
            input_dir=self.input_dir,
            total_files=total_files,
            total_size_bytes=total_size_bytes,
        ))