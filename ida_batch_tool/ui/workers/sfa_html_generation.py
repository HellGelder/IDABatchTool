import json
from pathlib import Path
from PySide6.QtCore import QThread, Signal

from ida_batch_tool.reporting.sfa_generator import SfaReportGenerator
from ida_batch_tool.ui.workers.results import SfaHtmlGenerationResult


class SfaHtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
    # Один dataclass-объект вместо 7 позиционных аргументов
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
        report_links = []
        generated_count = 0
        total = len(self.json_files)
        ida_info = {}
        total_files = 0
        total_size_bytes = 0

        for i, (json_path, _) in enumerate(self.json_files.items()):
            if not json_path.exists():
                self.error_occurred.emit(f"JSON не найден: {json_path}")
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not ida_info and "ida_info" in data:
                    ida_info = data["ida_info"]

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
                report_links.append({"filename": link, "display_name": display})
                generated_count += 1

                if source_full.exists():
                    total_files += 1
                    total_size_bytes += source_full.stat().st_size

                if self.delete_json:
                    json_path.unlink(missing_ok=True)
            except Exception as e:
                self.error_occurred.emit(f"Ошибка генерации отчёта СФ для {json_path.name}: {e}")
            self.progress_updated.emit(i + 1, total, "")

        self.finished.emit(SfaHtmlGenerationResult(
            generated_count=generated_count,
            report_links=report_links,
            ida_info=ida_info,
            reports_dir=self.reports_dir,
            input_dir=self.input_dir,
            total_files=total_files,
            total_size_bytes=total_size_bytes,
        ))