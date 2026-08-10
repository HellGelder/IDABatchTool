import json
import threading
from pathlib import Path
from typing import Set, Optional, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtCore import QThread, Signal

from ida_batch_tool.database.sfa_function_index import SfaFunctionIndex
from ida_batch_tool.reporting.sfa_generator import SfaReportGenerator
from ida_batch_tool.ui.workers.results import SfaHtmlGenerationResult


class SfaHtmlGeneratorWorker(QThread):
    progress_updated = Signal(int, int, str)
    finished = Signal(object)
    error_occurred = Signal(str)

    def __init__(self, json_files: dict, generator: SfaReportGenerator,
                 reports_dir: Path, input_dir: Path, delete_json: bool,
                 reuse_cache: bool = False):
        super().__init__()
        self.json_files = json_files
        self.generator = generator
        self.reports_dir = reports_dir
        self.input_dir = input_dir
        self.delete_json = delete_json
        self.reuse_cache = reuse_cache

    def run(self):
        jobs: List[Path] = [p for p in self.json_files if p.exists() or self.reuse_cache]
        total = len(jobs)
        if total == 0:
            self.finished.emit(SfaHtmlGenerationResult(
                generated_count=0, report_links=[], ida_info={},
                reports_dir=self.reports_dir, input_dir=self.input_dir,
                total_files=0, total_size_bytes=0,
            ))
            return

        # ─── Фаза 1: предварительное сканирование — строим индекс ──────
        function_index_path = self.reports_dir / "sfa_function_index.db"
        if self.reuse_cache:
            # Переиспользуем существующий индекс и кэш — только перегенерация HTML
            function_index = None
            if function_index_path.exists():
                try:
                    function_index = SfaFunctionIndex(function_index_path)
                    function_index.open_readonly()
                except Exception:
                    pass
            total_system_modules = function_index.total_modules if function_index and function_index.available else 0
            total_system_functions = function_index.total_functions if function_index and function_index.available else 0
            self.progress_updated.emit(0, 0, "Перегенерация HTML из кэша…")
        else:
            self.progress_updated.emit(0, 0, "Сканирование системных функций…")
            try:
                function_index = SfaFunctionIndex.build_from_jsons(
                    jobs, function_index_path,
                    progress_callback=None,
                )
                total_system_modules = function_index.total_modules if function_index and function_index.available else 0
                total_system_functions = function_index.total_functions if function_index and function_index.available else 0
                self.progress_updated.emit(
                    0, 0,
                    f"Найдено {total_system_functions} системных функций. Генерация HTML…"
                )
            except Exception as e:
                self.error_occurred.emit(f"Ошибка сканирования системных функций: {e}")
                function_index = None
                total_system_modules = 0
                total_system_functions = 0

        # В reuse-режиме JSON нет — не сортируем по размеру
        if not self.reuse_cache:
            jobs.sort(key=lambda p: p.stat().st_size if p.exists() else 0, reverse=True)

        lock = threading.Lock()
        report_links: list = []
        ida_info: Dict[str, Any] = {}
        generated_count = 0
        total_files = 0
        total_size_bytes = 0
        completed = 0

        # Устанавливаем максимум прогресс-бара = количество файлов
        self.progress_updated.emit(0, total, "Генерация HTML…")

        def process_one(json_path: Path):
<<<<<<< HEAD
            # В reuse-режиме json_path может не существовать на диске
            if not self.reuse_cache and not json_path.exists():
=======
            if not json_path.exists():
>>>>>>> fa1ac88d9f6133793771fcd529b3a1bb8ec2c05f
                return None

            # Reuse-режим: импорты читаем из index БД, а не из JSON
            if self.reuse_cache and function_index and function_index.available:
                imports_data = function_index.get_file_imports(json_path)
                local_file_name = function_index.get_file_name(json_path)
                if not imports_data:
                    self.error_occurred.emit(f"Нет импортов в индексе для {json_path.name}")
                    return None
                local_ida = {}
            else:
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception as e:
                    self.error_occurred.emit(f"Ошибка чтения {json_path.name}: {e}")
                    return None
                imports_data = data.get("imports", [])
                local_file_name = data.get("file_name", "")
                local_ida = data.get("ida_info", {})

            original_file = Path(local_file_name).name
            source_full = Path(local_file_name)
            if not source_full.is_absolute():
                source_full = self.input_dir / source_full
            try:
                rel = source_full.relative_to(self.input_dir)
            except ValueError:
                rel = Path(original_file)
            out_rel = rel.with_suffix(".sfa.html")
            output_html = self.reports_dir / out_rel
            output_html.parent.mkdir(parents=True, exist_ok=True)
            display = rel.as_posix()
<<<<<<< HEAD
=======
            try:
                rel = source_full.relative_to(self.input_dir)
            except ValueError:
                rel = Path(original_file)
            out_rel = rel.with_suffix(".sfa.html")
            output_html = self.reports_dir / out_rel
            output_html.parent.mkdir(parents=True, exist_ok=True)
            display = rel.as_posix()
>>>>>>> fa1ac88d9f6133793771fcd529b3a1bb8ec2c05f

            def on_func_progress(func_name: str, func_idx: int, total_in_file: int):
                """Вызывается из generate_report_from_json для каждой функции.
                Не влияет на основной прогресс-бар (он по файлам).
                """
                self.progress_updated.emit(
                    completed, total,
                    f"{display} → {func_name} ({func_idx + 1}/{total_in_file})"
                )

            self.generator.generate_report_from_json(
                json_path, output_html, self.reports_dir,
                progress_callback=on_func_progress,
                function_index=function_index,
                reuse_cache=self.reuse_cache,
                imports=imports_data,
                file_name_hint=local_file_name,
            )
            link = out_rel.as_posix()
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

                if result is not None:
                    self.progress_updated.emit(completed, total, f"{result[1]} — готов")
                else:
                    self.progress_updated.emit(completed, total, f"{json_path.name} — ошибка")

        # Сортируем отчёты по пути
        report_links.sort(key=lambda r: r["display_name"])

        self.finished.emit(SfaHtmlGenerationResult(
            generated_count=generated_count,
            report_links=report_links,
            ida_info=ida_info,
            reports_dir=self.reports_dir,
            input_dir=self.input_dir,
            total_files=total_files,
            total_size_bytes=total_size_bytes,
            total_system_modules=total_system_modules,
            total_system_functions=total_system_functions,
        ))