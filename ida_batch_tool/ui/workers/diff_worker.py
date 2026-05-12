# ida_batch_tool/ui/workers/diff_worker.py
"""Фоновый поток для параллельного сравнения BinDiff. Экспорт через -OBinExportAutoAction."""
from __future__ import annotations

import logging
import sqlite3
import json
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ida.runner import IDAAnalyzer
from ida_batch_tool.ui.constants import SCRIPTS_DIR

logger = logging.getLogger(__name__)


class DiffWorker(QThread):
    progress_updated = Signal(int, int, str)
    finished = Signal(int, int)          # (success_count, total_pairs)
    error_occurred = Signal(str)

    def __init__(self, file_pairs: List[Tuple[Path, Path]],
                 idat_path: str, bindiff_path: str,
                 output_dir: Path,
                 max_workers: int = 2, parent=None):
        super().__init__(parent)
        self.file_pairs = file_pairs
        self.idat_path = idat_path
        self.bindiff_path = bindiff_path
        self.output_dir = output_dir
        self.max_workers = max_workers
        self._cancel_event = threading.Event()
        self._completed_count = 0
        self._lock = threading.Lock()

    def cancel(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        total = len(self.file_pairs)
        if total == 0:
            self.finished.emit(0, 0)
            return

        logger.info(f"Сравнение {total} пар, параллельно до {self.max_workers}, результаты в {self.output_dir}")

        # Проверяем плагин один раз в начале
        if not self._verify_binexport():
            self.finished.emit(0, total)
            return

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_pair = {
                executor.submit(self._process_pair, primary, secondary, idx): (primary, secondary, idx)
                for idx, (primary, secondary) in enumerate(self.file_pairs)
            }

            for future in as_completed(future_to_pair):
                if self._cancel_event.is_set():
                    for f in future_to_pair:
                        f.cancel()
                    break
                primary, secondary, idx = future_to_pair[future]
                try:
                    success = future.result()
                    with self._lock:
                        self._completed_count += 1
                        if success:
                            self.progress_updated.emit(self._completed_count, total, primary.stem)
                except Exception as e:
                    logger.exception(f"Исключение в паре {primary.stem}")
                    self.error_occurred.emit(f"Ошибка пары {primary.stem}: {e}")
                    with self._lock:
                        self._completed_count += 1

        logger.info(f"Завершено. Всего обработано: {self._completed_count}")
        self.finished.emit(self._completed_count, total)

    def _process_pair(self, primary_i64: Path, secondary_i64: Path, idx: int) -> bool:
        stem = primary_i64.stem
        if self._cancel_event.is_set():
            return False

        try:
            # 1. Экспорт первичной базы
            primary_binexport = self.output_dir / f"{stem}_primary.BinExport"
            if not self._export_binexport(primary_i64, primary_binexport):
                # ошибка уже отправлена через error_occurred в _export_binexport
                return False

            # 2. Экспорт вторичной базы
            secondary_binexport = self.output_dir / f"{stem}_secondary.BinExport"
            if not self._export_binexport(secondary_i64, secondary_binexport):
                return False

            # 3. Сравнение
            diff_output = self.output_dir / f"{stem}.BinDiff"
            if not self._run_bindiff(primary_binexport, secondary_binexport, diff_output):
                self.error_occurred.emit(f"Ошибка сравнения {stem}")
                return False

            # 4. Парсинг
            json_output = self.output_dir / f"{stem}.diff.json"
            self._parse_bindiff_result(diff_output, str(primary_i64), str(secondary_i64), json_output)
            return True
        except Exception as e:
            logger.exception(f"Ошибка при обработке {stem}: {e}")
            self.error_occurred.emit(f"Ошибка {stem}: {e}")
            return False

    def _export_binexport(self, i64_path: Path, output_file: Path) -> bool:
        """Экспорт через опции IDA -OBinExportAutoAction и -OBinExportModule."""
        if self._cancel_event.is_set():
            return False

        output_file.unlink(missing_ok=True)

        cmd = [
            self.idat_path,
            "-A",
            "-OBinExportAutoAction:BinExportBinary",
            f"-OBinExportModule:{output_file}",
            str(i64_path)
        ]
        logger.info(f"Экспорт BinExport: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                logger.error(f"Экспорт завершился с ошибкой (код {proc.returncode}): {proc.stderr.strip()}")
                return False

            if not output_file.is_file():
                logger.error(f"Файл {output_file} не создан после экспорта")
                return False

            logger.info(f"BinExport создан: {output_file}")
            return True
        except Exception as e:
            logger.exception(f"Ошибка при экспорте BinExport: {e}")
            return False

    def _run_bindiff(self, primary: Path, secondary: Path, output: Path) -> bool:
        """Запускает bindiff.exe во временной изолированной папке, затем переносит результат."""
        tmp_dir = output.parent / f"{output.stem}_tmp"
        shutil.rmtree(tmp_dir, ignore_errors=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.bindiff_path,
            "--primary", str(primary),
            "--secondary", str(secondary),
            "--output_dir", str(tmp_dir)
        ]
        logger.info(f"BinDiff: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                logger.error(f"BinDiff ошибка: {proc.stderr.strip()}")
                return False

            diff_files = list(tmp_dir.glob("*.BinDiff"))
            if not diff_files:
                logger.error("Не найден .BinDiff файл после сравнения")
                return False

            result_file = diff_files[0]
            output.unlink(missing_ok=True)
            shutil.move(str(result_file), str(output))
            logger.info(f"Результат BinDiff сохранён как {output}")
            return True
        except Exception as e:
            logger.exception(f"Ошибка BinDiff: {e}")
            return False
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _parse_bindiff_result(self, db_path: Path, primary: str, secondary: str,
                              json_output: Path) -> None:
        """Читает SQLite .BinDiff и сохраняет JSON с совпадениями."""
        result = {
            "primary": primary,
            "secondary": secondary,
            "similarity": 0.0,
            "confidence": 0.0,
            "description": "",
            "version": "",
            "created": "",
            "modified": "",
            "file1": {},
            "file2": {},
            "matched_functions": [],
            "total_functions1": 0,
            "total_functions2": 0,
            "error": None
        }

        try:
            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()

            # Метаданные
            cur.execute("SELECT * FROM metadata")
            meta_row = cur.fetchone()
            if meta_row:
                meta_cols = [desc[0] for desc in cur.description]
                meta = dict(zip(meta_cols, meta_row))
                result["similarity"] = float(meta.get("similarity", 0.0))
                result["confidence"] = float(meta.get("confidence", 0.0))
                result["description"] = meta.get("description", "")
                result["version"] = meta.get("version", "")
                result["created"] = str(meta.get("created", ""))
                result["modified"] = str(meta.get("modified", ""))

            # Информация о файлах (две строки)
            cur.execute("SELECT * FROM file ORDER BY id")
            file_rows = cur.fetchall()
            if len(file_rows) >= 2:
                file_cols = [desc[0] for desc in cur.description]
                file1 = dict(zip(file_cols, file_rows[0]))
                file2 = dict(zip(file_cols, file_rows[1]))
                for f_dict, key in [(file1, "file1"), (file2, "file2")]:
                    result[key] = {
                        "filename": f_dict.get("filename", ""),
                        "exefilename": f_dict.get("exefilename", ""),
                        "hash": f_dict.get("hash", ""),
                        "functions": int(f_dict.get("functions", 0)),
                        "libfunctions": int(f_dict.get("libfunctions", 0)),
                        "calls": int(f_dict.get("calls", 0)),
                        "basicblocks": int(f_dict.get("basicblocks", 0)),
                        "libbasicblocks": int(f_dict.get("libbasicblocks", 0)),
                        "edges": int(f_dict.get("edges", 0)),
                        "libedges": int(f_dict.get("libedges", 0)),
                        "instructions": int(f_dict.get("instructions", 0)),
                        "libinstructions": int(f_dict.get("libinstructions", 0)),
                    }
                result["total_functions1"] = result["file1"]["functions"] + result["file1"]["libfunctions"]
                result["total_functions2"] = result["file2"]["functions"] + result["file2"]["libfunctions"]

            # Совпавшие функции
            cur.execute("""
                SELECT address1, name1, address2, name2,
                       similarity, confidence, flags, algorithm,
                       basicblocks, edges, instructions
                FROM function
                ORDER BY similarity DESC
            """)
            func_cols = [desc[0] for desc in cur.description]
            for row in cur.fetchall():
                func = dict(zip(func_cols, row))
                result["matched_functions"].append({
                    "name1": func.get("name1") or "<unnamed>",
                    "address1": f"0x{func['address1']:X}" if func.get("address1") else "",
                    "name2": func.get("name2") or "<unnamed>",
                    "address2": f"0x{func['address2']:X}" if func.get("address2") else "",
                    "similarity": round(func.get("similarity", 0.0), 4),
                    "confidence": round(func.get("confidence", 0.0), 4),
                    "flags": func.get("flags", 0),
                    "algorithm": func.get("algorithm", 0),
                    "basicblocks": func.get("basicblocks", 0),
                    "edges": func.get("edges", 0),
                    "instructions": func.get("instructions", 0),
                })
            conn.close()
        except Exception as e:
            result["error"] = str(e)
            logger.exception("Ошибка парсинга BinDiff")

        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
