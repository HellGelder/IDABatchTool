"""Фоновый поток для параллельного сравнения BinDiff. Экспорт через -OBinExportAutoAction."""
from __future__ import annotations

import difflib
import logging
import sqlite3
import json
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ui.constants import SCRIPTS_DIR

# Путь к IDAPython-скрипту экспорта (используется для извлечения импортов/псевдокода при diff)
_EXPORT_DATA_SCRIPT = SCRIPTS_DIR / "export_data.py"

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

            # 5. JSON-экспорт для импортов и псевдокода
            primary_json = self.output_dir / f"{stem}_primary.export.json"
            secondary_json = self.output_dir / f"{stem}_secondary.export.json"
            exported = self._export_json(primary_i64, primary_json, secondary_i64, secondary_json)

            # 6. Обогащаем .diff.json импортами, псевдокодом и hexdump
            self._enrich_diff_json(json_output, exported["primary"], exported["secondary"])

            # 7. Чистим временные .export.json, чтобы не мусорить
            for p in (primary_json, secondary_json):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            return True
        except Exception as e:
            logger.exception(f"Ошибка при обработке {stem}: {e}")
            self.error_occurred.emit(f"Ошибка {stem}: {e}")
            return False

    def _export_binexport(self, i64_path: Path, output_file: Path) -> bool:
        """Экспорт с немедленным оповещением при любом сбое."""
        if self._cancel_event.is_set():
            return False

        output_file.unlink(missing_ok=True)

        cmd = [
            self.idat_path,
            "-A",
            f"-OBinExportAutoAction:BinExportBinary",
            f"-OBinExportModule:{output_file}",
            str(i64_path)
        ]
        logger.info(f"Экспорт BinExport: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                  encoding='utf-8', errors='replace')
            stdout = (proc.stdout or "").strip()
            stderr = (proc.stderr or "").strip()

            if proc.returncode != 0:
                if "BinExport" in stderr or "BinExport" in stdout:
                    hint = "Плагин BinExport завершился с ошибкой."
                elif "not found" in stderr.lower() or "not found" in stdout.lower():
                    hint = "Плагин BinExport не найден или не загружен."
                else:
                    hint = f"IDA завершилась с кодом {proc.returncode}."
                detail = f"stdout:\n{stdout[:500]}\nstderr:\n{stderr[:500]}"
                logger.error(f"Экспорт {i64_path.name}: {hint}\n{detail}")
                self.error_occurred.emit(f"Ошибка экспорта {i64_path.name}: {hint}\n{detail}")
                return False

            if not output_file.is_file():
                detail = f"stdout:\n{stdout[:1000]}\nstderr:\n{stderr[:1000]}"
                logger.error(f"Файл {output_file} не создан после успешного выхода IDA. Вывод:\n{detail}")
                self.error_occurred.emit(
                    f"Файл BinExport не создан для {i64_path.name}, хотя IDA завершилась успешно.\n{detail}"
                )
                return False

            logger.info(f"BinExport создан: {output_file}")
            return True
        except Exception as e:
            logger.exception(f"Ошибка при экспорте BinExport: {e}")
            self.error_occurred.emit(f"Системная ошибка при экспорте {i64_path.name}: {e}")
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

    @staticmethod
    def _get_table_columns(conn: sqlite3.Connection, table: str) -> set:
        """Возвращает множество имён столбцов таблицы через PRAGMA table_info."""
        try:
            cur = conn.execute(f"PRAGMA table_info(\"{table}\")")
            return {row[1] for row in cur.fetchall()}
        except sqlite3.Error:
            return set()

    def _parse_bindiff_result(self, db_path: Path, primary: str, secondary: str,
                              json_output: Path) -> None:
        """Читает SQLite .BinDiff и сохраняет JSON с совпадениями.
           Схема таблиц определяется динамически через PRAGMA table_info,
           так что код устойчив к изменениям имён столбцов в разных версиях BinDiff.
        """
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
            try:
                cur = conn.cursor()

                # --- Метаданные (SELECT *) ---
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

                # --- Информация о файлах (SELECT *) ---
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

# --- Динамическое определение столбцов таблицы function ---
                func_columns = self._get_table_columns(conn, "function")

                # Таблица алиасов: каноническое_имя -> список возможных имён в БД
                COL_ALIASES = {
                    "address1":      ["address1"],
                    "name1":         ["name1"],
                    "address2":      ["address2"],
                    "name2":         ["name2"],
                    "similarity":    ["similarity", "sim"],
                    "confidence":    ["confidence", "conf"],
                    "flags":         ["flags"],
                    "algorithm":     ["algorithm", "algo"],
                    "basicblocks":   ["basicblocks", "basic_blocks", "basicblocks_count"],
                    "edges":         ["edges", "edgecount", "edge_count"],
                    "instructions":  ["instructions", "instructioncount", "instruction_count"],
                }

                # Строим reverse-маппинг: actual_column -> canonical_name
                actual_to_canonical = {}
                mandatory_ok = True
                for canonical, aliases in COL_ALIASES.items():
                    found = False
                    for alias in aliases:
                        if alias in func_columns:
                            actual_to_canonical[alias] = canonical
                            found = True
                            break
                    if not found and canonical in ("address1", "name1", "address2", "name2"):
                        mandatory_ok = False
                        logger.warning(
                            "Обязательный столбец '%s' не найден в таблице function. "
                            "Доступны: %s", canonical, sorted(func_columns)
                        )

                # --- Раскрываем имена алгоритмов матчинга ---
                algo_names: dict = {}
                try:
                    algo_columns = self._get_table_columns(conn, "functionalgorithm")
                    if {"id", "name"}.issubset(algo_columns):
                        algo_rows = cur.execute("SELECT id, name FROM functionalgorithm").fetchall()
                        algo_names = {r[0]: r[1] for r in algo_rows}
                except sqlite3.Error:
                    pass

                # --- Чтение совпавших функций ---
                if mandatory_ok and actual_to_canonical:
                    # Определяем реальное имя столбца для ORDER BY (любой из алиасов similarity)
                    sort_col_found = None
                    for alias_chain in COL_ALIASES.values():
                        for a in alias_chain:
                            if a in actual_to_canonical:
                                sort_col_found = a
                                break
                        if sort_col_found:
                            break
                    order_clause = f"ORDER BY {sort_col_found} DESC" if sort_col_found else ""

                    col_list = ", ".join(actual_to_canonical.keys())
                    cur.execute(f"SELECT {col_list} FROM function {order_clause}")

                    # Именованный доступ к row через список канонических имён
                    canonical_names = list(actual_to_canonical.values())
                    for row in cur.fetchall():
                        entry = {}
                        for idx, canonical in enumerate(canonical_names):
                            row_val = row[idx]
                            if canonical in ("address1", "address2") and row_val is not None:
                                entry[canonical] = f"0x{int(row_val):X}"
                            elif canonical in ("similarity", "confidence") and row_val is not None:
                                entry[canonical] = round(float(row_val), 4)
                            elif canonical in ("name1", "name2"):
                                entry[canonical] = row_val if row_val else "<unnamed>"
                            else:
                                entry[canonical] = row_val if row_val is not None else 0
                        entry.setdefault("similarity", 0.0)
                        entry.setdefault("confidence", 0.0)
                        entry.setdefault("basicblocks", 0)
                        entry.setdefault("edges", 0)
                        entry.setdefault("instructions", 0)
                        entry["algorithm_name"] = algo_names.get(
                            entry.get("algorithm", 0), f"#{entry.get('algorithm', 0)}"
                        )
                        result["matched_functions"].append(entry)
                else:
                    logger.warning(
                        "Не удалось прочитать таблицу function: обязательные столбцы отсутствуют. "
                        "Доступные столбцы: %s", func_columns
                    )

                # --- Чтение несовпавших функций не поддерживается в BinDiff v8 ---
                # (таблица unmatchedfunction отсутствует в схеме SQLite)
                result["unmatched_functions1"] = []
                result["unmatched_functions2"] = []

                # --- Распределение схожести ---
                sim_buckets = {
                    "1.0": 0, "0.95_0.99": 0, "0.80_0.94": 0, "0.50_0.79": 0, "below_0.50": 0,
                }
                for mf in result.get("matched_functions", []):
                    s = mf.get("similarity", 0.0)
                    if s >= 1.0:
                        sim_buckets["1.0"] += 1
                    elif s >= 0.95:
                        sim_buckets["0.95_0.99"] += 1
                    elif s >= 0.80:
                        sim_buckets["0.80_0.94"] += 1
                    elif s >= 0.50:
                        sim_buckets["0.50_0.79"] += 1
                    else:
                        sim_buckets["below_0.50"] += 1
                result["similarity_distribution"] = sim_buckets

                # --- Распределение алгоритмов матчинга функций ---
                try:
                    algo_dist = {}
                    cur.execute("""
                        SELECT f.algorithm, fa.name, COUNT(*)
                        FROM function f
                        LEFT JOIN functionalgorithm fa ON f.algorithm = fa.id
                        GROUP BY f.algorithm
                        ORDER BY COUNT(*) DESC
                    """)
                    for row in cur.fetchall():
                        algo_id, algo_name, cnt = row[0], row[1] or f"#{row[0]}", row[2]
                        algo_dist[algo_name] = cnt
                    result["algorithm_distribution"] = algo_dist
                except sqlite3.Error:
                    result["algorithm_distribution"] = {}

                # --- Переименованные функции (name1 != name2) ---
                renamed = []
                for mf in result.get("matched_functions", []):
                    n1 = mf.get("name1", "")
                    n2 = mf.get("name2", "")
                    if n1 and n2 and n1 != n2:
                        renamed.append(mf)
                result["renamed_functions"] = renamed

                # --- Статистика размеров совпавших функций ---
                bb_counts = [mf.get("basicblocks", 0) for mf in result.get("matched_functions", [])]
                insn_counts = [mf.get("instructions", 0) for mf in result.get("matched_functions", [])]
                if bb_counts:
                    result["function_size_stats"] = {
                        "avg_basicblocks": round(sum(bb_counts) / len(bb_counts), 1),
                        "min_basicblocks": min(bb_counts),
                        "max_basicblocks": max(bb_counts),
                        "avg_instructions": round(sum(insn_counts) / len(insn_counts), 1),
                        "min_instructions": min(insn_counts),
                        "max_instructions": max(insn_counts),
                    }
                else:
                    result["function_size_stats"] = {}

                # --- Агрегированные числа совпадений ---
                total_bb = sum(bb_counts)
                total_insn = sum(insn_counts)
                total_edges = sum(mf.get("edges", 0) for mf in result.get("matched_functions", []))
                result["total_matched_basicblocks"] = total_bb
                result["total_matched_instructions"] = total_insn
                result["total_matched_edges"] = total_edges

            finally:
                conn.close()
        except Exception as e:
            result["error"] = str(e)
            logger.exception("Ошибка парсинга BinDiff")

        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # JSON-экспорт через IDA (извлечение импортов / псевдокода)
    # ------------------------------------------------------------------
    def _export_json(self, primary_i64: Path, primary_out: Path,
                     secondary_i64: Path, secondary_out: Path) -> dict:
        """Запускает export_data.py для обоих .i64, возвращает {"primary": Path|None, "secondary": Path|None}."""
        result = {"primary": None, "secondary": None}
        pairs = [(primary_i64, primary_out), (secondary_i64, secondary_out)]

        for i64_path, json_path in pairs:
            if self._cancel_event.is_set():
                break
            if not _EXPORT_DATA_SCRIPT.is_file():
                self.error_occurred.emit(f"Скрипт экспорта не найден: {_EXPORT_DATA_SCRIPT}")
                continue
            cmd = [
                self.idat_path,
                "-A",
                f"-S\"{_EXPORT_DATA_SCRIPT}\" pseudocode=1",
                str(i64_path),
            ]
            logger.info(f"JSON-экспорт: {' '.join(cmd)}")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                      encoding="utf-8", errors="replace")
                if proc.returncode != 0:
                    self.error_occurred.emit(f"Ошибка JSON-экспорта {i64_path.name}: код {proc.returncode}")
                    continue
                # export_data.py пишет в <idb_path>.export.json, то есть в i64_path + ".export.json"
                src = Path(str(i64_path) + ".export.json")
                if src.is_file() and src != json_path:
                    shutil.move(str(src), str(json_path))
                if json_path.is_file():
                    key = "primary" if i64_path == primary_i64 else "secondary"
                    result[key] = json_path
            except Exception as e:
                logger.exception(f"Ошибка JSON-экспорта {i64_path.name}: {e}")
                self.error_occurred.emit(f"Системная ошибка JSON-экспорта {i64_path.name}: {e}")
        return result

    # ------------------------------------------------------------------
    # Обогащение diff.json импортами, псевдокодом, hexdump и diff
    # ------------------------------------------------------------------
    @staticmethod
    def _enrich_diff_json(diff_json: Path, primary_json: Optional[Path],
                          secondary_json: Optional[Path]) -> None:
        """Добавляет в diff.json секции imports_only_*, pseudocode_diff и hexdump."""
        try:
            with open(diff_json, "r", encoding="utf-8") as f:
                diff_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        # --------------------------------------------------------------
        # Импорты: только в primary / только в secondary
        # --------------------------------------------------------------
        primary_imports = set()
        secondary_imports = set()
        # Словари функций — индексируем ПО АДРЕСУ (start_ea), т.к. BinDiff
        # хранит имена в формате sub_10001000, а export_data.py нормализует
        # их в 10001000. Адрес — единственный надёжный идентификатор.
        primary_funcs: dict = {}
        secondary_funcs: dict = {}

        for label, json_path, out_set, out_dict in [
            ("primary", primary_json, primary_imports, primary_funcs),
            ("secondary", secondary_json, secondary_imports, secondary_funcs),
        ]:
            if json_path is None or not json_path.is_file():
                continue
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            for imp in data.get("imports", []):
                name = imp.get("name", "").strip()
                if name:
                    out_set.add(name)
            for func in data.get("functions", []):
                addr = func.get("start_ea", "")
                if not addr:
                    continue
                out_dict[addr] = {
                    "name": func.get("name", "").strip(),
                    "pseudocode": func.get("pseudocode", ""),
                    "hexdump": func.get("hexdump", ""),
                    "start_ea": addr,
                    "insn_types": func.get("insn_types", {}),
                    "callees": func.get("callees", []),
                }

        diff_data["imports_only_in_primary"] = sorted(primary_imports - secondary_imports)
        diff_data["imports_only_in_secondary"] = sorted(secondary_imports - primary_imports)

        # --------------------------------------------------------------
        # Обогащение matched_functions: pseudocode + hexdump + diff
        # --------------------------------------------------------------
        for mf in diff_data.get("matched_functions", []):
            name1 = mf.get("name1", "")
            name2 = mf.get("name2", "")
            addr1 = mf.get("address1", "")
            addr2 = mf.get("address2", "")

            # Ищем ПО АДРЕСУ — это единственный надёжный ключ для stripped бинарников.
            # Если не нашли по адресу — пытаемся по нормализованному имени (fallback).
            f1 = primary_funcs.get(addr1)
            f2 = secondary_funcs.get(addr2)
            if f1 is None and name1:
                norm1 = name1.replace("sub_", "") if name1.startswith("sub_") else name1
                for v in primary_funcs.values():
                    if v.get("name") == norm1 or v.get("name") == name1:
                        f1 = v
                        break
            if f2 is None and name2:
                norm2 = name2.replace("sub_", "") if name2.startswith("sub_") else name2
                for v in secondary_funcs.values():
                    if v.get("name") == norm2 or v.get("name") == name2:
                        f2 = v
                        break

            mf["pseudocode1"] = f1["pseudocode"] if f1 else ""
            mf["pseudocode2"] = f2["pseudocode"] if f2 else ""
            mf["hexdump1"] = f1["hexdump"] if f1 else ""
            mf["hexdump2"] = f2["hexdump"] if f2 else ""

            # Строим side-by-side diff (только если оба псевдокода непусты)
            if f1 and f2 and f1["pseudocode"] and f2["pseudocode"]:
                lines1 = f1["pseudocode"].splitlines()
                lines2 = f2["pseudocode"].splitlines()
                diff_rows = []
                for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(
                    None, lines1, lines2
                ).get_opcodes():
                    if tag == "equal":
                        for k in range(i1, i2):
                            diff_rows.append(
                                {"type": "equal", "left": lines1[k], "right": lines2[j1 + k - i1]}
                            )
                    elif tag == "delete":
                        for k in range(i1, i2):
                            diff_rows.append({"type": "removed", "left": lines1[k], "right": ""})
                    elif tag == "insert":
                        for k in range(j1, j2):
                            diff_rows.append({"type": "added", "left": "", "right": lines2[k]})
                    elif tag == "replace":
                        for k in range(i1, i2):
                            diff_rows.append({"type": "removed", "left": lines1[k], "right": ""})
                        for k in range(j1, j2):
                            diff_rows.append({"type": "added", "left": "", "right": lines2[k]})
                mf["pseudocode_diff"] = diff_rows
            else:
                mf["pseudocode_diff"] = []

            # Сравнение типов инструкций для пары функций
            if f1 and f2:
                it1 = f1.get("insn_types", {})
                it2 = f2.get("insn_types", {})
                all_mnemonics = sorted(set(list(it1.keys()) + list(it2.keys())))
                insn_type_diff = []
                for mne in all_mnemonics:
                    c1 = it1.get(mne, 0)
                    c2 = it2.get(mne, 0)
                    if c1 != c2:
                        insn_type_diff.append({
                            "mnemonic": mne,
                            "count1": c1,
                            "count2": c2,
                            "diff": c2 - c1,
                        })
                mf["insn_type_diff"] = insn_type_diff
                mf["insn_types1"] = it1
                mf["insn_types2"] = it2
            else:
                mf["insn_type_diff"] = []
                mf["insn_types1"] = {}
                mf["insn_types2"] = {}

            # Граф вызовов: callees
            if f1 and f2:
                callees1 = set(f1.get("callees", []))
                callees2 = set(f2.get("callees", []))
                mf["callees_only1"] = sorted(callees1 - callees2)
                mf["callees_only2"] = sorted(callees2 - callees1)
                mf["callees_common"] = sorted(callees1 & callees2)
            else:
                mf["callees_only1"] = []
                mf["callees_only2"] = []
                mf["callees_common"] = []

        # --- Глобальный сводный diff по типам инструкций ---
        all_insn_types1 = {}
        all_insn_types2 = {}
        for mf in diff_data.get("matched_functions", []):
            addr1 = mf.get("address1", "")
            f1 = primary_funcs.get(addr1)
            if f1 is None:
                name1 = mf.get("name1", "")
                norm1 = name1.replace("sub_", "") if name1.startswith("sub_") else name1
                for v in primary_funcs.values():
                    if v.get("name") == norm1 or v.get("name") == name1:
                        f1 = v
                        break
            if f1:
                for mne, cnt in f1.get("insn_types", {}).items():
                    all_insn_types1[mne] = all_insn_types1.get(mne, 0) + cnt

            addr2 = mf.get("address2", "")
            f2 = secondary_funcs.get(addr2)
            if f2 is None:
                name2 = mf.get("name2", "")
                norm2 = name2.replace("sub_", "") if name2.startswith("sub_") else name2
                for v in secondary_funcs.values():
                    if v.get("name") == norm2 or v.get("name") == name2:
                        f2 = v
                        break
            if f2:
                for mne, cnt in f2.get("insn_types", {}).items():
                    all_insn_types2[mne] = all_insn_types2.get(mne, 0) + cnt

        all_mnes = sorted(set(list(all_insn_types1.keys()) + list(all_insn_types2.keys())))
        global_insn_diff = []
        for mne in all_mnes:
            c1 = all_insn_types1.get(mne, 0)
            c2 = all_insn_types2.get(mne, 0)
            global_insn_diff.append({
                "mnemonic": mne,
                "count1": c1,
                "count2": c2,
                "diff": c2 - c1,
            })
        diff_data["global_insn_diff"] = global_insn_diff

        with open(diff_json, "w", encoding="utf-8") as f:
            json.dump(diff_data, f, indent=2, ensure_ascii=False)