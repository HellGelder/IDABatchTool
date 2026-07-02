"""Фоновый поток для параллельного сравнения BinDiff + Diaphora."""
from __future__ import annotations

import difflib
import hashlib
import logging
import os
import sqlite3
import json
import shutil
import subprocess
import threading
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple, Optional

from PySide6.QtCore import QThread, Signal

from ida_batch_tool.ui.constants import SCRIPTS_DIR

_EXPORT_DATA_SCRIPT = SCRIPTS_DIR / "export_data.py"
_EXPORT_CFG_SCRIPT = SCRIPTS_DIR / "export_cfg.py"
_DIAPHORA_DIR = SCRIPTS_DIR / "diaphora"
_DIAPHORA_SCRIPT = _DIAPHORA_DIR / "diaphora.py"

logger = logging.getLogger(__name__)


def _safe_filename(key: str) -> str:
    return key.replace("\\", "_").replace("/", "_").replace(" ", "_").replace(".", "_")


def _find_original_binary(i64_path: Path) -> Optional[Path]:
    """Находит исходный исполняемый файл по .i64 базе.
    
    Для uprngctl64.exe.i64:
      - stem = 'uprngctl64.exe' (Path.stem снимает только .i64)
      - сначала проверяем stem как есть — это сам оригин��льный файл
      - если нет — пробуем по расширениям
    """
    stem = i64_path.stem  # uprngctl64.exe.uprngctl64.exe -> uprngctl64.exe
    parent = i64_path.parent
    # 1) Сначала сам stem — он уже содержит расширение, если исходник был .exe
    candidate = parent / stem
    if candidate.is_file():
        return candidate
    # 2) Если .i64 создан из файла без расширения в имени — пробуем расширения
    for ext in ('.exe', '.dll', '.bin', '.sys', '.elf', '.so', '.o', '.out', '.wasm', '.pyc', '.class', '.jar', '.apk', '.dex'):
        candidate = parent / f"{stem}{ext}"
        if candidate.is_file():
            return candidate
    return None


def _compute_hexdump_diff(orig1: Path, orig2: Path) -> Tuple[list, float]:
    """Сравнивает два исполняемых файла поблочно (16 байт).
    Возвращает (hex_rows, hexdump_similarity), где similarity = совпавшие байты / макс. длина (0..1) с учётом alignment."""
    try:
        data1 = orig1.read_bytes()
        data2 = orig2.read_bytes()
    except (OSError, PermissionError):
        return [], 0.0
    if not data1 or not data2:
        return [], 0.0

    def _format_hex_block(data: bytes, addr: int) -> str:
        hex_part = ' '.join(f'{b:02x}' for b in data)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        return f'{addr:08x}  {hex_part:<48}  |{ascii_part}|'

    block_size = 16
    max_len = max(len(data1), len(data2))
    hex_rows = []
    matching_bytes = 0
    total_bytes = 0
    offset = 0
    while offset < max_len:
        chunk1 = data1[offset:offset + block_size]
        chunk2 = data2[offset:offset + block_size]
        line1 = _format_hex_block(chunk1, offset) if chunk1 else ''
        line2 = _format_hex_block(chunk2, offset) if chunk2 else ''
        if chunk1 == chunk2:
            hex_rows.append({"type": "equal", "left": line1, "right": line2})
            matching_bytes += min(len(chunk1), len(chunk2))
        else:
            # Побайтовое сравнение внутри блока
            for b_idx in range(max(len(chunk1), len(chunk2))):
                b1 = chunk1[b_idx] if b_idx < len(chunk1) else 0
                b2 = chunk2[b_idx] if b_idx < len(chunk2) else 0
                if b1 == b2:
                    matching_bytes += 1
            hex_rows.append({"type": "removed", "left": line1, "right": line2})
        total_bytes += max(len(chunk1), len(chunk2))
        offset += block_size

    hex_rows.append({"type": "_meta", "total_lines": len(hex_rows) - 1})
    similarity = round(matching_bytes / total_bytes, 6) if total_bytes > 0 else 0.0
    return hex_rows, similarity


def _parse_diaphora_results(sqlite_path: Path) -> dict:
    """Читает результаты Diaphora из SQLite -> dict с matched_functions."""
    result = {
        "matched_functions": [],
        "diaphora_algorithm_distribution": {},
    }
    if not sqlite_path.is_file():
        return result
    try:
        conn = sqlite3.connect(str(sqlite_path))
        cur = conn.cursor()
        # Таблица results
        try:
            cur.execute("SELECT type, address, name, address2, name2, ratio, nodes1, nodes2, description FROM results ORDER BY ratio DESC")
            col_names = [desc[0] for desc in cur.description]
            for row in cur.fetchall():
                r = dict(zip(col_names, row))
                heuristic_name = (r.get("description") or "diaphora_auto").strip()

                # Безопасный парсинг hex-адреса (Diaphora хранит без префикса 0x)
                def _parse_addr(val: str) -> str:
                    if not val:
                        return "?"
                    try:
                        return f"0x{int(val, 16):X}"
                    except (ValueError, TypeError):
                        return f"0x{val}"

                # Безопасный парсинг числа
                def _safe_int(val) -> int:
                    if val is None:
                        return 0
                    try:
                        return int(val)
                    except (ValueError, TypeError):
                        return 0

                result["matched_functions"].append({
                    "address1": _parse_addr(r.get("address")),
                    "name1": r.get("name", ""),
                    "address2": _parse_addr(r.get("address2")),
                    "name2": r.get("name2", ""),
                    "similarity": round(float(r.get("ratio", 0) or 0), 4),
                    "confidence": round(float(r.get("ratio", 0) or 0), 4),
                    "algorithm_name": heuristic_name,
                    "match_type": r.get("type", "partial"),
                    "nodes1": _safe_int(r.get("nodes1")),
                    "nodes2": _safe_int(r.get("nodes2")),
                    "source": "diaphora",
                })
                result["diaphora_algorithm_distribution"][heuristic_name] = \
                    result["diaphora_algorithm_distribution"].get(heuristic_name, 0) + 1
        except sqlite3.OperationalError:
            pass
        # Таблица unmatched
        try:
            unmatched1 = []
            unmatched2 = []
            cur.execute("SELECT type, address, name FROM unmatched")
            for row in cur.fetchall():
                typ, addr, name = row[0], row[1], row[2]
                entry = {"address": f"0x{int(addr, 16):X}" if addr else "?", "name": name or ""}
                if typ == 1:
                    unmatched1.append(entry)
                else:
                    unmatched2.append(entry)
            result["unmatched_functions1"] = unmatched1
            result["unmatched_functions2"] = unmatched2
        except sqlite3.OperationalError:
            pass
        conn.close()
    except Exception as e:
        logger.warning(f"Ошибка парсинга Diaphora SQLite: {e}")
    return result


class DiffWorker(QThread):
    progress_updated = Signal(int, int, str)
    stage_updated = Signal(str, int, int, str, str)
    # stage_updated(stage_name, current, total, file_stem, substage_description)
    pair_started = Signal(str)
    pair_completed = Signal(str)
    finished = Signal(int, int)
    error_occurred = Signal(str)

    def __init__(self, file_pairs: List[Tuple[Path, Path, str]],
                 idat_path: str, bindiff_path: str,
                 output_dir: Path,
                 engine: str = "bindiff",
                 max_workers: Optional[int] = None, parent=None):
        super().__init__(parent)
        self.file_pairs = file_pairs
        self.idat_path = idat_path
        self.bindiff_path = bindiff_path
        self.output_dir = output_dir
        self.engine = engine
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        if max_workers is not None:
            self.max_workers = max_workers
        else:
            self.max_workers = max(1, cpu_count - 1)
        self._cancel_event = threading.Event()
        self._completed_count = 0
        self._pulse_counter = 0
        self._lock = threading.Lock()

    def _safe_emit(self, signal, *args) -> None:
        """Безопасный эмит сигнала — ловит TypeError если QThread уже уничтожен."""
        try:
            signal.emit(*args)
        except TypeError as e:
            logger.warning(f"Signal emit failed (QThread destroyed?): {e}")

    def cancel(self) -> None:
        self._cancel_event.set()

    def _run_pass(self, stage_name: str, process_func, pairs: list) -> int:
        """Запускает фазу process_func для всех пар в ThreadPoolExecutor.
        Возвращает количество успешно завершённых пар в этой фазе."""
        total = len(pairs)
        if total == 0:
            return 0
        success = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_pair = {
                executor.submit(process_func, p, s, r): (p, s, r)
                for p, s, r in pairs
            }
            for future in as_completed(future_to_pair):
                if self._cancel_event.is_set():
                    for f in future_to_pair:
                        f.cancel()
                    break
                p, s, r = future_to_pair[future]
                stem = _safe_filename(r)
                try:
                    ok = future.result()
                    with self._lock:
                        if ok:
                            success += 1
                except Exception as e:
                    logger.exception(f"Ошибка пары {r} в фазе {stage_name}: {e}")
                    self._safe_emit(self.error_occurred, f"Ошибка пары {r} в фазе {stage_name}: {e}")
        return success

    def _safe_emit_stage(self, stage: str, cur: int, total: int, stem: str, desc: str) -> None:
        self._safe_emit(self.stage_updated, stage, cur, total, stem, desc)

    def run(self) -> None:
        total = len(self.file_pairs)
        if total == 0:
            self._safe_emit(self.finished, 0, 0)
            return
        logger.info(f"Сравнение {total} пар, engine={self.engine}, результаты в {self.output_dir}")

        if self.engine in ("bindiff", "both"):
            bindiff_pairs = [(p, s, r) for p, s, r in self.file_pairs]
            self._safe_emit_stage("BinDiff", 0, total, "", "Ожидание начала...")
            self._stage_current_stage = "BinDiff: экспорт"
            self._run_pass_with_progress("BinDiff", self._process_bindiff_pair, bindiff_pairs, total)

        if self.engine in ("diaphora", "both"):
            # Сортируем пары по размеру primary .i64 по возрастанию — сначала маленькие файлы
            diaphora_pairs = sorted(
                [(p, s, r) for p, s, r in self.file_pairs],
                key=lambda x: x[0].stat().st_size if x[0].is_file() else 0,
            )
            self._safe_emit_stage("Diaphora", 0, total, "", "Ожидание начала...")
            self._stage_current_stage = "Diaphora: сбор данных"
            self._run_pass_with_progress("Diaphora", self._process_diaphora_pair, diaphora_pairs, total)

        self._safe_emit_stage("Post", 0, total, "", "Ожидание начала...")
        self._stage_current_stage = "Пост-анализ"
        self._run_pass_with_progress("Post", self._process_post_pair, self.file_pairs, total)

        logger.info(f"Завершено. Всего обработано: {total}")
        self._safe_emit(self.finished, total, total)

    # Порог для крупных файлов: если .i64 больше этого — обрабатываем последовательно
    _LARGE_FILE_THRESHOLD = 100 * 1024 * 1024  # 100 MB

    @staticmethod
    def _is_large_file(i64_path: Path) -> bool:
        """Проверяет, является ли .i64 файл «крупным» (требует последовательной обработки)."""
        try:
            return i64_path.is_file() and i64_path.stat().st_size >= DiffWorker._LARGE_FILE_THRESHOLD
        except OSError:
            return False

    def _run_pass_with_progress(self, stage_name: str, process_func, pairs: list, total: int) -> None:
        """Запускает фазу с эмиссией прогресса.
        Крупные ф��йлы обрабатываются последовательно (1 за раз) для снижения нагрузки на память."""
        if total == 0:
            return

        # Разделяем пары на маленькие (параллельно) и крупные (последовательно)
        small_pairs = [x for x in pairs if not self._is_large_file(x[0])]
        large_pairs = [x for x in pairs if self._is_large_file(x[0])]

        completed = 0

        def _emit_progress(p, s, r, ok: bool):
            nonlocal completed
            display_name = p.name
            with self._lock:
                completed += 1
                self._pulse_counter = completed  # для pulse-обновлений
                if ok:
                    self._safe_emit_stage(stage_name, completed, total, display_name, self._stage_current_stage)
                else:
                    self._safe_emit_stage(stage_name, completed, total, display_name, f"ОШИБКА {r}")

        # 1) Маленькие файлы — параллельно через ThreadPoolExecutor
        if small_pairs:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_pair = {
                    executor.submit(process_func, p, s, r): (p, s, r)
                    for p, s, r in small_pairs
                }
                for future in as_completed(future_to_pair):
                    if self._cancel_event.is_set():
                        for f in future_to_pair:
                            f.cancel()
                        break
                    p, s, r = future_to_pair[future]
                    try:
                        ok = future.result()
                        _emit_progress(p, s, r, ok)
                    except Exception as e:
                        logger.exception(f"Ошибка {r} в фазе {stage_name}: {e}")
                        self._safe_emit(self.error_occurred, f"Ошибка {r} в фазе {stage_name}: {e}")
                        _emit_progress(p, s, r, False)

        if self._cancel_event.is_set():
            return

        # 2) Крупные файлы — последовательно (1 IDA-процесс за раз)
        for p, s, r in large_pairs:
            if self._cancel_event.is_set():
                break
            try:
                ok = process_func(p, s, r)
                _emit_progress(p, s, r, ok)
            except Exception as e:
                logger.exception(f"Ошибка {r} в фазе {stage_name}: {e}")
                self._safe_emit(self.error_occurred, f"Ошибка {r} в фазе {stage_name}: {e}")
                _emit_progress(p, s, r, False)

    # ----- ФАЗА 1: BinDiff -----
    def _process_bindiff_pair(self, primary_i64: Path, secondary_i64: Path, rel_key: str) -> bool:
        stem = _safe_filename(rel_key)
        if self._cancel_event.is_set():
            return False
        try:
            json_output = self.output_dir / f"{stem}.diff.json"
            primary_binexport = self.output_dir / f"{stem}_primary.BinExport"
            secondary_binexport = self.output_dir / f"{stem}_secondary.BinExport"
            if not self._export_binexport(primary_i64, primary_binexport):
                return False
            if not self._export_binexport(secondary_i64, secondary_binexport):
                return False
            diff_output = self.output_dir / f"{stem}.BinDiff"
            if not self._run_bindiff(primary_binexport, secondary_binexport, diff_output):
                self._safe_emit(self.error_occurred, f"BinDiff: {stem}")
                return False
            self._parse_bindiff_result(diff_output, str(primary_i64), str(secondary_i64), json_output)
            return True
        except Exception as e:
            logger.exception(f"Ошибка BinDiff {stem}: {e}")
            self._safe_emit(self.error_occurred, f"Ошибка BinDiff {stem}: {e}")
            return False

    # ----- ФАЗА 2: Diaphora -----
    def _process_diaphora_pair(self, primary_i64: Path, secondary_i64: Path, rel_key: str) -> bool:
        stem = _safe_filename(rel_key)
        if self._cancel_event.is_set():
            return False
        if not _DIAPHORA_SCRIPT.is_file():
            logger.warning(f"Diaphora не найден: {_DIAPHORA_SCRIPT}")
            return False
        try:
            json_output = self.output_dir / f"{stem}.diff.json"
            diaphora_db_pr = self.output_dir / f"{stem}_primary.diaphora.sqlite"
            diaphora_db_sc = self.output_dir / f"{stem}_secondary.diaphora.sqlite"
            diaphora_result = self.output_dir / f"{stem}_diaphora_result.sqlite"

            # PULSE: обновляем статус каждые 30 сек во время долгого экспорта
            def _pulse(msg: str) -> None:
                self._safe_emit_stage("Diaphora", self._pulse_counter, len(self.file_pairs),
                                      primary_i64.name, msg)

            if not self._run_diaphora_export(primary_i64, diaphora_db_pr, pulse_callback=_pulse):
                self._safe_emit(self.error_occurred, f"Diaphora экспорт primary {stem}")
                return False
            if not self._run_diaphora_export(secondary_i64, diaphora_db_sc, pulse_callback=_pulse):
                self._safe_emit(self.error_occurred, f"Diaphora экспорт secondary {stem}")
                return False

            if diaphora_db_pr.is_file() and diaphora_db_sc.is_file():
                if self._run_diaphora_diff(diaphora_db_pr, diaphora_db_sc, diaphora_result):
                    self._merge_diaphora_into_json(json_output, diaphora_result, stem)
            return True
        except Exception as e:
            logger.exception(f"Ошибка Diaphora {stem}: {e}")
            self._safe_emit(self.error_occurred, f"Ошибка Diaphora {stem}: {e}")
            return False

    # ----- ФАЗА 3: Пост-анализ (JSON export, enrich, CFG, hexdump, cleanup) -----
    def _process_post_pair(self, primary_i64: Path, secondary_i64: Path, rel_key: str) -> bool:
        stem = _safe_filename(rel_key)
        if self._cancel_event.is_set():
            return False
        try:
            json_output = self.output_dir / f"{stem}.diff.json"
            primary_json = self.output_dir / f"{stem}_primary.export.json"
            secondary_json = self.output_dir / f"{stem}_secondary.export.json"
            exported = self._export_json(primary_i64, primary_json, secondary_i64, secondary_json)
            self._enrich_diff_json(json_output, exported["primary"], exported["secondary"])

            # Hexdump diff
            orig1 = _find_original_binary(primary_i64)
            orig2 = _find_original_binary(secondary_i64)
            if orig1 and orig2:
                try:
                    with open(json_output, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    hex_rows, hex_sim = _compute_hexdump_diff(orig1, orig2)
                    data["global_hex_diff"] = [{
                        "name1": orig1.name, "path1": str(orig1),
                        "name2": orig2.name, "path2": str(orig2),
                        "hex_rows": hex_rows, "hexdump_similarity": hex_sim,
                    }]
                    data["hexdump_similarity"] = hex_sim
                    data["real_primary"] = str(orig1)
                    data["real_secondary"] = str(orig2)
                    with open(json_output, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                except (OSError, json.JSONDecodeError):
                    pass

            # CFG export
            pr_cfg_idx, sc_cfg_idx = self._export_cfg_pair(primary_i64, secondary_i64, stem)
            if pr_cfg_idx or sc_cfg_idx:
                try:
                    with open(json_output, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    for mf in data.get("matched_functions", []):
                        a1 = mf.get("address1", "")
                        a2 = mf.get("address2", "")
                        if pr_cfg_idx and a1 in pr_cfg_idx:
                            mf["cfg_svg1"] = pr_cfg_idx[a1]
                        if sc_cfg_idx and a2 in sc_cfg_idx:
                            mf["cfg_svg2"] = sc_cfg_idx[a2]
                    with open(json_output, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                except (OSError, json.JSONDecodeError):
                    pass

            # Unmatched из IDA-экспорта
            try:
                with open(json_output, "r", encoding="utf-8") as f:
                    data = json.load(f)
                matched_primary = set()
                matched_secondary = set()
                for mf in data.get("matched_functions", []):
                    a1 = mf.get("address1", "")
                    a2 = mf.get("address2", "")
                    if a1: matched_primary.add(a1)
                    if a2: matched_secondary.add(a2)

                def _read_export(pj_path, matched_set):
                    funcs = []
                    if pj_path and pj_path.is_file():
                        try:
                            with open(pj_path, "r", encoding="utf-8") as pf:
                                pdata = json.load(pf)
                            for func in pdata.get("functions", []):
                                raw_addr = func.get("start_ea", "")
                                if not raw_addr: continue
                                try:
                                    addr_int = int(raw_addr, 16) if raw_addr.startswith("0x") else int(raw_addr)
                                    addr_norm = f"0x{addr_int:X}"
                                except (ValueError, TypeError):
                                    addr_norm = raw_addr
                                if addr_norm not in matched_set:
                                    funcs.append({"address": addr_norm, "name": func.get("name", "<unnamed>")})
                        except (OSError, json.JSONDecodeError):
                            pass
                    return funcs

                un1 = _read_export(exported.get("primary"), matched_primary)
                un2 = _read_export(exported.get("secondary"), matched_secondary)
                if un1: data.setdefault("unmatched_functions1", un1)
                if un2: data.setdefault("unmatched_functions2", un2)
                total1 = data.get("total_functions1", 0)
                matched_cnt = len(data.get("matched_functions", []))
                data["total_unmatched"] = total1 - matched_cnt
                with open(json_output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except (OSError, json.JSONDecodeError):
                pass

            # Cleanup
            for p in (primary_json, secondary_json):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            return True
        except Exception as e:
            logger.exception(f"Ошибка пост-анализа {stem}: {e}")
            self._safe_emit(self.error_occurred, f"Ошибка пост-анализа {stem}: {e}")
            return False

    # ----- Все существующие приватные методы (неизменны) -----
    # _run_diaphora_export, _run_diaphora_diff, _merge_diaphora_into_json
    # _export_cfg_pair, _export_binexport, _run_bindiff
    # _get_table_columns, _parse_bindiff_result, _export_json
    # _enrich_diff_json

    def _run_diaphora_export(self, i64_path: Path, out_sqlite: Path,
                              pulse_callback: Optional[callable] = None) -> bool:
        """Запускает diaphora.py --export через IDA с переменными окружения.
        
        Для крупных файлов (>100MB .i64) добавляет флаги:
          - -dVPAGESIZE=16384       (увеличенная виртуальная память)
          - -dUNDO_MAXSIZE=0        (отключение undo для экономии ОЗУ)
        
        Процесс IDA запускается через Popen с polling:
          - stdout/stderr пишутся во временные файлы (без дедлока pipe-буфера)
          - каждые 30 секунд проверяется рост выходного файла и вызывается
            pulse_callback (если передан) для обновления статуса в UI
          - проверяется _cancel_event для возможности прервать через кнопку «Отмена»
        """
        import tempfile
        import time

        env = os.environ.copy()
        env["DIAPHORA_AUTO"] = "1"
        env["DIAPHORA_EXPORT_FILE"] = str(out_sqlite)

        # Флаги IDA для больших баз
        extra_flags = []
        if self._is_large_file(i64_path):
            extra_flags = [
                "-dVPAGESIZE=16384",        # 256MB виртуальной памяти вместо 128MB
                "-dUNDO_MAXSIZE=0",         # отключаем undo — экономит память
            ]
            ida_log = out_sqlite.parent / f"{out_sqlite.stem}.ida.log"
            extra_flags.append(f"-L\"{ida_log}\"")

        cmd = (
            [self.idat_path, "-A"]
            + extra_flags
            + [f"-S\"{_DIAPHORA_SCRIPT}\"", str(i64_path)]
        )
        logger.info(f"Diaphora экспорт: {' '.join(str(c) for c in cmd)}")
        try:
            tmp_out = tempfile.TemporaryFile()
            tmp_err = tempfile.TemporaryFile()
            proc = subprocess.Popen(cmd, stdout=tmp_out, stderr=tmp_err, env=env)

            # Polling с пульс-обновлениями
            POLL_INTERVAL = 2.0
            PULSE_INTERVAL = 30.0  # обновляем статус каждые 30 сек
            STALL_LOG_INTERVAL = 300.0  # логгируем «зависание» каждые 5 мин
            start_time = time.monotonic()
            last_pulse_time = 0.0
            last_stall_log_time = 0.0
            last_file_size = 0

            while True:
                if self._cancel_event.is_set():
                    proc.kill()
                    proc.wait()
                    tmp_out.close()
                    tmp_err.close()
                    logger.warning(f"Diaphora экспорт {i64_path.name} прерван (отмена)")
                    return False

                now = time.monotonic()
                elapsed = now - start_time

                try:
                    proc.wait(timeout=POLL_INTERVAL)
                    break  # процесс завершился
                except subprocess.TimeoutExpired:
                    pass

                # Пульс-обновление статуса каждые 30 секунд
                if pulse_callback and (now - last_pulse_time >= PULSE_INTERVAL):
                    last_pulse_time = now
                    mins = int(elapsed // 60)
                    secs = int(elapsed % 60)
                    status = f"экспорт {i64_path.name} ({mins} мин {secs} сек)"
                    try:
                        pulse_callback(status)
                    except Exception:
                        pass

                # Проверка роста выходного файла каждые 5 минут
                if now - last_stall_log_time >= STALL_LOG_INTERVAL:
                    last_stall_log_time = now
                    try:
                        cur_size = out_sqlite.stat().st_size if out_sqlite.is_file() else 0
                        if cur_size == last_file_size:
                            logger.warning(
                                f"Diaphora экспорт {i64_path.name}: "
                                f"размер выходного файла не меняется ({cur_size} байт) "
                                f"уже {int(elapsed//60)} мин. "
                                f"Процесс IDA ещё работает (PID={proc.pid})."
                            )
                        else:
                            logger.info(
                                f"Diaphora экспорт {i64_path.name}: "
                                f"выходной файл {cur_size} байт "
                                f"(+{cur_size - last_file_size} за 5 мин), "
                                f"прошло {int(elapsed//60)} мин."
                            )
                            last_file_size = cur_size
                    except OSError:
                        pass

            # Процесс завершился
            ok = proc.returncode == 0 and out_sqlite.is_file()
            if not ok:
                tmp_out.seek(0); stdout_data = tmp_out.read()
                tmp_err.seek(0); stderr_data = tmp_err.read()
                self._save_diaphora_log(
                    cmd, proc.returncode,
                    stdout_data.decode("utf-8", errors="replace"),
                    stderr_data.decode("utf-8", errors="replace"),
                    out_sqlite,
                )
            tmp_out.close()
            tmp_err.close()
            return ok
        except Exception as e:
            logger.warning(f"Ошибка Diaphora экспорта: {e}")
            return False

    @staticmethod
    def _save_diaphora_log(cmd, returncode, stdout, stderr, out_sqlite: Path) -> None:
        """Сохраняет логи Diaphora экспорта рядом с целевым sqlite."""
        log_path = out_sqlite.parent / f"{out_sqlite.stem}.diaphora_export.log"
        try:
            with open(log_path, "w", encoding="utf-8") as lf:
                lf.write(f"CMD: {' '.join(str(c) for c in cmd)}\n")
                lf.write(f"RC: {returncode}\n\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n")
            logger.warning(f"Diaphora экспорт неудачен. Лог: {log_path}")
        except OSError:
            pass

    def _run_diaphora_diff(self, db1: Path, db2: Path, out_sqlite: Path) -> bool:
        """Запускает diaphora.py --diff (не требует IDA).
        В standalone-режиме использует argparse: diaphora.py db1 db2 -o out"""
        cmd = [sys.executable, str(_DIAPHORA_SCRIPT), str(db1), str(db2), "-o", str(out_sqlite)]
        logger.info(f"Diaphora diff: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                  encoding="utf-8", errors="replace")
            return proc.returncode == 0 and out_sqlite.is_file()
        except Exception as e:
            logger.warning(f"Ошибка Diaphora diff: {e}")
            return False

    def _merge_diaphora_into_json(self, json_path: Path, diaphora_sqlite: Path, stem: str) -> None:
        """Сливает результаты Diaphora в .diff.json с разделением по source."""
        if not json_path.is_file():
            return
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        dres = _parse_diaphora_results(diaphora_sqlite)

        # Уже существующие (от BinDiff) помечаем source="bindiff"
        for m in data.get("matched_functions", []):
            if "source" not in m:
                m["source"] = "bindiff"

        # Строим индекс существующих (addr1, addr2)
        existing = {}
        for m in data.get("matched_functions", []):
            key = (m.get("address1", ""), m.get("address2", ""))
            existing[key] = m

        new_matches = []
        both_matches = []   # пары, которые уже были в BinDiff
        for m in dres.get("matched_functions", []):
            key = (m["address1"], m["address2"])
            if key in existing:
                # Есть в обоих — ставим source="both", сохраняем оба similarity
                existing[key]["source"] = "both"
                existing[key]["bindiff_similarity"] = existing[key].get("similarity", 0.0)
                existing[key]["diaphora_similarity"] = m.get("similarity", 0.0)
                both_matches.append(m)
            else:
                new_matches.append(m)
                existing[key] = m

        # Добавляем новые совпадения (только Diaphora)
        data["matched_functions"].extend(new_matches)

        # Собираем matched_summary
        bindiff_only = [m for m in data["matched_functions"] if m.get("source") == "bindiff"]
        diaphora_only = [m for m in data["matched_functions"] if m.get("source") == "diaphora"]
        both_src = [m for m in data["matched_functions"] if m.get("source") == "both"]

        data["matched_summary"] = {
            "total": len(data["matched_functions"]),
            "bindiff_only": len(bindiff_only),
            "diaphora_only": len(diaphora_only),
            "both": len(both_src),
        }
        # Данные по источникам для шаблона
        data["matched_diaphora_only"] = diaphora_only

        # Метаданные
        data["diaphora_matched_count"] = len(new_matches) + len(both_matches)
        data["engine"] = "bindiff+diaphora" if data.get("matched_functions") else "bindiff"
        data["total_matched"] = len(data["matched_functions"])

        # Пробрасываем unmatched из Diaphora
        if "unmatched_functions1" in dres:
            data.setdefault("unmatched_functions1", [])
            existing_un1 = {u.get("address", "") for u in data["unmatched_functions1"]}
            for u in dres["unmatched_functions1"]:
                if u.get("address", "") not in existing_un1:
                    data["unmatched_functions1"].append(u)
                    existing_un1.add(u.get("address", ""))
        if "unmatched_functions2" in dres:
            data.setdefault("unmatched_functions2", [])
            existing_un2 = {u.get("address", "") for u in data["unmatched_functions2"]}
            for u in dres["unmatched_functions2"]:
                if u.get("address", "") not in existing_un2:
                    data["unmatched_functions2"].append(u)
                    existing_un2.add(u.get("address", ""))

        # Распределение алгоритмов Diaphora
        ad = data.setdefault("algorithm_distribution", {})
        for algo_name, cnt in dres.get("diaphora_algorithm_distribution", {}).items():
            ad[algo_name] = ad.get(algo_name, 0) + cnt
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def _export_cfg_pair(self, primary_i64: Path, secondary_i64: Path, stem: str) -> Tuple[Optional[dict], Optional[dict]]:
        """Экспортирует SVG-графы. Возвращает (pr_index, sc_index) {hex_addr: rel_svg_path}."""
        cfg_dir = self.output_dir / "cfg" / stem
        cfg_dir.mkdir(parents=True, exist_ok=True)
        out_pr = cfg_dir / "primary"
        out_sc = cfg_dir / "secondary"
        for i64, out_dir in [(primary_i64, out_pr), (secondary_i64, out_sc)]:
            cmd = [
                self.idat_path, "-A",
                f"-S\"{_EXPORT_CFG_SCRIPT}\"",
                f"output={out_dir}",
                str(i64),
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=False,
                               encoding="utf-8", errors="replace")
            except Exception:
                pass

        def _load_cfg_index(base_dir: Path, side: str) -> Optional[dict]:
            """Читает cfg_manifest.json и строит {hex_addr: rel_path}."""
            mp = base_dir / "cfg_manifest.json"
            if not mp.is_file():
                return None
            try:
                with open(mp, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except (OSError, json.JSONDecodeError):
                return None
            idx = {}
            for func_name, rel in raw.items():
                if not rel:
                    continue
                try:
                    addr_hex = Path(rel).stem.split("_")[-1]
                    idx[f"0x{addr_hex}"] = f"cfg/{stem}/{side}/{rel}"
                except (IndexError, ValueError):
                    continue
            return idx

        pr_idx = _load_cfg_index(out_pr, "primary")
        sc_idx = _load_cfg_index(out_sc, "secondary")
        return pr_idx, sc_idx

    def _export_binexport(self, i64_path: Path, output_file: Path) -> bool:
        if self._cancel_event.is_set():
            return False
        output_file.unlink(missing_ok=True)
        cmd = [self.idat_path, "-A",
               f"-OBinExportAutoAction:BinExportBinary",
               f"-OBinExportModule:{output_file}",
               str(i64_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                  encoding='utf-8', errors='replace')
            if proc.returncode != 0 or not output_file.is_file():
                detail = f"stdout:\n{(proc.stdout or '')[:500]}\nstderr:\n{(proc.stderr or '')[:500]}"
                logger.error(f"BinExport {i64_path.name}: {detail}")
                self._safe_emit(self.error_occurred, f"Ошибка BinExport {i64_path.name}")
                return False
            return True
        except Exception as e:
            logger.exception(f"Ошибка BinExport: {e}")
            return False

    def _run_bindiff(self, primary: Path, secondary: Path, output: Path) -> bool:
        tmp_dir = output.parent / f"{output.stem}_tmp"
        shutil.rmtree(tmp_dir, ignore_errors=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)
        cmd = [self.bindiff_path, "--primary", str(primary), "--secondary", str(secondary), "--output_dir", str(tmp_dir)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                return False
            diff_files = list(tmp_dir.glob("*.BinDiff"))
            if not diff_files:
                return False
            output.unlink(missing_ok=True)
            shutil.move(str(diff_files[0]), str(output))
            return True
        except Exception as e:
            logger.exception(f"BinDiff: {e}")
            return False
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _get_table_columns(conn: sqlite3.Connection, table: str) -> set:
        try:
            cur = conn.execute(f"PRAGMA table_info(\"{table}\")")
            return {row[1] for row in cur.fetchall()}
        except sqlite3.Error:
            return set()

    def _parse_bindiff_result(self, db_path: Path, primary: str, secondary: str,
                              json_output: Path) -> None:
        result = {
            "primary": primary, "secondary": secondary,
            "similarity": 0.0, "confidence": 0.0,
            "description": "", "version": "", "created": "", "modified": "",
            "file1": {}, "file2": {},
            "matched_functions": [],
            "total_functions1": 0, "total_functions2": 0,
            "error": None, "engine": "bindiff",
        }
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                cur = conn.cursor()
                # metadata
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
                # file info
                cur.execute("SELECT * FROM file ORDER BY id")
                file_rows = cur.fetchall()
                if len(file_rows) >= 2:
                    file_cols = [desc[0] for desc in cur.description]
                    f1 = dict(zip(file_cols, file_rows[0]))
                    f2 = dict(zip(file_cols, file_rows[1]))
                    for f_dict, key in [(f1, "file1"), (f2, "file2")]:
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
                # function matches
                func_columns = self._get_table_columns(conn, "function")
                COL_ALIASES = {
                    "address1": ["address1"], "name1": ["name1"],
                    "address2": ["address2"], "name2": ["name2"],
                    "similarity": ["similarity", "sim"],
                    "confidence": ["confidence", "conf"],
                    "flags": ["flags"], "algorithm": ["algorithm", "algo"],
                    "basicblocks": ["basicblocks", "basic_blocks", "basicblocks_count"],
                    "edges": ["edges", "edgecount", "edge_count"],
                    "instructions": ["instructions", "instructioncount", "instruction_count"],
                }
                actual_to_canonical = {}
                for cn, aliases in COL_ALIASES.items():
                    for a in aliases:
                        if a in func_columns:
                            actual_to_canonical[a] = cn
                            break
                if actual_to_canonical:
                    algo_names = {}
                    try:
                        ac = self._get_table_columns(conn, "functionalgorithm")
                        if {"id", "name"}.issubset(ac):
                            ar = cur.execute("SELECT id, name FROM functionalgorithm").fetchall()
                            algo_names = {r[0]: r[1] for r in ar}
                    except sqlite3.Error:
                        pass
                    col_list = ", ".join(actual_to_canonical.keys())
                    cur.execute(f"SELECT {col_list} FROM function ORDER BY similarity DESC")
                    for row in cur.fetchall():
                        entry = {}
                        for idx, (act_col, cn) in enumerate(actual_to_canonical.items()):
                            rv = row[idx]
                            if cn in ("address1", "address2") and rv is not None:
                                entry[cn] = f"0x{int(rv):X}"
                            elif cn in ("similarity", "confidence") and rv is not None:
                                entry[cn] = round(float(rv), 4)
                            elif cn in ("name1", "name2"):
                                entry[cn] = rv if rv else "<unnamed>"
                            else:
                                entry[cn] = rv if rv is not None else 0
                        entry.setdefault("similarity", 0.0)
                        entry.setdefault("confidence", 0.0)
                        entry["algorithm_name"] = algo_names.get(entry.get("algorithm", 0), f"#{entry.get('algorithm', 0)}")
                        entry["source"] = "bindiff"
                        result["matched_functions"].append(entry)
                # similarity distribution
                sim_buckets = {"1.0": 0, "0.95_0.99": 0, "0.80_0.94": 0, "0.50_0.79": 0, "below_0.50": 0}
                for mf in result.get("matched_functions", []):
                    s = mf.get("similarity", 0.0)
                    if s >= 1.0: sim_buckets["1.0"] += 1
                    elif s >= 0.95: sim_buckets["0.95_0.99"] += 1
                    elif s >= 0.80: sim_buckets["0.80_0.94"] += 1
                    elif s >= 0.50: sim_buckets["0.50_0.79"] += 1
                    else: sim_buckets["below_0.50"] += 1
                result["similarity_distribution"] = sim_buckets
                # algorithm distribution
                try:
                    ad_bd = {}
                    cur.execute("""
                        SELECT fa.name, COUNT(*) FROM function f
                        LEFT JOIN functionalgorithm fa ON f.algorithm = fa.id
                        GROUP BY f.algorithm ORDER BY COUNT(*) DESC""")
                    for r in cur.fetchall():
                        ad_bd[r[0] or f"#{r[0]}"] = r[1]
                    result["algorithm_distribution"] = ad_bd
                except sqlite3.Error:
                    pass
                # struct stats — всё мёртвое, убираем присвоения кроме basicblocks/instructions для matched_functions
                for mf in result["matched_functions"]:
                    mf["basicblocks"] = mf.get("basicblocks", 0)
                    mf["instructions"] = mf.get("instructions", 0)
            finally:
                conn.close()
        except Exception as e:
            result["error"] = str(e)
            logger.exception("Ошибка парсинга BinDiff")
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    def _export_json(self, primary_i64: Path, primary_out: Path,
                     secondary_i64: Path, secondary_out: Path) -> dict:
        result = {"primary": None, "secondary": None}
        for i64_path, json_path in [(primary_i64, primary_out), (secondary_i64, secondary_out)]:
            if self._cancel_event.is_set():
                break
            cmd = [self.idat_path, "-A", f"-S\"{_EXPORT_DATA_SCRIPT}\" pseudocode=1", str(i64_path)]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                      encoding="utf-8", errors="replace")
                if proc.returncode != 0:
                    continue
                src = Path(str(i64_path) + ".export.json")
                if src.is_file() and src != json_path:
                    shutil.move(str(src), str(json_path))
                if json_path.is_file():
                    key = "primary" if i64_path == primary_i64 else "secondary"
                    result[key] = json_path
            except Exception as e:
                logger.exception(f"Ошибка JSON-экспорта {i64_path.name}: {e}")
                self._safe_emit(self.error_occurred, f"Ошибка JSON-экспорта {i64_path.name}: {e}")
        return result

    @staticmethod
    def _enrich_diff_json(diff_json: Path, primary_json: Optional[Path],
                          secondary_json: Optional[Path]) -> None:
        try:
            with open(diff_json, "r", encoding="utf-8") as f:
                diff_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        primary_imports = set()
        secondary_imports = set()
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
        for mf in diff_data.get("matched_functions", []):
            addr1 = mf.get("address1", "")
            addr2 = mf.get("address2", "")
            f1 = primary_funcs.get(addr1)
            f2 = secondary_funcs.get(addr2)
            if f1 is None:
                name1 = mf.get("name1", "")
                n1 = name1.replace("sub_", "") if name1.startswith("sub_") else name1
                for v in primary_funcs.values():
                    if v.get("name") == n1 or v.get("name") == name1:
                        f1 = v
                        break
            if f2 is None:
                name2 = mf.get("name2", "")
                n2 = name2.replace("sub_", "") if name2.startswith("sub_") else name2
                for v in secondary_funcs.values():
                    if v.get("name") == n2 or v.get("name") == name2:
                        f2 = v
                        break
            mf["pseudocode1"] = f1["pseudocode"] if f1 else ""
            mf["pseudocode2"] = f2["pseudocode"] if f2 else ""
            mf["hexdump1"] = f1["hexdump"] if f1 else ""
            mf["hexdump2"] = f2["hexdump"] if f2 else ""
            if f1 and f2 and f1["pseudocode"] and f2["pseudocode"]:
                lines1 = f1["pseudocode"].splitlines()
                lines2 = f2["pseudocode"].splitlines()
                diff_rows = []
                for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, lines1, lines2).get_opcodes():
                    if tag == "equal":
                        for k in range(i1, i2):
                            diff_rows.append({"type": "equal", "left": lines1[k], "right": lines2[j1 + k - i1]})
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
            # insn types diff per pair
            if f1 and f2:
                it1 = f1.get("insn_types", {})
                it2 = f2.get("insn_types", {})
                all_mnes = sorted(set(list(it1.keys()) + list(it2.keys())))
                insn_diff = []
                for mne in all_mnes:
                    c1 = it1.get(mne, 0)
                    c2 = it2.get(mne, 0)
                    if c1 != c2:
                        insn_diff.append({"mnemonic": mne, "count1": c1, "count2": c2, "diff": c2 - c1})
                mf["insn_type_diff"] = insn_diff
                mf["insn_types1"] = it1
                mf["insn_types2"] = it2
                # call graph
                callees1 = set(f1.get("callees", []))
                callees2 = set(f2.get("callees", []))
                mf["callees_only1"] = sorted(callees1 - callees2)
                mf["callees_only2"] = sorted(callees2 - callees1)
                mf["callees_common"] = sorted(callees1 & callees2)
            else:
                mf["insn_type_diff"] = []
                mf["insn_types1"] = {}
                mf["insn_types2"] = {}
                mf["callees_only1"] = []
                mf["callees_only2"] = []
                mf["callees_common"] = []
        # global insn diff
        all_types1 = {}
        all_types2 = {}
        for mf in diff_data.get("matched_functions", []):
            addr1 = mf.get("address1", "")
            f1 = primary_funcs.get(addr1)
            if f1 is None:
                name1 = mf.get("name1", "")
                n1 = name1.replace("sub_", "") if name1.startswith("sub_") else name1
                for v in primary_funcs.values():
                    if v.get("name") == n1 or v.get("name") == name1:
                        f1 = v
                        break
            if f1:
                for mne, cnt in f1.get("insn_types", {}).items():
                    all_types1[mne] = all_types1.get(mne, 0) + cnt
            addr2 = mf.get("address2", "")
            f2 = secondary_funcs.get(addr2)
            if f2 is None:
                name2 = mf.get("name2", "")
                n2 = name2.replace("sub_", "") if name2.startswith("sub_") else name2
                for v in secondary_funcs.values():
                    if v.get("name") == n2 or v.get("name") == name2:
                        f2 = v
                        break
            if f2:
                for mne, cnt in f2.get("insn_types", {}).items():
                    all_types2[mne] = all_types2.get(mne, 0) + cnt
        all_mnes = sorted(set(list(all_types1.keys()) + list(all_types2.keys())))
        diff_data["global_insn_diff"] = [
            {"mnemonic": mne, "count1": all_types1.get(mne, 0), "count2": all_types2.get(mne, 0), "diff": all_types2.get(mne, 0) - all_types1.get(mne, 0)}
            for mne in all_mnes
        ]

        with open(diff_json, "w", encoding="utf-8") as f:
            json.dump(diff_data, f, indent=2, ensure_ascii=False)