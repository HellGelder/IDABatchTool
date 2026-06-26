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


def _compute_hex_similarity(file1: Path, file2: Path) -> float:
    try:
        data1 = file1.read_bytes()
        data2 = file2.read_bytes()
    except (OSError, PermissionError):
        return 0.0
    if not data1 or not data2:
        return 0.0
    block_size = 4096
    blocks1 = set()
    for offset in range(0, len(data1), block_size):
        blocks1.add(hashlib.sha256(data1[offset:offset + block_size]).hexdigest())
    blocks2 = set()
    for offset in range(0, len(data2), block_size):
        blocks2.add(hashlib.sha256(data2[offset:offset + block_size]).hexdigest())
    if not blocks1 or not blocks2:
        return 0.0
    overlap = len(blocks1 & blocks2)
    total = len(blocks1 | blocks2)
    size_ratio = min(len(data1), len(data2)) / max(len(data1), len(data2), 1)
    return round((overlap / total) * size_ratio, 4)


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


def _compute_hexdump_diff(orig1: Path, orig2: Path) -> list:
    """Сравнивает два исполняемых файла поблочно (16 байт) как hexdump, пропуская идентичное."""
    try:
        data1 = orig1.read_bytes()
        data2 = orig2.read_bytes()
    except (OSError, PermissionError):
        return []
    if not data1 or not data2:
        return []

    def _format_hex_block(data: bytes, addr: int) -> str:
        hex_part = ' '.join(f'{b:02x}' for b in data)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        return f'{addr:08x}  {hex_part:<48}  |{ascii_part}|'

    block_size = 16
    lines1 = []
    for offset in range(0, len(data1), block_size):
        chunk = data1[offset:offset + block_size]
        lines1.append(_format_hex_block(chunk, offset))

    lines2 = []
    for offset in range(0, len(data2), block_size):
        chunk = data2[offset:offset + block_size]
        lines2.append(_format_hex_block(chunk, offset))

    import difflib
    matcher = difflib.SequenceMatcher(None, lines1, lines2)
    hex_rows = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            if hex_rows and hex_rows[-1].get("type") != "skip":
                hex_rows.append({"type": "skip", "count": 0})
            if hex_rows and hex_rows[-1]["type"] == "skip":
                hex_rows[-1]["count"] += (i2 - i1)
            else:
                hex_rows.append({"type": "skip", "count": i2 - i1})
        elif tag == "delete":
            for k in range(i1, i2):
                hex_rows.append({"type": "removed", "left": lines1[k], "right": ""})
        elif tag == "insert":
            for k in range(j1, j2):
                hex_rows.append({"type": "added", "left": "", "right": lines2[k]})
        elif tag == "replace":
            for k in range(i1, i2):
                hex_rows.append({"type": "removed", "left": lines1[k], "right": ""})
            for k in range(j1, j2):
                hex_rows.append({"type": "added", "left": "", "right": lines2[k]})

    return hex_rows


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
    finished = Signal(int, int)
    error_occurred = Signal(str)

    def __init__(self, file_pairs: List[Tuple[Path, Path, str]],
                 idat_path: str, bindiff_path: str,
                 output_dir: Path,
                 engine: str = "bindiff",
                 max_workers: int = 2, parent=None):
        super().__init__(parent)
        self.file_pairs = file_pairs
        self.idat_path = idat_path
        self.bindiff_path = bindiff_path
        self.output_dir = output_dir
        self.engine = engine
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
        logger.info(f"Сравнение {total} пар, engine={self.engine}, результаты в {self.output_dir}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_pair = {
                executor.submit(self._process_pair, primary, secondary, rel_key, idx): (primary, secondary, rel_key, idx)
                for idx, (primary, secondary, rel_key) in enumerate(self.file_pairs)
            }
            for future in as_completed(future_to_pair):
                if self._cancel_event.is_set():
                    for f in future_to_pair:
                        f.cancel()
                    break
                primary, secondary, rel_key, idx = future_to_pair[future]
                try:
                    ok = future.result()
                    with self._lock:
                        self._completed_count += 1
                        if ok:
                            self.progress_updated.emit(self._completed_count, total, rel_key)
                except Exception as e:
                    logger.exception(f"Ошибка пары {rel_key}")
                    self.error_occurred.emit(f"Ошибка пары {rel_key}: {e}")
                    with self._lock:
                        self._completed_count += 1

        logger.info(f"Завершено. Всего обработано: {self._completed_count}")
        self.finished.emit(self._completed_count, total)

    def _process_pair(self, primary_i64: Path, secondary_i64: Path, rel_key: str, idx: int) -> bool:
        stem = _safe_filename(rel_key)
        if self._cancel_event.is_set():
            return False

        try:
            json_output = self.output_dir / f"{stem}.diff.json"

            # === BINDIFF PATH ===
            if self.engine in ("bindiff", "both"):
                primary_binexport = self.output_dir / f"{stem}_primary.BinExport"
                secondary_binexport = self.output_dir / f"{stem}_secondary.BinExport"
                if not self._export_binexport(primary_i64, primary_binexport):
                    return False
                if not self._export_binexport(secondary_i64, secondary_binexport):
                    return False
                diff_output = self.output_dir / f"{stem}.BinDiff"
                if not self._run_bindiff(primary_binexport, secondary_binexport, diff_output):
                    self.error_occurred.emit(f"BinDiff: {stem}")
                    return False
                self._parse_bindiff_result(diff_output, str(primary_i64), str(secondary_i64), json_output)

            # === DIAPHORA PATH ===
            if self.engine in ("diaphora", "both"):
                if _DIAPHORA_SCRIPT.is_file():
                    diaphora_db_pr = self.output_dir / f"{stem}_primary.diaphora.sqlite"
                    diaphora_db_sc = self.output_dir / f"{stem}_secondary.diaphora.sqlite"
                    diaphora_result = self.output_dir / f"{stem}_diaphora_result.sqlite"
                    # Экспорт primary
                    if not self._run_diaphora_export(primary_i64, diaphora_db_pr):
                        self.error_occurred.emit(f"Diaphora экспорт primary {stem}")
                    # Экспорт secondary
                    if not self._run_diaphora_export(secondary_i64, diaphora_db_sc):
                        self.error_occurred.emit(f"Diaphora экспорт secondary {stem}")
                    # Diff
                    if diaphora_db_pr.is_file() and diaphora_db_sc.is_file():
                        if self._run_diaphora_diff(diaphora_db_pr, diaphora_db_sc, diaphora_result):
                            self._merge_diaphora_into_json(json_output, diaphora_result, stem)
                else:
                    logger.warning(f"Diaphora не найден: {_DIAPHORA_SCRIPT}")

            # === JSON EXPORT + CFG + HEX SIMILARITY ===
            primary_json = self.output_dir / f"{stem}_primary.export.json"
            secondary_json = self.output_dir / f"{stem}_secondary.export.json"
            exported = self._export_json(primary_i64, primary_json, secondary_i64, secondary_json)
            self._enrich_diff_json(json_output, exported["primary"], exported["secondary"])
            self._add_hex_similarity(json_output, primary_i64, secondary_i64)

            # === HEXDUMP DIFF оригинальных исполняемых файлов ===
            orig1 = _find_original_binary(primary_i64)
            orig2 = _find_original_binary(secondary_i64)
            if orig1 and orig2:
                try:
                    with open(json_output, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    hex_rows = _compute_hexdump_diff(orig1, orig2)
                    data["global_hex_diff"] = [{
                        "name1": orig1.name,
                        "address1": "0x0",
                        "name2": orig2.name,
                        "address2": "0x0",
                        "hex_rows": hex_rows,
                    }]
                    with open(json_output, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                except (OSError, json.JSONDecodeError):
                    pass

            # CFG-экспорт и запись путей SVG в .diff.json
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

            # === Вычисляем полный список несопоставленных функций из IDA-экспорта ===
            try:
                with open(json_output, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Собираем адреса сопоставленных функций (primary)
                matched_addrs = set()
                for mf in data.get("matched_functions", []):
                    addr = mf.get("address1", "")
                    if addr:
                        matched_addrs.add(addr)

                # Читаем primary-экспорт, находим реальные несопоставленные функции
                unmatched_funcs = []
                for pj_path in (exported.get("primary"), exported.get("secondary")):
                    if pj_path and pj_path.is_file():
                        try:
                            with open(pj_path, "r", encoding="utf-8") as pf:
                                pdata = json.load(pf)
                            for func in pdata.get("functions", []):
                                addr = func.get("start_ea", "")
                                if addr and addr not in matched_addrs:
                                    unmatched_funcs.append({
                                        "address": addr,
                                        "name": func.get("name", "<unnamed>")
                                    })
                        except (OSError, json.JSONDecodeError):
                            pass
                    break  # только primary, secondary через unmatched_functions2

                if unmatched_funcs:
                    data.setdefault("unmatched_functions1", unmatched_funcs)
                total1 = data.get("total_functions1", 0)
                matched_cnt = len(data.get("matched_functions", []))
                data["total_unmatched"] = total1 - matched_cnt

                with open(json_output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except (OSError, json.JSONDecodeError):
                pass

            for p in (primary_json, secondary_json):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
            return True
        except Exception as e:
            logger.exception(f"Ошибка {stem}: {e}")
            self.error_occurred.emit(f"Ошибка {stem}: {e}")
            return False

    def _run_diaphora_export(self, i64_path: Path, out_sqlite: Path) -> bool:
        """Запускает diaphora.py --export через IDA с переменными окружения."""
        env = os.environ.copy()
        env["DIAPHORA_AUTO"] = "1"
        env["DIAPHORA_EXPORT_FILE"] = str(out_sqlite)
        cmd = [
            self.idat_path, "-A",
            f"-S\"{_DIAPHORA_SCRIPT}\"",
            str(i64_path),
        ]
        logger.info(f"Diaphora экспорт: {' '.join(str(c) for c in cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                  encoding="utf-8", errors="replace", timeout=300, env=env)
            return proc.returncode == 0 and out_sqlite.is_file()
        except subprocess.TimeoutExpired:
            self.error_occurred.emit(f"Таймаут Diaphora экспорта {i64_path.name}")
            return False
        except Exception as e:
            logger.warning(f"Ошибка Diaphora экспорта: {e}")
            return False

    def _run_diaphora_diff(self, db1: Path, db2: Path, out_sqlite: Path) -> bool:
        """Запускает diaphora.py --diff (не требует IDA).
        В standalone-режиме использует argparse: diaphora.py db1 db2 -o out"""
        cmd = [sys.executable, str(_DIAPHORA_SCRIPT), str(db1), str(db2), "-o", str(out_sqlite)]
        logger.info(f"Diaphora diff: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                  encoding="utf-8", errors="replace", timeout=600)
            return proc.returncode == 0 and out_sqlite.is_file()
        except subprocess.TimeoutExpired:
            self.error_occurred.emit("Таймаут Diaphora diff")
            return False
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
        data["matched_bindiff_only"] = bindiff_only
        data["matched_diaphora_only"] = diaphora_only
        data["matched_both"] = both_src

        # Метаданные
        data["diaphora_matched_count"] = len(new_matches) + len(both_matches)
        data["engine"] = "bindiff+diaphora" if data.get("matched_functions") else "bindiff"
        # Пересчитываем total_matched с учётом обоих движков
        data["total_matched"] = len(data["matched_functions"])

        # Пробрасываем unmatched из Diaphora
        if "unmatched_functions1" in dres:
            data.setdefault("unmatched_functions1", [])
            # Объединяем существующие (от BinDiff) с Diaphora
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
                               encoding="utf-8", errors="replace", timeout=120)
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
                self.error_occurred.emit(f"Ошибка BinExport {i64_path.name}")
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
                    ad = {}
                    cur.execute("""
                        SELECT fa.name, COUNT(*) FROM function f
                        LEFT JOIN functionalgorithm fa ON f.algorithm = fa.id
                        GROUP BY f.algorithm ORDER BY COUNT(*) DESC""")
                    for r in cur.fetchall():
                        ad[r[0] or f"#{r[0]}"] = r[1]
                    result["algorithm_distribution"] = ad
                except sqlite3.Error:
                    pass
                # renamed
                result["renamed_functions"] = [mf for mf in result["matched_functions"]
                                               if mf.get("name1") and mf.get("name2") and mf["name1"] != mf["name2"]]
                # struct stats
                bb = [mf.get("basicblocks", 0) for mf in result["matched_functions"]]
                insn = [mf.get("instructions", 0) for mf in result["matched_functions"]]
                if bb:
                    result["function_size_stats"] = {
                        "avg_basicblocks": round(sum(bb) / len(bb), 1),
                        "min_basicblocks": min(bb), "max_basicblocks": max(bb),
                        "avg_instructions": round(sum(insn) / len(insn), 1),
                        "min_instructions": min(insn), "max_instructions": max(insn),
                    }
                result["total_matched_basicblocks"] = sum(bb)
                result["total_matched_instructions"] = sum(insn)
                result["total_matched_edges"] = sum(mf.get("edges", 0) for mf in result["matched_functions"])
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
                                      encoding="utf-8", errors="replace", timeout=300)
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
                self.error_occurred.emit(f"Ошибка JSON-экспорта {i64_path.name}: {e}")
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

        # Глобальный hex diff — только различающиеся блоки
        global_hex_diff = []
        for mf in diff_data.get("matched_functions", []):
            s = float(mf.get("similarity", 0.0))
            if s >= 1.0:
                continue  # 100% — пропускаем
            h1 = mf.get("hexdump1", "")
            h2 = mf.get("hexdump2", "")
            if not h1 or not h2:
                continue
            lines1 = h1.splitlines()
            lines2 = h2.splitlines()
            matcher = difflib.SequenceMatcher(None, lines1, lines2)
            hex_rows = []
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == "equal":
                    # Пропускаем идентичные блоки — как в Linux hexdump
                    if hex_rows and hex_rows[-1].get("type") != "skip":
                        hex_rows.append({"type": "skip", "count": 0})
                    if hex_rows and hex_rows[-1]["type"] == "skip":
                        hex_rows[-1]["count"] += (i2 - i1)
                    else:
                        hex_rows.append({"type": "skip", "count": i2 - i1})
                elif tag == "delete":
                    for k in range(i1, i2):
                        hex_rows.append({"type": "removed", "left": lines1[k], "right": ""})
                elif tag == "insert":
                    for k in range(j1, j2):
                        hex_rows.append({"type": "added", "left": "", "right": lines2[k]})
                elif tag == "replace":
                    for k in range(i1, i2):
                        hex_rows.append({"type": "removed", "left": lines1[k], "right": ""})
                    for k in range(j1, j2):
                        hex_rows.append({"type": "added", "left": "", "right": lines2[k]})
            global_hex_diff.append({
                "name1": mf.get("name1", ""),
                "address1": mf.get("address1", ""),
                "name2": mf.get("name2", ""),
                "address2": mf.get("address2", ""),
                "hex_rows": hex_rows,
            })
        diff_data["global_hex_diff"] = global_hex_diff

        with open(diff_json, "w", encoding="utf-8") as f:
            json.dump(diff_data, f, indent=2, ensure_ascii=False)

    def _add_hex_similarity(self, json_output: Path, primary_i64: Path, secondary_i64: Path) -> None:
        if not json_output.is_file():
            return
        try:
            with open(json_output, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        hex_sim = _compute_hex_similarity(primary_i64, secondary_i64)
        data["hex_similarity"] = hex_sim
        bs = float(data.get("similarity", 0.0))
        zf = (data.get("total_functions1", 0) == 0 and data.get("total_functions2", 0) == 0)
        tm = len(data.get("matched_functions", []))
        if zf or tm == 0:
            data["blended_similarity"] = hex_sim
            data["similarity_source"] = "hexdump"
        elif bs > 0:
            data["blended_similarity"] = round((bs + hex_sim) / 2, 4)
            data["similarity_source"] = "blended"
        else:
            data["blended_similarity"] = hex_sim
            data["similarity_source"] = "hexdump"
        try:
            with open(json_output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except OSError:
            pass