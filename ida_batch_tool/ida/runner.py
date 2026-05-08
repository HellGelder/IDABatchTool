"""
Управление запуском IDA Pro в пакетном режиме.
Поддерживает параллельный анализ файлов и выполнение скриптов на готовых .i64.
"""
from __future__ import annotations

import subprocess
import time
import logging
import os
import struct                     # CHANGED: оставлен, т.к. используется в другом месте
from pathlib import Path
from typing import List, Optional, Callable, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from ida_batch_tool.config.loader import get_ida_executable, get_max_ida

logger = logging.getLogger(__name__)

ID0_EXT = ".id0"
ID1_EXT = ".id1"
NAM_EXT = ".nam"
TIL_EXT = ".til"
ASM_EXT = ".asm"
LOG_EXT = ".log"

DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0


class IDAAnalyzer:
    """Класс для пакетного анализа файлов в IDA Pro."""

    def __init__(self, idat_path: Optional[str] = None, max_workers: Optional[int] = None):
        self.idat: str = idat_path or get_ida_executable()
        self.max_workers: int = max_workers or get_max_ida()
        self._progress_callback: Optional[Callable[[str, int, int], None]] = None
        self._file_start_callback: Optional[Callable[[str], None]] = None
        self._file_done_callback: Optional[Callable[[str, bool], None]] = None

    def set_progress_callback(self, callback: Callable[[str, int, int], None]) -> None:
        self._progress_callback = callback

    def set_file_start_callback(self, callback: Callable[[str], None]) -> None:
        self._file_start_callback = callback

    def set_file_done_callback(self, callback: Callable[[str, bool], None]) -> None:
        self._file_done_callback = callback

    # ------------------------------------------------------------------
    # Анализ файлов (создание .i64)
    # ------------------------------------------------------------------
    @staticmethod
    def _unique_idb_path(file_path: Path, output_dir: Path) -> Path:
        return output_dir / (file_path.name + ".i64")

    def analyze_file(self, file_path: Path, output_dir: Optional[Path] = None,
                     script_path: Optional[Path] = None,
                     keep_log_on_error: bool = True) -> bool:
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return False

        if self._file_start_callback:
            self._file_start_callback(file_path.name)

        out_dir = output_dir or file_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)

        idb_path = self._unique_idb_path(file_path, out_dir)
        log_path = out_dir / (file_path.name + LOG_EXT)

        cmd = [self.idat, "-B", f"-o{idb_path}", f"-L{log_path}"]
        if script_path:
            cmd.append(f"-S{script_path}")
        cmd.append(str(file_path))

        logger.info(f"Starting IDA: {cmd}")
        return self._run_process(cmd, file_path, idb_path, log_path, keep_log_on_error)

    def analyze_batch(self, files: List[Path], output_dir: Optional[Path] = None,
                      script_path: Optional[Path] = None,
                      cleanup_temp: bool = True, temp_cleanup: bool = True) -> Dict[Path, bool]:
        total = len(files)
        results: Dict[Path, bool] = {}
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {}
            for f in files:
                future = executor.submit(self.analyze_file, f, output_dir, script_path)
                future_to_file[future] = f

            for future in as_completed(future_to_file):
                f = future_to_file[future]
                try:
                    success = future.result()
                    results[f] = success
                except Exception as e:
                    logger.error(f"Error during analysis of {f}: {e}")
                    results[f] = False
                completed += 1
                if self._progress_callback:
                    self._progress_callback(f.name, completed, total)
                if self._file_done_callback:
                    self._file_done_callback(f.name, results[f])

        if cleanup_temp or temp_cleanup:
            logger.info("Starting delayed cleanup of temporary files...")
            for f, success in results.items():
                if not success:
                    continue
                out_dir = output_dir or f.parent
                idb_path = self._unique_idb_path(f, out_dir)
                log_path = out_dir / (f.name + LOG_EXT)
                if cleanup_temp:
                    self._safe_clean_file(log_path, "log")
                    asm_path = idb_path.with_suffix(ASM_EXT)
                    self._safe_clean_file(asm_path, "asm")
                if temp_cleanup:
                    for ext in (ID0_EXT, ID1_EXT, NAM_EXT, TIL_EXT):
                        for temp_file in out_dir.glob(f"*{ext}"):
                            self._safe_clean_file(temp_file, ext[1:])

        return results

    # ------------------------------------------------------------------
    # Выполнение скрипта на существующих .i64/.idb
    # ------------------------------------------------------------------
    def run_script_on_idb(self, idb_path: Path, script_path: Path,
                          output_dir: Optional[Path] = None,
                          script_args: Optional[Dict[str, str]] = None) -> bool:
        if not idb_path.exists():
            logger.error(f"Database not found: {idb_path}")
            return False
        if not script_path.exists():
            logger.error(f"Script not found: {script_path}")
            return False

        if self._file_start_callback:
            self._file_start_callback(idb_path.name)

        out_dir = output_dir or idb_path.parent
        log_path = out_dir / (idb_path.stem + "_script.log")

        if script_args:
            args_str = " ".join(f"{k}={v}" for k, v in script_args.items())
            script_cmd = f'"{script_path}" {args_str}'
        else:
            script_cmd = f'"{script_path}"'

        cmd = [self.idat, "-A", f"-S{script_cmd}", f"-L{log_path}", str(idb_path)]

        logger.info(f"Running script on {idb_path.name}: {script_cmd}")
        return self._run_process(cmd, idb_path, None, log_path, keep_log_on_error=True)

    def run_script_on_batch(self, idb_files: List[Path], script_path: Path,
                            output_dir: Optional[Path] = None,
                            script_args: Optional[Dict[str, str]] = None) -> Dict[Path, bool]:
        total = len(idb_files)
        results: Dict[Path, bool] = {}
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {}
            for f in idb_files:
                future = executor.submit(self.run_script_on_idb, f, script_path, output_dir, script_args)
                future_to_file[future] = f

            for future in as_completed(future_to_file):
                f = future_to_file[future]
                try:
                    success = future.result()
                    results[f] = success
                except Exception as e:
                    logger.error(f"Error running script on {f}: {e}")
                    results[f] = False
                completed += 1
                if self._progress_callback:
                    self._progress_callback(f.name, completed, total)
                if self._file_done_callback:
                    self._file_done_callback(f.name, results[f])

        return results

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    def _run_process(self, cmd: List[str], target_path: Path,
                     idb_path: Optional[Path], log_path: Path,
                     keep_log_on_error: bool) -> bool:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
            proc.wait()
            ret = proc.returncode

            if idb_path is not None:
                temp_id0 = idb_path.with_suffix(".id0")
                if temp_id0.exists():
                    logger.error(f"IDA crashed on {target_path.name}: .id0 still present")
                    if keep_log_on_error and log_path.exists():
                        self._log_tail(log_path)
                    return False

            if ret != 0:
                logger.error(f"IDA failed on {target_path.name}: returncode={ret}")
                if keep_log_on_error and log_path.exists():
                    self._log_tail(log_path)
                return False

            if idb_path is not None and not idb_path.exists():
                logger.error(f"Database not created for {target_path.name}: {idb_path}")
                return False

            return True
        except Exception as e:
            logger.exception(f"Error running IDA for {target_path.name}: {e}")
            return False

    @staticmethod
    def _safe_clean_file(file_path: Path, description: str = "",
                         retries: int = DEFAULT_RETRIES,
                         delay: float = DEFAULT_RETRY_DELAY) -> None:
        if not file_path.exists():
            return
        for attempt in range(1, retries + 1):
            try:
                file_path.unlink()
                logger.info(f"Removed {description}: {file_path.name}")
                return
            except PermissionError as e:
                if attempt < retries:
                    logger.warning(f"Could not remove {file_path.name} (attempt {attempt}): {e}. Retrying...")
                    time.sleep(delay)
                else:
                    logger.warning(f"Could not remove {file_path.name} after {retries} attempts: {e}")
            except Exception as e:
                logger.warning(f"Could not remove {file_path.name}: {e}")
                break

    # CHANGED: удалён неиспользуемый метод _detect_arch

    @staticmethod
    def _log_tail(log_path: Path, lines: int = 10) -> None:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                log_lines = f.readlines()
            if log_lines:
                logger.error("Last lines from IDA log:\n" + "".join(log_lines[-lines:]))
        except Exception as e:
            logger.warning(f"Could not read log: {e}")