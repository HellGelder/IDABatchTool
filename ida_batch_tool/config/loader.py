"""Загрузка и сохранение конфигурации из config.yaml."""
from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"

# Единое имя исполняемого файла IDA 9.0+
_IDA_EXECUTABLE_NAME = "idat"


def _default_config() -> Dict[str, Any]:
    return {
        "ida": {
            "executable": _IDA_EXECUTABLE_NAME,
        },
        "max_ida": 4,
        "default_inputdir": ".",
        "log_level": "INFO",
        "theme": "light",
    }


def _merge_with_defaults(user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    default = _default_config()
    for key, value in default.items():
        if key not in user_cfg:
            user_cfg[key] = value
    if "ida" in default:
        if "ida" not in user_cfg:
            user_cfg["ida"] = {}
        for subkey, subval in default["ida"].items():
            if subkey not in user_cfg["ida"]:
                user_cfg["ida"][subkey] = subval
    return user_cfg


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return _default_config()
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return _merge_with_defaults(cfg)


def save_config(config_dict: Dict[str, Any], config_path: Optional[Path] = None) -> None:
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, allow_unicode=True)


def _contains_path_traversal(name: str) -> bool:
    """Проверяет, содержит ли имя переходы по каталогам (../ или ..\\)."""
    return bool(re.search(r'(?:(^|[/\\])\.\.(?:[/\\]|$))', name))


def _find_in_path(executable: str) -> Optional[Path]:
    """Ищет исполняемый файл в системном PATH (для Windows добавляет .exe при необходимости)."""
    if sys.platform == "win32" and not executable.endswith(".exe"):
        exe_path = shutil.which(executable + ".exe")
        if exe_path:
            return Path(exe_path)
    exe_path = shutil.which(executable)
    return Path(exe_path) if exe_path else None


def _find_ida_manually(name: str) -> Optional[Path]:
    """Поиск IDA 9.0+ в типичных директориях установки."""
    # Защита от path traversal: при ручном поиске используем только простое имя файла
    if _contains_path_traversal(name) or os.sep in name or '/' in name:
        return None

    possible_dirs = []

    if sys.platform == "win32":
        program_files = Path("C:/Program Files")
        if program_files.exists():
            for d in program_files.iterdir():
                if d.is_dir() and d.name.startswith("IDA Professional 9."):
                    possible_dirs.append(d)
    elif sys.platform == "linux":
        possible_dirs = [
            Path.home() / "ida-pro-9.0",
            Path.home() / "ida",
            Path("/opt/ida-pro-9.0"),
            Path("/opt/ida"),
        ]
    elif sys.platform == "darwin":
        applications = Path("/Applications")
        if applications.exists():
            for d in applications.iterdir():
                if d.is_dir() and d.name.startswith("IDA Professional 9."):
                    possible_dirs.append(d / "Contents/MacOS")
    else:
        return None

    for base in possible_dirs:
        if not base.exists():
            continue
        # Проверяем, что финальный путь остаётся внутри base
        exe = (base / name).resolve()
        try:
            exe.relative_to(base.resolve())
        except ValueError:
            continue
        if exe.is_file():
            return exe
        if sys.platform == "win32":
            exe_win = exe.with_suffix(".exe")
            try:
                exe_win.relative_to(base.resolve())
            except ValueError:
                continue
            if exe_win.is_file():
                return exe_win
    return None


def get_ida_executable() -> str:
    """
    Возвращает полный путь к idat (IDA 9.0+).
    Порядок поиска:
    1. Значение из config.yaml.
    2. Поиск в системном PATH (idat или idat.exe).
    3. Поиск в типичных папках установки.
    Если ничего не найдено, возвращает значение из конфига.
    """
    cfg = load_config()
    name = cfg.get("ida", {}).get("executable", _IDA_EXECUTABLE_NAME)

    # 1. Полный путь из конфига?
    if os.path.isabs(name):
        p = Path(name)
        if p.is_file():
            return str(p)
        return name  # не файл, но возвращаем как есть

    # Защита от path traversal в относительном имени (для поиска)
    if _contains_path_traversal(name):
        return name

    # 2. Поиск в PATH
    found = _find_in_path(name)
    if found:
        return str(found)

    # 3. Типичные папки установки
    found_man = _find_ida_manually(name)
    if found_man:
        return str(found_man)

    return name


def get_max_ida() -> int:
    return load_config().get("max_ida", 4)


def get_default_inputdir() -> str:
    return load_config().get("default_inputdir", ".")