"""Загрузка и сохранение конфигурации из config.yaml.
Поиск IDA и BinDiff в системе (только Windows)."""
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

_IDA_EXECUTABLE_NAME = "idat.exe"
_BINDIFF_EXECUTABLE_NAME = "bindiff.exe"


def _default_config() -> Dict[str, Any]:
    return {
        "ida": {
            "executable": _IDA_EXECUTABLE_NAME,
        },
        "bindiff": {
            "executable": _BINDIFF_EXECUTABLE_NAME,
        },
        "max_ida": 4,
        "default_inputdir": ".",
        "log_level": "INFO",
        "theme": "light",
        "sf_db_path": "databases",
    }


def _merge_with_defaults(user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    default = _default_config()
    for key, value in default.items():
        if key not in user_cfg:
            user_cfg[key] = value
        elif isinstance(value, dict):
            for subkey, subval in value.items():
                if subkey not in user_cfg[key]:
                    user_cfg[key][subkey] = subval
    return user_cfg


def get_sf_db_path() -> str:
    return load_config().get("sf_db_path", "databases")


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


def get_max_ida() -> int:
    return load_config().get("max_ida", 4)


def get_default_inputdir() -> str:
    return load_config().get("default_inputdir", ".")


# ──────────────────────────────────────────────
#  Поиск исполняемых файлов (только Windows)
# ──────────────────────────────────────────────

def _read_registry(key_path: str, value_name: str) -> Optional[str]:
    """Читает строковое значение из реестра Windows (HKLM или HKCU)."""
    try:
        import winreg
        for hive, hive_name in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"),
                                 (winreg.HKEY_CURRENT_USER, "HKCU")]:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if value:
                        return value
            except OSError:
                pass
            # Попробовать 32-битное представление (WOW6432Node)
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if value:
                        return value
            except OSError:
                pass
    except ImportError:
        pass
    return None


def _find_in_path(exe_name: str) -> Optional[Path]:
    """Ищет исполняемый файл в системном PATH (добавляет .exe при необходимости)."""
    if sys.platform == "win32" and not exe_name.lower().endswith(".exe"):
        exe_name += ".exe"
    found = shutil.which(exe_name)
    return Path(found).resolve() if found else None


def _find_in_program_files(*patterns: str) -> Optional[Path]:
    r"""Ищет исполняемый файл в C:\Program Files и C:\Program Files (x86) по шаблонам.
    patterns — список фрагментов пути для glob-поиска, например:
      "IDA*/idat.exe", "IDA Professional */idat.exe", "IDA Pro */idat.exe"
    """
    for pf in ("C:\\Program Files", "C:\\Program Files (x86)"):
        base = Path(pf)
        if not base.is_dir():
            continue
        for pattern in patterns:
            matches = list(base.glob(pattern))
            if matches:
                return matches[0].resolve()
            # Поиск без учёта регистра первой буквы (для "ida"/"IDA")
            matches = list(base.glob(pattern[0].lower() + pattern[1:]))
            if matches:
                return matches[0].resolve()
    return None


def _find_ida_in_common_locations() -> Optional[Path]:
    """Поиск idat.exe в типичных Windows-каталогах."""
    # 1) Реестр Hex-Rays
    reg_path = _read_registry(r"SOFTWARE\Hex-Rays\IDA", "InstallDir")
    if reg_path:
        candidate = Path(reg_path) / "idat.exe"
        if candidate.is_file():
            return candidate.resolve()
        candidate = Path(reg_path) / "idat64.exe"
        if candidate.is_file():
            return candidate.resolve()

    # 2) Реестр IDA Pro (альтернативный ключ)
    reg_path = _read_registry(r"SOFTWARE\IDA Pro", "InstallDir")
    if reg_path:
        candidate = Path(reg_path) / "idat.exe"
        if candidate.is_file():
            return candidate.resolve()
        candidate = Path(reg_path) / "idat64.exe"
        if candidate.is_file():
            return candidate.resolve()

    # 3) Program Files — основные варианты
    candidates = [
        "IDA*/idat.exe",
        "IDA*/idat64.exe",
        "IDA Professional */idat.exe",
        "IDA Professional */idat64.exe",
        "IDA Pro */idat.exe",
        "IDA Pro */idat64.exe",
        "Hex-Rays/IDA*/idat.exe",
        "Hex-Rays/IDA*/idat64.exe",
    ]
    found = _find_in_program_files(*candidates)
    if found:
        return found

    # 4) PATH (на случай если idat добавлен туда вручную)
    found = _find_in_path("idat.exe")
    if found:
        return found
    found = _find_in_path("idat64.exe")
    if found:
        return found

    return None


def _find_bindiff_in_common_locations() -> Optional[Path]:
    """Поиск bindiff.exe в типичных Windows-каталогах."""
    # 1) Реестр Zynamics / Google BinDiff
    reg_path = _read_registry(r"SOFTWARE\Zynamics\BinDiff", "InstallDir")
    if reg_path:
        candidate = Path(reg_path) / "bindiff.exe"
        if candidate.is_file():
            return candidate.resolve()

    reg_path = _read_registry(r"SOFTWARE\Google\BinDiff", "InstallDir")
    if reg_path:
        candidate = Path(reg_path) / "bindiff.exe"
        if candidate.is_file():
            return candidate.resolve()

    # 2) Реестр BinDiff (альтернативный ключ)
    reg_path = _read_registry(r"SOFTWARE\BinDiff", "InstallDir")
    if reg_path:
        candidate = Path(reg_path) / "bindiff.exe"
        if candidate.is_file():
            return candidate.resolve()

    # 3) Program Files
    candidates = [
        "BinDiff*/bindiff.exe",
        "BinDiff */bindiff.exe",
        "zynamics/BinDiff*/bindiff.exe",
        "Google/BinDiff*/bindiff.exe",
    ]
    found = _find_in_program_files(*candidates)
    if found:
        return found

    # 4) PATH
    found = _find_in_path("bindiff.exe")
    if found:
        return found
    found = _find_in_path("BinDiff.exe")
    if found:
        return found

    return None


def _find_in_project_root(basename: str) -> Optional[Path]:
    """Ищет файл в корне проекта (рядом с config.yaml)."""
    candidate = PROJECT_ROOT / basename
    return candidate.resolve() if candidate.is_file() else None


# ──────────────────────────────────────────────
#  Публичные функции
# ──────────────────────────────────────────────

def get_ida_executable() -> str:
    r"""
    Возвращает полный путь к idat.exe (Windows).

    Порядок поиска:
      1. Значение из config.yaml (ключ 'ida.executable').
      2. Реестр Windows (HKLM\SOFTWARE\Hex-Rays\IDA\InstallDir и др.).
      3. Поиск в C:\Program Files и C:\Program Files (x86)
         (IDA Professional 9.*, IDA Pro 9.*, IDA*).
      4. Системный PATH.
    Если ничего не найдено, возвращает просто 'idat.exe'.
    """
    cfg = load_config()
    name = cfg.get("ida", {}).get("executable", _IDA_EXECUTABLE_NAME)

    # 1. Если это уже полный путь и файл существует — используем его
    if os.path.isabs(name):
        p = Path(name)
        if p.is_file():
            return str(p.resolve())
        # Путь задан, но не существует — не ищем дальше, возвращаем как есть
        return name

    # 2. Поиск в системе
    found = _find_ida_in_common_locations()
    if found:
        return str(found)

    # 3. Поиск рядом с config.yaml (на случай ручного размещения)
    found = _find_in_project_root("idat.exe")
    if found:
        return str(found)

    return name


def get_bindiff_executable() -> str:
    r"""
    Возвращает полный путь к bindiff.exe (Windows).

    Порядок поиска:
      1. Значение из config.yaml (ключ 'bindiff.executable').
      2. Корень проекта (рядом с config.yaml).
      3. Реестр Windows (Zynamics\BinDiff, Google\BinDiff).
      4. C:\Program Files\BinDiff*.
      5. Системный PATH.
    Если ничего не найдено, возвращает просто 'bindiff.exe'.
    """
    cfg = load_config()
    name = cfg.get("bindiff", {}).get("executable", _BINDIFF_EXECUTABLE_NAME)

    # 1. Полный путь из конфига
    if os.path.isabs(name):
        p = Path(name)
        if p.is_file():
            return str(p.resolve())
        return name

    # 2. Корень проекта (пользователь сказал, что bindiff всегда лежит рядом)
    found = _find_in_project_root(name)
    if found:
        return str(found)
    found = _find_in_project_root("bindiff.exe")
    if found:
        return str(found)

    # 3. Поиск в системе
    found = _find_bindiff_in_common_locations()
    if found:
        return str(found)

    return name
