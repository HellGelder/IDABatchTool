"""Загрузка и сохранение конфигурации из config.yaml."""
from __future__ import annotations

import os
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
    """Возвращает словарь конфигурации по умолчанию.
    
    Returns:
        Dict[str, Any]: Базовая конфигурация с параметрами IDA (idat), 
                       количеством потоков (4), директорией ввода ("."), 
                       уровнем логирования (INFO) и темой (light).
    """
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
    """Объединяет пользовательскую конфигурацию с дефолтными значениями.
    
    Args:
        user_cfg (Dict[str, Any]): Конфигурация, загруженная из config.yaml.
        
    Returns:
        Dict[str, Any]: Полная конфигурация с заполненными значениями по умолчанию.
                       Гарантирует наличие всех ключей даже если они отсутствуют в user_cfg.
    """
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
    """Загружает конфигурацию из файла config.yaml или возвращает значения по умолчанию.
    
    Args:
        config_path (Optional[Path]): Путь к файлу конфигурации. Если None, используется 
                                      стандартный путь PROJECT_ROOT / "config.yaml".
                                      
    Returns:
        Dict[str, Any]: Полная конфигурация с объединением пользовательских и дефолтных значений.
                       При отсутствии файла возвращается полная конфигурация по умолчанию.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return _default_config()
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return _merge_with_defaults(cfg)


def save_config(config_dict: Dict[str, Any], config_path: Optional[Path] = None) -> None:
    """Сохраняет конфигурацию в файл YAML.
    
    Args:
        config_dict (Dict[str, Any]): Словарь конфигурации для сохранения.
        config_path (Optional[Path]): Путь к файлу конфигурации. Если None, используется 
                                      стандартный путь PROJECT_ROOT / "config.yaml".
                                      
    Note:
        Создаёт родительские директории файла, если они не существуют.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, allow_unicode=True)


def _find_in_path(executable: str) -> Optional[Path]:
    """Ищет исполняемый файл в системном PATH (для Windows добавляет .exe при необходимости).
    
    Args:
        executable (str): Имя исполняемого файла или путь к нему.
        
    Returns:
        Optional[Path]: Полный путь к найденному файлу, если он существует в PATH.
                       Возвращает None, если файл не найден.
    """
    if sys.platform == "win32" and not executable.endswith(".exe"):
        exe_path = shutil.which(executable + ".exe")
        if exe_path:
            return Path(exe_path)
    exe_path = shutil.which(executable)
    return Path(exe_path) if exe_path else None


def _find_ida_manually() -> Optional[Path]:
    """Ищет IDA Pro 9.0+ в типичных директориях установки для различных ОС.
    
    Returns:
        Optional[Path]: Полный путь к исполняемому файлу idat, если найден.
                       Возвращает None, если IDA не найдена ни в одной из стандартных 
                       директорий установки.
                       
    Note:
        Windows: C:/Program Files/IDA Professional 9.X/
        Linux: ~/ida-pro-9.0/, ~/ida/, /opt/ida-pro-9.0/, /opt/ida/
        macOS: /Applications/IDA Professional 9.X/Contents/MacOS
    """
    name = _IDA_EXECUTABLE_NAME
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
        exe = base / name
        if exe.is_file():
            return exe
        if sys.platform == "win32":
            exe_win = base / (name + ".exe")
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

    # 2. Поиск в PATH
    found = _find_in_path(name)
    if found:
        return str(found)

    # 3. Типичные папки установки
    found_man = _find_ida_manually()
    if found_man:
        return str(found_man)

    return name


def get_max_ida() -> int:
    """Возвращает максимальное количество параллельных потоков IDA из конфигурации.
    
    Returns:
        int: Максимальное число одновременно работающих экземпляров IDA.
             По умолчанию — 4, если параметр не указан в config.yaml.
             
    Note:
        Значение должно быть разумным (рекомендуется 2-8) для избежания 
        перегрузки системы при параллельном анализе.
    """
    return load_config().get("max_ida", 4)


def get_default_inputdir() -> str:
    """Возвращает директорию по умолчанию для поиска файлов анализа.
    
    Returns:
        str: Путь к директории по умолчанию. По умолчанию — текущая директория (".").
             
    Note:
        Этот путь используется в GUI при инициализации поля ввода директории,
        если пользователь не указал явный путь.
    """
    return load_config().get("default_inputdir", ".")
