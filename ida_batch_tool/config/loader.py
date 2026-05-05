"""Загрузка и сохранение конфигурации из config.yaml."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, Optional

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"


def _default_config() -> Dict[str, Any]:
    return {
        "ida": {
            "idat64": "idat.exe",
            "idat32": "idat.exe",
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


def get_ida_executable(arch: str = "64") -> str:
    cfg = load_config()
    key = f"idat{arch}"
    return cfg.get("ida", {}).get(key, f"idat{arch}.exe")


def get_max_ida() -> int:
    return load_config().get("max_ida", 4)


def get_default_inputdir() -> str:
    return load_config().get("default_inputdir", ".")