"""Изолированные классификаторы по платформам. Без пустой строки в расширениях."""
from __future__ import annotations

import re
import logging
from typing import Dict, Optional, Tuple

from .windows import WINDOWS_MODULES
from .linux import LINUX_MODULES
from .android import ANDROID_MODULES
from .macos import MACOS_MODULES
from .third_party_platforms import (
    THIRD_PARTY_WINDOWS,
    THIRD_PARTY_LINUX,
    THIRD_PARTY_MACOS,
)

logger = logging.getLogger(__name__)


def _normalize_name(name: str) -> str:
    """Нормализация имени модуля: обрезает путь, расширение, приводит к нижнему регистру."""
    if not name:
        return ""
    # Убираем путь
    if '\\' in name or '/' in name:
        name = name.replace('\\', '/').split('/')[-1]
    # Убираем расширения (важно: без пустой строки!)
    for ext in ('.dll', '.so', '.dylib', '.drv', '.sys', '.exe', '.framework'):
        if name.endswith(ext):
            name = name[:-len(ext)]
            break
    # Убираем версионные суффиксы .1.dylib, .2.dylib (если остались)
    if '.dylib' in name:
        name = name.split('.dylib')[0]
    # Убираем @rpath/
    if name.startswith('@rpath/'):
        name = name[7:]
    return name.lower()


class BasePlatformClassifier:
    def __init__(self, platform_name: str, system_dicts: Dict[str, str],
                 third_party_dicts: Dict[str, str]):
        self.name = platform_name
        merged = {}
        merged.update(system_dicts)
        merged.update(third_party_dicts)
        self._normalized: Dict[str, str] = {
            _normalize_name(k): v for k, v in merged.items()
        }

    def classify(self, module_name: str) -> Optional[str]:
        norm = _normalize_name(module_name)
        return self._normalized.get(norm)


class WindowsClassifier(BasePlatformClassifier):
    def __init__(self):
        super().__init__("Windows", WINDOWS_MODULES, THIRD_PARTY_WINDOWS)

    def classify(self, module_name: str) -> Optional[str]:
        res = super().classify(module_name)
        if res:
            return res
        if module_name.startswith("api-ms-win-"):
            return "Windows API Set (контрактная DLL)"
        if module_name.startswith("ext-ms-win-"):
            return "Windows API Set (расширенная контрактная DLL)"
        if re.search(r'msvc|vcruntime|msvcp|concrt|vcomp|mfc|atl', module_name, re.I):
            return "Вероятно, библиотека времени выполнения Microsoft Visual C++"
        return None


class LinuxClassifier(BasePlatformClassifier):
    def __init__(self):
        system = {}
        system.update(LINUX_MODULES)
        system.update(ANDROID_MODULES)
        super().__init__("Linux/Android", system, THIRD_PARTY_LINUX)


class MacOSClassifier(BasePlatformClassifier):
    def __init__(self):
        super().__init__("macOS/iOS", MACOS_MODULES, THIRD_PARTY_MACOS)

    def classify(self, module_name: str) -> Optional[str]:
        res = super().classify(module_name)
        if res:
            return res
        if re.search(r'libswift|libobjc|libdispatch', module_name, re.I):
            return "Вероятно, компонент Swift / Objective‑C runtime"
        return None


class CompositeClassifier:
    def __init__(self):
        self._classifiers = [
            MacOSClassifier(),
            LinuxClassifier(),
            WindowsClassifier(),
        ]

    def classify(self, module_name: str) -> str:
        if module_name == "<self>":
            return "Собственный исполняемый модуль"
        for c in self._classifiers:
            desc = c.classify(module_name)
            if desc:
                return desc
        return "Неопознанный модуль"


_composite = CompositeClassifier()


def classify_module(module_name: str) -> str:
    return _composite.classify(module_name)


def get_platform_classifier(platform: str) -> BasePlatformClassifier:
    if platform == "Windows":
        return WindowsClassifier()
    elif platform == "Linux / Android":
        return LinuxClassifier()
    elif platform == "macOS / iOS":
        return MacOSClassifier()
    else:
        raise ValueError(f"Unknown platform: {platform}")