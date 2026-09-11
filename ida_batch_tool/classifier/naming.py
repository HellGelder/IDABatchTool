"""Единая нормализация имён модулей (библиотек) для всего проекта.

Одна и та же библиотека должна приводиться к одному ключу везде: в
классификаторе, в индексе системных функций и в генераторах отчётов.
Это исключает ситуацию, когда ``KERNEL32.dll`` и ``kernel32.dll``
считаются двумя разными библиотеками.
"""
from __future__ import annotations

import re

# Расширения модулей по платформам. Срезается ровно одно расширение,
# поэтому версии вида ``libc.so.6`` сохраняют номер и совпадают с ключами
# словарей (``libc.so.6``), а не превращаются в ``libc``.
MODULE_EXTENSIONS: tuple[str, ...] = (
    # Windows
    ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".scr", ".efi",
    # Linux / Android
    ".so", ".ko", ".o", ".elf",
    # macOS / iOS
    ".dylib", ".framework", ".bundle",
)

# Префиксы путей Mach-O, которые встречаются в поле module до срезания пути.
_DYLD_PREFIXES: tuple[str, ...] = (
    "@rpath/", "@loader_path/", "@executable_path/",
)


def normalize_module_name(module_name: str) -> str:
    """Приводит имя модуля к каноническому ключу.

    Убирает путь, префиксы ``@rpath/@loader_path/@executable_path``,
    одно расширение платформы и приводит к нижнему регистру.
    Возвращает пустую строку для пустого входа.
    """
    if not module_name:
        return ""

    name = module_name.strip()
    if not name:
        return ""

    # Оставляем только последний компонент пути (Windows и POSIX разделители).
    # Для Mach-O ``Foo.framework/Versions/A/Foo`` это даст ``Foo``.
    if "\\" in name or "/" in name:
        name = name.replace("\\", "/").rsplit("/", 1)[-1]

    # Отдельно стоящие префиксы (без разделителя пути) — защитный случай.
    for prefix in _DYLD_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    lowered = name.lower()
    for ext in MODULE_EXTENSIONS:
        if lowered.endswith(ext):
            name = name[: -len(ext)]
            break

    return name.lower()


def _strip_path_and_lower(name: str) -> str:
    """Убирает путь и префиксы Mach-O, приводит к нижнему регистру.

    Расширение сохраняется — это нужно для построения вариантов имён,
    в которых платформенный маркер (``.so`` / ``.dylib``) значим.
    """
    if not name:
        return ""
    name = name.strip()
    if "\\" in name or "/" in name:
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
    for prefix in _DYLD_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name.lower()


# Варианты имён с сохранением платформенного маркера. Безверсионная форма
# обязана сохранять ``.so`` / ``.dylib``: иначе ``libz.so.1`` (Linux) и
# ``libz.1.dylib`` (macOS) дали бы общий ключ ``libz`` и Linux-импорт
# ошибочно считался бы системным при анализе macOS.
_SO_FLAVOR_RE = re.compile(
    r"^(?P<base>.+?\.so)(?:\.\d+)*$",  # libz.so.1.2.11 -> libz.so
    re.IGNORECASE,
)
_DYLIB_FLAVOR_RE = re.compile(
    r"^(?P<base>.+?)\.(?:[0-9]+(?:\.[0-9]+)*|[a-z])\.dylib$",
    # libz.1.2.dylib / libSystem.B.dylib -> libz.dylib / libsystem.dylib
    re.IGNORECASE,
)


def module_name_aliases(module_name: str) -> tuple[str, ...]:
    """Возвращает варианты ключа модуля для сопоставления со словарями.

    Первый элемент — канонический ключ ``normalize_module_name``. При
    наличии версии добавляется форма с сохранённым платформенным маркером
    (``libz.so.1.2.11`` → ``libz.so``, ``libz.1.2.dylib`` → ``libz.dylib``).
    Это позволяет находить системную библиотеку при несовпадении точной
    версии, не смешивая библиотеки разных платформ.
    """
    key = normalize_module_name(module_name)
    if not key:
        return ()

    aliases = [key]
    full = _strip_path_and_lower(module_name)

    so_match = _SO_FLAVOR_RE.match(full)
    if so_match:
        alias = so_match.group("base")
        if alias and alias not in aliases:
            aliases.append(alias)

    dylib_match = _DYLIB_FLAVOR_RE.match(full)
    if dylib_match:
        alias = dylib_match.group("base") + ".dylib"
        if alias not in aliases:
            aliases.append(alias)

    return tuple(aliases)
