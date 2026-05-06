"""
IDAPython-скрипт для экспорта данных из IDA Pro в JSON.
Запускается через idat.exe -A -Sexport_data.py <файл.i64>
Совместим с IDA Pro 9.3.

Параметры скрипта (передаются после имени скрипта в кавычках):
    pseudocode=1          – генерировать псевдокод для экспортируемых функций
    inputdir=<путь>       – корневая директория проекта для поиска internal-библиотек
"""
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

import idaapi
import idautils
import idc
import ida_nalt
import ida_bytes


# ------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------
def _is_elf_file() -> bool:
    try:
        raw = ida_bytes.get_bytes(0, 4)
        return raw[:4] == b'\x7fELF'
    except Exception:
        return False


def _format_hexdump_with_ascii(data: bytes, start_addr: int = 0) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        addr = f'{start_addr + offset:08x}'
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{addr}  {hex_part:<48}  |{ascii_part}|')
    return '\n'.join(lines)


def _get_argv_param(prefix: str) -> Optional[str]:
    for arg in idc.ARGV:
        if arg.startswith(prefix + "="):
            return arg.split("=", 1)[1].strip()
    return None


def _pseudocode_enabled() -> bool:
    val = _get_argv_param("pseudocode")
    if val is not None:
        return val.lower() in ("1", "true", "yes")
    return os.environ.get('IDA_PSEUDOCODE', '0') == '1'


def _try_init_hexrays() -> bool:
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            print("[IDAPython] Плагин Hex‑Rays успешно инициализирован.")
            return True
        else:
            print("[IDAPython] Не удалось инициализировать Hex‑Rays.")
            return False
    except ImportError:
        print("[IDAPython] Модуль ida_hexrays не найден.")
        return False


def _decompile_function(ea: int, hexrays_available: bool) -> str:
    if not hexrays_available:
        return "Декомпилятор недоступен."
    try:
        import ida_hexrays
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc) if cfunc else "Декомпиляция не удалась."
    except ida_hexrays.DecompilationFailure as e:
        return f"Ошибка декомпиляции: {e}"
    except Exception as e:
        return f"Неизвестная ошибка: {e}"


def _strip_symbol_version(name: str) -> str:
    """Удаляет суффикс версии символа (@@GLIBC_2.4, @OPENSSL_1_1_0 и т.п.)."""
    return re.sub(r'@+[\w.]+$', '', name)


def _normalize_func_name(name: str) -> str:
    """Demangle и чистка префиксов."""
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    if demangled:
        name = demangled
    for prefix in ('sub_', 'j_', 'def_', 'nullsub_'):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name


# ------------------------------------------------------------
# Парсинг ELF‑зависимостей (DT_NEEDED)
# ------------------------------------------------------------
def _parse_elf_dependencies(filepath: str) -> List[str]:
    try:
        from elftools.elf.elffile import ELFFile
        with open(filepath, 'rb') as f:
            elffile = ELFFile(f)
            dynamic = elffile.get_section_by_name('.dynamic')
            if not dynamic:
                for sec in elffile.iter_sections():
                    if sec.header['sh_type'] == 'SHT_DYNAMIC':
                        dynamic = sec
                        break
            if not dynamic:
                print("[IDAPython] Секция .dynamic не найдена.")
                return []
            return [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
    except ImportError:
        print("[IDAPython] pyelftools не установлен.")
        return []
    except Exception as e:
        print(f"[IDAPython] Ошибка парсинга ELF: {e}")
        return []


# ------------------------------------------------------------
# Разрешение импортов через DT_VERNEED
# ------------------------------------------------------------
def _resolve_import_libraries(filepath: str) -> Dict[str, str]:
    """
    Читает DT_VERNEED и строит словарь:
        {имя_символа: имя_библиотеки}
    Использует pyelftools.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        print("[IDAPython] pyelftools не установлен – пропуск разрешения импортов.")
        return {}

    resolver = {}
    try:
        with open(filepath, 'rb') as f:
            elffile = ELFFile(f)

            # Ищем динамические секции
            dynsym = elffile.get_section_by_name('.dynsym')
            if not dynsym:
                for sec in elffile.iter_sections():
                    if isinstance(sec, SymbolTableSection):
                        dynsym = sec
                        break
            if not dynsym:
                return {}

            # Ищем verneed (может быть несколько)
            verneed_sections = []
            for sec in elffile.iter_sections():
                if sec.header.get('sh_type') == 'SHT_GNU_verneed':
                    verneed_sections.append(sec)

            if not verneed_sections:
                # Нет версионных данных – используем только Internal
                return {}

            # Извлекаем символы и индексы версий
            sym_version_indices = {}
            for ver_section in elffile.iter_sections():
                if ver_section.header.get('sh_type') == 'SHT_GNU_versym':
                    for i, entry in enumerate(ver_section.iter_symbols()):
                        sym_version_indices[i] = entry['vs_val']

            # Строим отображение индекс версии -> имя библиотеки
            version_index_to_lib = {}
            for verneed in verneed_sections:
                for file_entry in verneed.iter_versions():
                    lib_name = file_entry.name
                    for ver in file_entry.get_versions():
                        version_index_to_lib[ver['ndx']] = lib_name

            # Сопоставляем символы с библиотеками
            for i, sym in enumerate(dynsym.iter_symbols()):
                if sym.entry['st_shndx'] == 'SHN_UNDEF' and sym.name:
                    vs_val = sym_version_indices.get(i)
                    if vs_val is not None and vs_val > 1:  # 0=local, 1=global undefined
                        lib = version_index_to_lib.get(vs_val)
                        if lib:
                            resolver[sym.name] = lib

            return resolver
    except Exception as e:
        print(f"[IDAPython] Ошибка при разборе VERNEED: {e}")
        return {}


# ------------------------------------------------------------
# Построение карты экспортов (внутренние библиотеки)
# ------------------------------------------------------------
def _build_export_map(search_dir: Optional[str]) -> Dict[str, str]:
    if not search_dir:
        return {}
    root = Path(search_dir)
    if not root.is_dir():
        return {}
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {}

    export_map: Dict[str, str] = {}
    for elf_file in root.rglob('*'):
        if not elf_file.is_file():
            continue
        try:
            with open(elf_file, 'rb') as f:
                if f.read(4) != b'\x7fELF':
                    continue
        except Exception:
            continue
        try:
            with open(elf_file, 'rb') as f:
                elffile = ELFFile(f)
                dynsym = elffile.get_section_by_name('.dynsym')
                if not dynsym:
                    continue
                lib_name = elf_file.name
                for sym in dynsym.iter_symbols():
                    if sym.entry['st_info']['bind'] == 'STB_GLOBAL' and sym.name:
                        export_map[sym.name] = lib_name
        except Exception:
            pass
    return export_map


# ------------------------------------------------------------
# Основная функция экспорта
# ------------------------------------------------------------
def export_to_json(output_path: Optional[str] = None) -> None:
    idaapi.auto_wait()

    if output_path is None:
        idb_path = idc.get_idb_path()
        output_path = idb_path + ".export.json"

    is_elf = _is_elf_file()
    kernel_version = idaapi.get_kernel_version()
    ida_info = {"kernel_version": kernel_version}

    data: Dict[str, Any] = {
        "file_name": idc.get_input_file_path(),
        "is_elf": is_elf,
        "functions": [],
        "imports": [],
        "exports": [],
        "elf_sections": [],
        "needed_libs": [],
        "ida_info": ida_info
    }

    if is_elf:
        data["needed_libs"] = _parse_elf_dependencies(idc.get_input_file_path())

    pseudocode_enabled = _pseudocode_enabled()
    if pseudocode_enabled:
        print("[IDAPython] Генерация псевдокода включена (только для экспортных функций).")
        hexrays_available = _try_init_hexrays()
    else:
        hexrays_available = False

    # ----------------------------------------------------------------
    # Экспорты (собираем адреса)
    # ----------------------------------------------------------------
    exports: List[Dict[str, Any]] = []
    for i in range(idc.get_entry_qty()):
        entry = idc.get_entry_ordinal(i)
        if entry != -1:
            addr = idc.get_entry(entry)
            name = idc.get_entry_name(addr)
            if name:
                name = _strip_symbol_version(name) if is_elf else name
                name = _normalize_func_name(name)
                exports.append({
                    "name": name,
                    "address": f"0x{addr:X}",
                    "ordinal": entry
                })

    if not exports:
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if name and not name.startswith(("sub_", "j_", "def_", "nullsub_")):
                name = _strip_symbol_version(name) if is_elf else name
                name = _normalize_func_name(name)
                exports.append({
                    "name": name,
                    "address": f"0x{ea:X}",
                    "ordinal": len(exports)
                })

    data["exports"] = exports
    export_eas: Set[int] = {int(exp["address"], 16) for exp in exports}

    # ----------------------------------------------------------------
    # Функции
    # ----------------------------------------------------------------
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.size()

        instructions = []
        for head in idautils.Heads(ea, ea + size):
            mnem = idc.print_insn_mnem(head)
            op_str = idc.print_operand(head, 0)
            if mnem:
                instructions.append(f"0x{head:X}  {mnem} {op_str}")
        disassembly_text = '\n'.join(instructions)

        try:
            raw = ida_bytes.get_bytes(ea, size)
            hexdump = _format_hexdump_with_ascii(raw, ea) if raw else ""
        except Exception:
            hexdump = "недоступно"

        pseudocode = ""
        if pseudocode_enabled and ea in export_eas:
            pseudocode = _decompile_function(ea, hexrays_available)

        data["functions"].append({
            "name": _normalize_func_name(name),
            "start_ea": f"0x{ea:X}",
            "size": size,
            "instructions_text": disassembly_text,
            "hexdump": hexdump,
            "pseudocode": pseudocode
        })

    # ----------------------------------------------------------------
    # Импорты
    # ----------------------------------------------------------------
    try:
        import_module_count = ida_nalt.get_import_module_qty()
    except AttributeError:
        import_module_count = 0

    raw_imports: List[Dict[str, str]] = []
    for mod_index in range(import_module_count):
        try:
            module_name = ida_nalt.get_import_module_name(mod_index)
        except AttributeError:
            module_name = "unknown"

        def callback(ea, name, ordinal):
            if name:
                clean = _strip_symbol_version(name) if is_elf else name
                demangled = _normalize_func_name(clean)
                raw_imports.append({
                    "name": demangled,
                    "module": module_name,
                    "address": f"0x{ea:X}"
                })
            return True

        try:
            ida_nalt.enum_import_names(mod_index, callback)
        except AttributeError:
            pass

    # ----------------------------------------------------------------
    # Разрешение импортов ELF через VERNEED + Internal
    # ----------------------------------------------------------------
    if is_elf:
        # VERNEED – прямое указание библиотеки для каждого символа
        verneed_map = _resolve_import_libraries(idc.get_input_file_path())

        # Internal – через export_map
        input_dir = _get_argv_param("inputdir")
        if not input_dir:
            input_dir = os.path.dirname(idc.get_input_file_path())
        export_map = _build_export_map(input_dir)

        for imp in raw_imports:
            sym = imp["name"]
            resolved = set()

            # Проверяем Internal
            if sym in export_map:
                resolved.add(f"Internal/{export_map[sym]}")

            # Проверяем VERNEED (точная привязка через версии)
            if sym in verneed_map:
                resolved.add(verneed_map[sym])

            if resolved:
                imp["resolved_libs"] = list(resolved)
                imp["module_display"] = "/".join(sorted(resolved))
            else:
                imp["resolved_libs"] = []
                imp["module_display"] = imp["module"] if imp["module"] != "unknown" else "ELF"
    else:
        data["needed_libs"] = []
        data["elf_sections"] = []

    data["imports"] = raw_imports

    # ----------------------------------------------------------------
    # Сортировка функций
    # ----------------------------------------------------------------
    data["functions"].sort(
        key=lambda f: (0 if int(f["start_ea"], 16) in export_eas else 1,
                       int(f["start_ea"], 16))
    )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[IDAPython] Данные экспортированы в {output_path}")
    idc.qexit(0)


if __name__ == "__main__":
    export_to_json()