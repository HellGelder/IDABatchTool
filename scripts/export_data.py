"""
IDAPython-скрипт для экспорта данных из IDA Pro в JSON.
Запускается через idat.exe -A -Sexport_data.py <файл.i64>

Параметры (передаются после имени скрипта в кавычках):
    pseudocode=1 – генерировать псевдокод только для экспортных функций
"""
import json
import os
import re
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

import idaapi
import idautils
import idc
import ida_nalt
import ida_bytes

# Для парсинга DT_NEEDED (ELF)
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[IDAPython] pyelftools не установлен. ELF-зависимости не будут получены.")

# Для парсинга Mach-O
try:
    from macholib.MachO import MachO
    from macholib.mach_o import LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB
    MACHO_AVAILABLE = True
except ImportError:
    MACHO_AVAILABLE = False
    print("[IDAPython] macholib не установлен. Mach-O-зависимости не будут получены.")


# ------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------
def _get_file_format() -> str:
    """Определяет формат файла, загруженного в IDA: 'pe', 'elf', 'macho' или 'unknown'."""
    try:
        raw = ida_bytes.get_bytes(0, 4)
        if raw[:4] == b'\x7fELF':
            return 'elf'
        if raw[:2] == b'MZ':
            return 'pe'
        # Mach-O magic: 0xfeedface (32-bit), 0xfeedfacf (64-bit), 0xcafebabe (fat binary)
        magic = struct.unpack('<I', raw[:4])[0] if len(raw) >= 4 else 0
        if magic in (0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcefaedfe, 0xcffaedfe):
            return 'macho'
    except Exception:
        pass
    return 'unknown'


def _is_macho_file() -> bool:
    return _get_file_format() == 'macho'


def _is_elf_file() -> bool:
    return _get_file_format() == 'elf'


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
    return False


def _try_init_hexrays() -> bool:
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            print("[IDAPython] Hex‑Rays инициализирован.")
            return True
        else:
            print("[IDAPython] Hex‑Rays не инициализирован.")
            return False
    except ImportError:
        print("[IDAPython] Hex‑Rays не найден.")
        return False


def _decompile_function(ea: int, hexrays_available: bool) -> str:
    if not hexrays_available:
        return "Декомпилятор недоступен."
    try:
        import ida_hexrays
        cfunc = ida_hexrays.decompile(ea)
        return str(cfunc) if cfunc else "Декомпиляция не удалась."
    except Exception as e:
        return f"Ошибка: {e}"


def _strip_symbol_version(name: str) -> str:
    return re.sub(r'@+[\w.]+$', '', name)


def _normalize_func_name(name: str) -> str:
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    if demangled:
        name = demangled
    for prefix in ('sub_', 'j_', 'def_', 'nullsub_'):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = re.sub(r'(_\d+)$', '', name) if len(name) > 5 else name
    name = re.sub(r'_{2,}', '_', name)
    name = name.strip()
    return name


# ------------------------------------------------------------
# Парсинг DT_NEEDED (ELF)
# ------------------------------------------------------------
def _get_elf_needed_libraries(elf_path: str) -> List[str]:
    try:
        with open(elf_path, 'rb') as f:
            elffile = ELFFile(f)
            dynamic = None
            for segment in elffile.iter_segments():
                if segment['p_type'] == 'PT_DYNAMIC':
                    dynamic = segment
                    break
            if not dynamic:
                dynamic = elffile.get_section_by_name('.dynamic')
            if not dynamic:
                return []
            needed = []
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed.append(tag.needed)
            return needed
    except Exception as e:
        print(f"[IDAPython] Ошибка получения DT_NEEDED: {e}")
        return []


# ------------------------------------------------------------
# Парсинг LC_LOAD_DYLIB (Mach-O)
# ------------------------------------------------------------
def _get_macho_dependencies(macho_path: str) -> List[str]:
    """Возвращает список зависимостей Mach-O из LC_LOAD_DYLIB и аналогичных команд."""
    if not MACHO_AVAILABLE:
        print("[IDAPython] macholib не установлен. Зависимости Mach-O не будут получены.")
        return []
    try:
        macho = MachO(macho_path)
        dependencies = []
        for header in macho.headers:
            for cmd, cmd_data, _ in header.commands:
                if cmd.cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB):
                    # Извлекаем имя библиотеки
                    data = cmd_data
                    if isinstance(data, bytes):
                        # Пропускаем заголовок команды (16 байт для 64-бит)
                        name_data = data[16:]
                        null_pos = name_data.find(b'\x00')
                        if null_pos != -1:
                            lib_name = name_data[:null_pos].decode('utf-8')
                            if lib_name not in dependencies:
                                dependencies.append(lib_name)
        return dependencies
    except Exception as e:
        print(f"[IDAPython] Ошибка парсинга Mach-O зависимостей: {e}")
        return []


# ------------------------------------------------------------
# Основная функция экспорта
# ------------------------------------------------------------
def export_to_json(output_path: Optional[str] = None) -> None:
    idaapi.auto_wait()

    if output_path is None:
        idb_path = idc.get_idb_path()
        if not idb_path:
            print("Не удалось получить путь к базе данных.")
            idc.qexit(1)
        output_path = idb_path + ".export.json"

    file_format = _get_file_format()
    is_elf = (file_format == 'elf')
    is_macho = (file_format == 'macho')
    kernel_version = idaapi.get_kernel_version()
    current_file_path = idc.get_input_file_path()

    data: Dict[str, Any] = {
        "file_name": current_file_path,
        "is_elf": is_elf,
        "is_macho": is_macho,
        "functions": [],
        "imports": [],
        "exports": [],
        "elf_sections": [],
        "needed_libs": [],
        "ida_info": {"kernel_version": kernel_version}
    }

    # --- Для ELF: получаем список библиотек DT_NEEDED ---
    if is_elf and current_file_path and os.path.exists(current_file_path):
        data["needed_libs"] = _get_elf_needed_libraries(current_file_path)
        print(f"[IDAPython] ELF: найдены библиотеки: {data['needed_libs']}")
    # --- Для Mach-O: получаем список библиотек LC_LOAD_DYLIB ---
    elif is_macho and current_file_path and os.path.exists(current_file_path):
        data["needed_libs"] = _get_macho_dependencies(current_file_path)
        print(f"[IDAPython] Mach-O: найдены зависимости: {data['needed_libs']}")
    else:
        data["needed_libs"] = []

    # --- Псевдокод ---
    pseudocode_enabled = _pseudocode_enabled()
    hexrays_available = False
    if pseudocode_enabled:
        print("[IDAPython] Генерация псевдокода для экспортных функций.")
        hexrays_available = _try_init_hexrays()

    # ----------------------------------------------------------------
    # Экспорты
    # ----------------------------------------------------------------
    exports: List[Dict[str, Any]] = []
    for i in range(idc.get_entry_qty()):
        entry = idc.get_entry_ordinal(i)
        if entry != -1:
            addr = idc.get_entry(entry)
            name = idc.get_entry_name(addr)
            if name:
                if is_elf:
                    name = _strip_symbol_version(name)
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
                if is_elf:
                    name = _strip_symbol_version(name)
                name = _normalize_func_name(name)
                exports.append({
                    "name": name,
                    "address": f"0x{ea:X}",
                    "ordinal": len(exports)
                })

    data["exports"] = exports
    export_eas: Set[int] = {int(exp["address"], 16) for exp in exports}

    # ----------------------------------------------------------------
    # Функции (дизассемблер + псевдокод для экспортов)
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
    # Импорты (через IDA API)
    # ----------------------------------------------------------------
    try:
        import_module_count = ida_nalt.get_import_module_qty()
    except AttributeError:
        import_module_count = 0

    raw_imports: List[Dict[str, Any]] = []
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

    print(f"[IDAPython] Экспорт завершён: {output_path}")
    idc.qexit(0)


if __name__ == "__main__":
    export_to_json()