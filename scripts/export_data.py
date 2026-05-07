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

# Для парсинга DT_NEEDED (только необходимые библиотеки, без привязки символов)
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[IDAPython] pyelftools не установлен. Установите: pip install pyelftools")
    idc.qexit(1)


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
# Получение DT_NEEDED (список необходимых библиотек)
# ------------------------------------------------------------
def _get_needed_libraries(elf_path: str) -> List[str]:
    """Возвращает список библиотек из DT_NEEDED ELF-файла."""
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

    is_elf = _is_elf_file()
    kernel_version = idaapi.get_kernel_version()
    current_file_path = idc.get_input_file_path()

    data: Dict[str, Any] = {
        "file_name": current_file_path,
        "is_elf": is_elf,
        "functions": [],
        "imports": [],
        "exports": [],
        "elf_sections": [],
        "needed_libs": [],
        "ida_info": {"kernel_version": kernel_version}
    }

    # --- Для ELF: получаем только список зависимых библиотек (без привязки символов) ---
    if is_elf and current_file_path and os.path.exists(current_file_path):
        data["needed_libs"] = _get_needed_libraries(current_file_path)
        print(f"[IDAPython] Найдены библиотеки: {data['needed_libs']}")
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
    # Импорты (только имена, без библиотек)
    # ----------------------------------------------------------------
    try:
        import_module_count = ida_nalt.get_import_module_qty()
    except AttributeError:
        import_module_count = 0

    raw_imports: List[Dict[str, Any]] = []
    for mod_index in range(import_module_count):
        def callback(ea, name, ordinal):
            if name:
                clean = _strip_symbol_version(name) if is_elf else name
                demangled = _normalize_func_name(clean)
                if is_elf:
                    # Для ELF сохраняем только имя и адрес, поле module не заполняем
                    raw_imports.append({
                        "name": demangled,
                        "address": f"0x{ea:X}"
                    })
                else:
                    # Для PE используем модуль из IDA
                    try:
                        mod_name = ida_nalt.get_import_module_name(mod_index)
                    except AttributeError:
                        mod_name = "unknown"
                    raw_imports.append({
                        "name": demangled,
                        "module": mod_name,
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