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
import ida_funcs  # for callers/callees
import ida_xref  # for xrefs (cross-references)

# Для парсинга DT_NEEDED (ELF) – с корректной обработкой отсутствия библиотеки
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None
    print("[IDAPython] pyelftools не установлен. ELF-зависимости не будут получены.")


# -------------------------------------------------------------------- #
#  Вспомогательные функции
# -------------------------------------------------------------------- #
def _get_file_format() -> str:
    try:
        raw = ida_bytes.get_bytes(0, 4)
        if raw[:4] == b'\x7fELF':
            return 'elf'
        if raw[:2] == b'MZ':
            return 'pe'
        magic = struct.unpack('<I', raw[:4])[0] if len(raw) >= 4 else 0
        if magic in (0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcefaedfe, 0xcffaedfe):
            return 'macho'
    except Exception:
        pass
    return 'unknown'


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


def _extract_framework_name(raw_path: str) -> str:
    """
    Из полного пути вроде @rpath/Bedrock.framework/Bedrock
    возвращает 'Bedrock.framework'.
    Для /System/Library/Frameworks/Foundation.framework/Foundation
    возвращает 'Foundation.framework'.
    """
    clean = raw_path
    for prefix in ('@rpath/', '@loader_path/'):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    if '.framework' in clean:
        idx = clean.find('.framework')
        clean = clean[:idx + len('.framework')]
        return Path(clean).name
    return Path(clean).name


def _get_elf_needed_libraries(elf_path: str) -> List[str]:
    """Возвращает список DT_NEEDED из ELF-файла или пустой список, если pyelftools недоступен."""
    if ELFFile is None:
        return []

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


# -------------------------------------------------------------------- #
#  Основная функция экспорта
# -------------------------------------------------------------------- #
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

    # --- Псевдокод ---
    pseudocode_on = _pseudocode_enabled()
    hx = False
    if pseudocode_on:
        print("[IDAPython] Включён псевдокод для экспортных функций.")
        hx = _try_init_hexrays()

    # --- Экспорты ---
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
                exports.append({"name": name, "address": f"0x{addr:X}", "ordinal": entry})
    if not exports:
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if name and not name.startswith(("sub_", "j_", "def_", "nullsub_")):
                if is_elf:
                    name = _strip_symbol_version(name)
                exports.append({"name": _normalize_func_name(name),
                                "address": f"0x{ea:X}", "ordinal": len(exports)})
    data["exports"] = exports
    export_eas = {int(e["address"], 16) for e in exports}

    # --- Функции ---
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.size()
        instrs = []
        insn_types = {}  # счётчик по мнемоникам
        callees = []     # функции, вызываемые из этой функции
        xref_list = []   # адреса cross-references (opcodes с call/jmp на другие функции)
        for head in idautils.Heads(ea, ea + size):
            mnem = idc.print_insn_mnem(head)
            op = idc.print_operand(head, 0)
            if mnem:
                instrs.append(f"0x{head:X}  {mnem} {op}")
                insn_types[mnem] = insn_types.get(mnem, 0) + 1
            # Определяем вызовы: call, jmp с reference на другую функцию
            if mnem in ("call", "jmp", "ljmp", "callf"):
                try:
                    for xref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
                        if xref.type in (ida_xref.dr_O, ida_xref.dr_U, ida_xref.fl_CF, ida_xref.fl_JF):
                            target_name = idc.get_func_name(xref.to)
                            if target_name and not target_name.startswith(("sub_", "j_", "def_", "nullsub_")):
                                callees.append(_normalize_func_name(target_name))
                            elif target_name:
                                callees.append(_normalize_func_name(target_name))
                except Exception:
                    pass
        disasm = '\n'.join(instrs)
        try:
            raw = ida_bytes.get_bytes(ea, size)
            hexd = _format_hexdump_with_ascii(raw, ea) if raw else ""
        except Exception:
            hexd = "недоступно"
        pseudo = ""
        if pseudocode_on and ea in export_eas:
            pseudo = _decompile_function(ea, hx)
        data["functions"].append({
            "name": _normalize_func_name(name),
            "start_ea": f"0x{ea:X}",
            "size": size,
            "instructions_text": disasm,
            "hexdump": hexd,
            "pseudocode": pseudo,
            "insn_types": insn_types,
            "callees": list(set(callees)),
        })

    # --- Импорты ---
    try:
        mod_cnt = ida_nalt.get_import_module_qty()
    except AttributeError:
        mod_cnt = 0
    raw_imports = []
    for mod_idx in range(mod_cnt):
        try:
            mod_name = ida_nalt.get_import_module_name(mod_idx)
        except Exception:
            mod_name = "unknown"
        def callback(ea, name, ordinal):
            if name:
                clean = _strip_symbol_version(name) if is_elf else name
                demangled = _normalize_func_name(clean)
                raw_imports.append({"name": demangled, "module": mod_name, "address": f"0x{ea:X}"})
            return True
        try:
            ida_nalt.enum_import_names(mod_idx, callback)
        except Exception:
            pass
    data["imports"] = raw_imports

    # --- Зависимости (needed_libs) ---
    if is_elf and current_file_path and os.path.exists(current_file_path):
        data["needed_libs"] = _get_elf_needed_libraries(current_file_path)
    elif is_macho:
        # Для Mach-O: собираем имена модулей из таблицы импорта IDA и преобразуем их
        unique_modules = set()
        for imp in raw_imports:
            mod = imp.get("module", "")
            if mod and mod.lower() != "unknown":
                unique_modules.add(_extract_framework_name(mod))
        data["needed_libs"] = sorted(unique_modules)
        print(f"[IDAPython] Mach‑O зависимости (из IDA): {data['needed_libs']}")

    # Сортировка функций: экспортные первыми
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