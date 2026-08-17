"""
IDAPython-скрипт для экспорта данных из IDA Pro в JSON.
Запускается через idat.exe -A -Sexport_data.py <файл.i64>

Параметры (передаются после имени скрипта в кавычках):
    pseudocode=1 – генерировать псевдокод только для экспортных функций
"""
import hashlib
import json
import os
import re
import struct
import zlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

import idaapi
import idautils
import idc
import ida_nalt
import ida_bytes
import ida_funcs  # for callers/callees
import ida_xref  # for xrefs (cross-references)

# Нативные API IDA для информации о файле (хеши, компилятор, формат).
# В старых версиях IDA модули могут отсутствовать — тогда используются fallback'и.
try:
    import ida_ida
except ImportError:
    ida_ida = None
try:
    import ida_typeinf
except ImportError:
    ida_typeinf = None

# Для парсинга DT_NEEDED (ELF) – с корректной обработкой отсутствия библиотеки.
# pyelftools используется ТОЛЬКО как fallback, когда IDA Pro не даёт нужных полей
# (DT_NEEDED / DT_SONAME / DT_RPATH / DT_RUNPATH / .comment) нативными API.
try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None
    print("[IDAPython] pyelftools не установлен. ELF-зависимости будут получены только из IDA.")


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


def _get_file_type_name() -> str:
    """Возвращает человекочитаемое имя типа входного файла (f_ELF → 'ELF', и т.д.)."""
    try:
        ft = ida_ida.inf_get_filetype() if ida_ida is not None else None
        if ft is None:
            return ""
        names = {
            "f_PE": "PE",
            "f_ELF": "ELF",
            "f_MACHO": "Mach-O",
            "f_BIN": "Binary",
            "f_COFF": "COFF",
            "f_AOUT": "a.out",
        }
        for key, label in names.items():
            try:
                if ft == getattr(ida_ida, key):
                    return label
            except Exception:
                continue
    except Exception:
        pass
    return ""


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


_ELF_MACHINES = {
    "EM_386": "x86",
    "EM_X86_64": "x86-64",
    "EM_ARM": "ARM",
    "EM_AARCH64": "AArch64",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC64",
    "EM_RISCV": "RISC-V",
    "EM_S390": "S390",
    "EM_SPARC": "SPARC",
    "EM_LOONGARCH": "LoongArch",
}

_ELF_TYPES = {
    "ET_NONE": "No file type",
    "ET_REL": "Relocatable",
    "ET_EXEC": "Executable",
    "ET_DYN": "Shared object",
    "ET_CORE": "Core",
}


def _compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Возвращает SHA256/MD5/CRC32 файла.

    Приоритет: нативные API IDA Pro (значения из БД, верхний регистр),
    затем самостоятельное вычисление по файлу на диске.
    """
    result = {"sha256": "", "md5": "", "crc32": ""}

    def _ida_hex(value) -> str:
        if value is None:
            return ""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex().upper()
        if isinstance(value, int):
            return f"{value & 0xFFFFFFFF:08X}"
        return str(value).upper()

    try:
        result["sha256"] = _ida_hex(ida_nalt.retrieve_input_file_sha256())
    except Exception:
        result["sha256"] = ""
    try:
        result["md5"] = _ida_hex(ida_nalt.retrieve_input_file_md5())
    except Exception:
        result["md5"] = ""
    try:
        result["crc32"] = _ida_hex(ida_nalt.retrieve_input_file_crc32())
    except Exception:
        result["crc32"] = ""

    # Если IDA не вернула какое-то значение — считаем напрямую из файла.
    try:
        if not all(result.values()) and file_path and os.path.exists(file_path):
            sha = hashlib.sha256()
            md5 = hashlib.md5()
            crc = 0
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    sha.update(chunk)
                    md5.update(chunk)
                    crc = zlib.crc32(chunk, crc)
            if not result["sha256"]:
                result["sha256"] = sha.hexdigest().upper()
            if not result["md5"]:
                result["md5"] = md5.hexdigest().upper()
            if not result["crc32"]:
                result["crc32"] = f"{crc & 0xFFFFFFFF:08X}"
    except Exception as e:
        print(f"[IDAPython] Ошибка вычисления хешей {file_path}: {e}")
    return result


def _get_compiler_name() -> Optional[str]:
    """Определяет компилятор через нативные API IDA (ida_typeinf.get_compiler_name)."""
    if ida_typeinf is None:
        return None
    try:
        comp_id = idc.get_inf_attr(idc.INF_CC_ID)
        if comp_id is None:
            return None
        comp_id = int(comp_id) & 0x0F  # COMP_MASK
        name = ida_typeinf.get_compiler_name(comp_id)
        if name and name.lower() not in ("unknown", "unknown compiler"):
            return name
    except Exception:
        pass
    return None


def _parse_comment_section(elffile) -> Optional[str]:
    """Извлекает строку компилятора из секции .comment (GCC/clang)."""
    try:
        comment = elffile.get_section_by_name(".comment")
        if comment is None:
            return None
        raw = comment.data()
    except Exception:
        return None
    text = raw.decode("utf-8", errors="replace")
    for token in text.split("\x00"):
        token = token.strip()
        if not token:
            continue
        if "clang version" in token:
            return "Clang " + token.split("clang version", 1)[1].strip().split()[0]
        if token.startswith("GCC:"):
            version = token.split("GCC:", 1)[1].strip()
            version = version.lstrip("(GNU) ").split()[0]
            return "GNU C/C++ " + version
    return None


def _infer_compiler(needed_libs: List[str]) -> Optional[str]:
    """Определяет компилятор по набору зависимостей, если .comment отсутствует."""
    libs = set(needed_libs)
    if any(l.startswith("libstdc++") for l in libs):
        return "GNU C++"
    if any(l.startswith("libgfortran") for l in libs):
        return "GNU Fortran"
    if any(l.startswith(("libgo", "libobjc")) for l in libs):
        return "GNU Go/Objective-C"
    if any(l.startswith(("libmono", "libcoreclr", "libmscoree")) for l in libs):
        return ".NET (managed)"
    if libs & {"libc.so.6", "libc.so", "libc.musl-x86_64.so.1"}:
        return "GNU C"
    return None


def _get_elf_metadata(elf_path: str) -> Dict[str, Any]:
    """Извлекает метаданные ELF: формат, DT_NEEDED, DT_SONAME, RPATH/RUNPATH, компилятор.

    Приоритет данных:
      1. Нативные API IDA Pro (хеши — отдельно, компилятор, формат).
      2. pyelftools — только для полей, которые IDA не отдаёт напрямую
         (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, .comment).
    """
    meta: Dict[str, Any] = {
        "format": "",
        "needed_libs": [],
        "soname": None,
        "rpath": None,
        "runpath": None,
        "compiler": None,
    }

    # Компилятор — сначала нативный API IDA.
    meta["compiler"] = _get_compiler_name()

    # Формат — нативный API IDA.
    meta["format"] = _get_file_type_name()

    if ELFFile is None:
        return meta

    try:
        with open(elf_path, "rb") as f:
            elffile = ELFFile(f)

            # Формат: если IDA не дал имя типа, собираем его из заголовка ELF.
            if not meta["format"]:
                elf_class = f"ELF{elffile.elfclass}"
                machine = _ELF_MACHINES.get(elffile["e_machine"], "")
                etype = _ELF_TYPES.get(elffile["e_type"], "")
                parts = [elf_class]
                if machine:
                    parts.append("for " + machine)
                if etype:
                    parts.append("(" + etype + ")")
                meta["format"] = " ".join(parts)

            # Компилятор: если IDA не дал, берём из .comment.
            if not meta["compiler"]:
                meta["compiler"] = _parse_comment_section(elffile)

            dynamic = None
            for segment in elffile.iter_segments():
                if segment["p_type"] == "PT_DYNAMIC":
                    dynamic = segment
                    break
            if dynamic is None:
                dynamic = elffile.get_section_by_name(".dynamic")
            if dynamic is not None:
                needed = []
                for tag in dynamic.iter_tags():
                    d_tag = tag.entry.d_tag
                    if d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif d_tag == "DT_SONAME" and meta["soname"] is None:
                        meta["soname"] = tag.soname
                    elif d_tag == "DT_RPATH" and meta["rpath"] is None:
                        meta["rpath"] = tag.rpath
                    elif d_tag == "DT_RUNPATH" and meta["runpath"] is None:
                        meta["runpath"] = tag.runpath
                meta["needed_libs"] = needed

            if meta["compiler"] is None:
                meta["compiler"] = _infer_compiler(meta["needed_libs"])
    except Exception as e:
        print(f"[IDAPython] Ошибка извлечения метаданных ELF: {e}")
    return meta


def _get_elf_needed_libraries(elf_path: str) -> List[str]:
    """Возвращает список DT_NEEDED из ELF-файла или пустой список, если pyelftools недоступен."""
    return _get_elf_metadata(elf_path).get("needed_libs", [])


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
        "soname": None,
        "rpath": None,
        "runpath": None,
        "compiler": None,
        "format": "",
        "hashes": {"sha256": "", "md5": "", "crc32": ""},
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
        meta = _get_elf_metadata(current_file_path)
        data["needed_libs"] = meta["needed_libs"]
        data["soname"] = meta["soname"]
        data["rpath"] = meta["rpath"]
        data["runpath"] = meta["runpath"]
        data["compiler"] = meta["compiler"]
        data["format"] = meta["format"]
        data["hashes"] = _compute_file_hashes(current_file_path)
    elif is_macho:
        # Для Mach-O: собираем имена модулей из таблицы импорта IDA и преобразуем их
        unique_modules = set()
        for imp in raw_imports:
            mod = imp.get("module", "")
            if mod and mod.lower() != "unknown":
                unique_modules.add(_extract_framework_name(mod))
        data["needed_libs"] = sorted(unique_modules)
        print(f"[IDAPython] Mach‑O зависимости (из IDA): {data['needed_libs']}")
        if current_file_path and os.path.exists(current_file_path):
            data["hashes"] = _compute_file_hashes(current_file_path)
    else:
        # PE и прочие форматы — хеши всё равно полезны для отчёта
        if current_file_path and os.path.exists(current_file_path):
            data["hashes"] = _compute_file_hashes(current_file_path)

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