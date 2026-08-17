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


# -------------------------------------------------------------------- #
#  Парсинг ELF без pyelftools (работает в любом Python, включая
#  встроенный Python IDA Pro, где нет сторонних пакетов).
# -------------------------------------------------------------------- #

_ELF_EI_MAGIC = b'\x7fELF'
_ELF_CLASS_32 = 1
_ELF_CLASS_64 = 2
_ELF_DATA_LE = 1
_ELF_DATA_BE = 2

_ELF_PT_NULL = 0
_ELF_PT_DYNAMIC = 2

_ELF_DT_NEEDED = 1
_ELF_DT_STRTAB = 5
_ELF_DT_STRSZ = 10
_ELF_DT_SONAME = 14
_ELF_DT_RPATH = 15
_ELF_DT_RUNPATH = 29

_ELF_SHT_DYNSYM = 11
_ELF_SHT_STRTAB = 3

_ELF_MACHINES = {
    0: "No machine",
    2: "SPARC",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    22: "S390",
    40: "ARM",
    43: "SPARC v9",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
    258: "LoongArch",
}

_ELF_TYPES = {
    0: "No file type",
    1: "Relocatable",
    2: "Executable",
    3: "Shared object",
    4: "Core",
}


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


def _read_elf_metadata(elf_path: str) -> Dict[str, Any]:
    """Извлекает метаданные ELF на чистом struct (без pyelftools).

    Возвращает словарь с полями:
        format, needed_libs, soname, rpath, runpath, compiler
    """
    meta: Dict[str, Any] = {
        "format": "",
        "needed_libs": [],
        "soname": None,
        "rpath": None,
        "runpath": None,
        "compiler": None,
    }

    try:
        with open(elf_path, "rb") as f:
            magic = f.read(4)
            if magic != _ELF_EI_MAGIC:
                return meta

            ei_class = _ELF_CLASS_64
            ei_data = _ELF_DATA_LE
            f.seek(0)
            raw = f.read(64)
            if len(raw) < 64:
                return meta
            ei_class = raw[4]
            ei_data = raw[5]

            endian = '<' if ei_data == _ELF_DATA_LE else '>'

            if ei_class == _ELF_CLASS_64:
                # 64-bit ELF header: e_ident[16] + e_type(2) + e_machine(2) + e_version(4) +
                # e_entry(8) + e_phoff(8) + e_shoff(8) + e_flags(4) + e_ehsize(2) +
                # e_phentsize(2) + e_phnum(2) + e_shentsize(2) + e_shnum(2) + e_shstrndx(2)
                if len(raw) < 64:
                    return meta
                hdr = struct.unpack(endian + '16sHHIQQQIHHHHHH', raw[:64])
                e_type, e_machine = hdr[1], hdr[2]
                e_phoff, e_shoff = hdr[5], hdr[6]
                e_phentsize, e_phnum = hdr[9], hdr[10]
                e_shentsize, e_shnum = hdr[11], hdr[12]
                elf_class_str = "ELF64"
                ph_fmt = endian + 'IIQQQQQQ'  # p_type(4), p_flags(4), p_offset(8), p_vaddr(8), p_paddr(8), p_filesz(8), p_memsz(8), p_align(8)
                ph_size = 56
                sh_fmt = endian + 'IIQQQQIIQQ'  # sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8), sh_size(8), sh_link(4), sh_info(4), sh_addralign(8), sh_entsize(8)
                sh_size = 64
                dyn_fmt = endian + 'QQ'  # d_tag(8), d_val(8)
                dyn_entry_size = 16
                shstrndx = hdr[13]
            else:
                # 32-bit ELF header
                hdr = struct.unpack(endian + '16sHHIIIIIHHHHHH', raw[:52])
                e_type, e_machine = hdr[1], hdr[2]
                e_phoff, e_shoff = hdr[5], hdr[6]
                e_phentsize, e_phnum = hdr[8], hdr[9]
                e_shentsize, e_shnum = hdr[10], hdr[11]
                elf_class_str = "ELF32"
                ph_fmt = endian + 'IIIIIIII'  # p_type(4), p_offset(4), p_vaddr(4), p_paddr(4), p_filesz(4), p_memsz(4), p_flags(4), p_align(4)
                ph_size = 32
                sh_fmt = endian + 'IIIIIIIIII'  # sh_name(4), sh_type(4), sh_flags(4), sh_addr(4), sh_offset(4), sh_size(4), sh_link(4), sh_info(4), sh_addralign(4), sh_entsize(4)
                sh_size = 40
                dyn_fmt = endian + 'ii'  # d_tag(4), d_val(4)
                dyn_entry_size = 8
                shstrndx = hdr[12]

            # --- Формат ---
            machine_name = _ELF_MACHINES.get(e_machine, f"machine#{e_machine}")
            etype_name = _ELF_TYPES.get(e_type, "")
            parts = [elf_class_str]
            if machine_name:
                parts.append("for " + machine_name)
            if etype_name:
                parts.append("(" + etype_name + ")")
            meta["format"] = " ".join(parts)

            # --- Поиск PT_DYNAMIC в програмных заголовках ---
            dynamic_offset = 0
            dynamic_size = 0
            for i in range(e_phnum):
                f.seek(e_phoff + i * ph_size)
                ph_data = f.read(ph_size)
                if len(ph_data) < ph_size:
                    break
                if ei_class == _ELF_CLASS_64:
                    p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack(ph_fmt, ph_data)
                else:
                    p_type, p_offset, _, _, p_filesz, _, _, _ = struct.unpack(ph_fmt, ph_data)
                if p_type == _ELF_PT_DYNAMIC:
                    dynamic_offset = p_offset
                    dynamic_size = p_filesz
                    break

            if dynamic_offset > 0 and dynamic_size > 0:
                dyn_entries = dynamic_size // dyn_entry_size
                strtab_addr = None
                strtab_size = None
                needed_offsets = []
                soname_offset = None
                rpath_offset = None
                runpath_offset = None

                for d in range(dyn_entries):
                    f.seek(dynamic_offset + d * dyn_entry_size)
                    d_data = f.read(dyn_entry_size)
                    if len(d_data) < dyn_entry_size:
                        break
                    if ei_class == _ELF_CLASS_64:
                        tag, val = struct.unpack(dyn_fmt, d_data)
                    else:
                        tag, val = struct.unpack(dyn_fmt, d_data)

                    if tag == _ELF_DT_NEEDED:
                        needed_offsets.append(val)
                    elif tag == _ELF_DT_SONAME:
                        soname_offset = val
                    elif tag == _ELF_DT_RPATH:
                        rpath_offset = val
                    elif tag == _ELF_DT_RUNPATH:
                        runpath_offset = val
                    elif tag == _ELF_DT_STRTAB:
                        strtab_addr = val
                    elif tag == _ELF_DT_STRSZ:
                        strtab_size = val

                if strtab_addr is not None:
                    # Ищем строковую таблицу по адресу strtab_addr.
                    # Сначала — через секции (.dynstr, по sh_addr).
                    # Если секций нет (e_shnum == 0, stripped ELF), используем
                    # PT_LOAD-сегменты для конвертации vaddr → file offset.
                    strtab_offset = 0
                    strtab_len = 0
                    for s in range(e_shnum):
                        f.seek(e_shoff + s * sh_size)
                        sh_data = f.read(sh_size)
                        if len(sh_data) < sh_size:
                            break
                        if ei_class == _ELF_CLASS_64:
                            _, sh_type, _, sh_addr, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)
                        else:
                            _, sh_type, _, sh_addr, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)
                        if sh_addr == strtab_addr:
                            strtab_offset = sh_offset
                            strtab_len = sh_size_sh
                            break

                    if strtab_offset == 0 and e_shnum == 0:
                        # Fallback: vaddr → file offset через PT_LOAD
                        strtab_offset = 0
                        strtab_len = strtab_size or 0
                        f.seek(e_phoff)
                        for i in range(e_phnum):
                            ph_data = f.read(ph_size)
                            if len(ph_data) < ph_size:
                                break
                            if ei_class == _ELF_CLASS_64:
                                p_type, _, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack(ph_fmt, ph_data)
                            else:
                                p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, _, _ = struct.unpack(ph_fmt, ph_data)
                            if p_type == 1:  # PT_LOAD
                                if p_vaddr <= strtab_addr < p_vaddr + p_memsz:
                                    strtab_offset = p_offset + (strtab_addr - p_vaddr)
                                    break

                    if strtab_offset > 0 and strtab_len > 0:
                        f.seek(strtab_offset)
                        strtab = f.read(strtab_len)

                        for off in needed_offsets:
                            if off < strtab_len:
                                lib_name = strtab[off:].split(b'\x00')[0].decode('utf-8', errors='replace')
                                if lib_name:
                                    meta["needed_libs"].append(lib_name)

                        if soname_offset is not None and soname_offset < strtab_len:
                            meta["soname"] = strtab[soname_offset:].split(b'\x00')[0].decode('utf-8', errors='replace')
                        if rpath_offset is not None and rpath_offset < strtab_len:
                            meta["rpath"] = strtab[rpath_offset:].split(b'\x00')[0].decode('utf-8', errors='replace')
                        if runpath_offset is not None and runpath_offset < strtab_len:
                            meta["runpath"] = strtab[runpath_offset:].split(b'\x00')[0].decode('utf-8', errors='replace')

            # --- Извлечение компилятора из секции .comment ---
            for s in range(e_shnum):
                f.seek(e_shoff + s * sh_size)
                sh_data = f.read(sh_size)
                if len(sh_data) < sh_size:
                    break
                if ei_class == _ELF_CLASS_64:
                    _, sh_type, _, sh_addr, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)
                else:
                    _, sh_type, _, sh_addr, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)

                if sh_type == _ELF_SHT_STRTAB:
                    # Проверяем имя секции через sh_name → shstrndx
                    pass  # Пропускаем — для .comment нужно имя секции, а не тип

            # Ищем .comment по имени через shstrndx
            if shstrndx < e_shnum:
                # Читаем shstrtab
                f.seek(e_shoff + shstrndx * sh_size)
                shstr_data = f.read(sh_size)
                if len(shstr_data) >= sh_size:
                    if ei_class == _ELF_CLASS_64:
                        _, _, _, _, shstr_offset, shstr_size, _, _, _, _ = struct.unpack(sh_fmt, shstr_data)
                    else:
                        _, _, _, _, shstr_offset, shstr_size, _, _, _, _ = struct.unpack(sh_fmt, shstr_data)
                    f.seek(shstr_offset)
                    shstrtab = f.read(shstr_size)

                    for s in range(e_shnum):
                        f.seek(e_shoff + s * sh_size)
                        sh_data = f.read(sh_size)
                        if len(sh_data) < sh_size:
                            break
                        if ei_class == _ELF_CLASS_64:
                            sh_name, _, _, _, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)
                        else:
                            sh_name, _, _, _, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)

                        # Имя секции из shstrtab
                        sec_name = shstrtab[sh_name:].split(b'\x00')[0].decode('utf-8', errors='replace') if sh_name < shstr_size else ""

                        if sec_name == ".comment":
                            f.seek(sh_offset)
                            comment_raw = f.read(sh_size_sh)
                            text = comment_raw.decode('utf-8', errors='replace')
                            for token in text.split("\x00"):
                                token = token.strip()
                                if not token:
                                    continue
                                if "clang version" in token:
                                    meta["compiler"] = "Clang " + token.split("clang version", 1)[1].strip().split()[0]
                                    break
                                if token.startswith("GCC:"):
                                    version = token.split("GCC:", 1)[1].strip()
                                    version = version.lstrip("(GNU) ").split()[0]
                                    meta["compiler"] = "GNU C/C++ " + version
                                    break

            if meta["compiler"] is None:
                meta["compiler"] = _infer_compiler(meta["needed_libs"])

    except Exception as e:
        print(f"[IDAPython] Ошибка парсинга ELF {elf_path}: {e}")

    return meta


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
        meta = _read_elf_metadata(current_file_path)
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