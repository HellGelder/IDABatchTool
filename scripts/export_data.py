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


# -------------------------------------------------------------------- #
#  Вспомогательные функции
# -------------------------------------------------------------------- #
def _get_file_format() -> str:
    """Определяет формат входного файла.

    Приоритет отдан нативному API IDA (``ida_ida.inf_get_filetype``): он не
    зависит от того, по какому адресу загрузчик разместил заголовок файла.
    Non-PIE ELF (``ET_EXEC``) IDA грузит по imagebase (например 0x400000),
    поэтому чтение байтов строго по адресу 0 даёт мусор и формат терялся.
    """
    if ida_ida is not None:
        try:
            filetype = ida_ida.inf_get_filetype()
            for attr, fmt in (("f_ELF", "elf"), ("f_PE", "pe"), ("f_MACHO", "macho")):
                expected = getattr(ida_ida, attr, None)
                if expected is not None and filetype == expected:
                    return fmt
        except Exception:
            pass

    # Fallback: сигнатура. Проверяем и адрес 0, и imagebase.
    candidates = [0]
    try:
        imagebase = ida_nalt.get_imagebase()
        if imagebase and imagebase not in candidates:
            candidates.append(imagebase)
    except Exception:
        pass

    for addr in candidates:
        try:
            raw = ida_bytes.get_bytes(addr, 4)
        except Exception:
            continue
        if not raw or len(raw) < 4:
            continue
        if raw[:4] == b'\x7fELF':
            return 'elf'
        if raw[:2] == b'MZ':
            return 'pe'
        magic = struct.unpack('<I', raw[:4])[0]
        if magic in (0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcefaedfe, 0xcffaedfe):
            return 'macho'
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

# Типы секций и сегментов — для человекочитаемого описания в отчёте.
_ELF_SECTION_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
    18: "SYMTAB_SHNDX", 0x6ffffff6: "GNU_HASH", 0x6ffffffe: "VERNEED",
    0x6fffffff: "VERSYM", 0x6ffffffd: "VERDEF",
}
_ELF_SEGMENT_TYPES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB",
    6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
    0x6474e552: "GNU_RELRO",
}
_ELF_SECTION_FLAGS = ((0x1, "W"), (0x2, "A"), (0x4, "X"), (0x10, "M"), (0x20, "S"), (0x400, "T"))
_ELF_SEGMENT_FLAGS = ((0x1, "X"), (0x2, "W"), (0x4, "R"))

_ELF_PT_LOAD = 1
_ELF_PT_INTERP = 3
_ELF_PT_NOTE = 4
_ELF_PT_PHDR = 6


def _elf_flag_names(value: int, table) -> List[str]:
    """Возвращает список имён флагов по битовой маске."""
    return [name for mask, name in table if value & mask]


def _parse_elf_notes(blob: bytes, endian: str) -> Dict[str, Any]:
    """Разбирает содержимое PT_NOTE.

    Извлекает то, что реально полезно в отчёте: Build ID (GNU, тип 3),
    ABI-тег (GNU, тип 1 — минимальная версия ядра) и уровень Android API
    (Android, тип 1).
    """
    result: Dict[str, Any] = {}
    offset = 0
    while offset + 12 <= len(blob):
        try:
            namesz, descsz, ntype = struct.unpack_from(endian + "III", blob, offset)
        except struct.error:
            break
        offset += 12
        name = blob[offset:offset + namesz].split(b"\x00")[0].decode("utf-8", "replace")
        offset += (namesz + 3) & ~3
        desc = blob[offset:offset + descsz]
        offset += (descsz + 3) & ~3
        if name == "GNU" and ntype == 3 and desc:
            result["build_id"] = desc.hex()
        elif name == "GNU" and ntype == 1 and len(desc) >= 16:
            major, minor, sub = struct.unpack_from(endian + "III", desc, 4)
            result["abi_tag"] = f"{major}.{minor}.{sub}"
        elif name == "Android" and ntype == 1 and len(desc) >= 4:
            result["android_api"] = struct.unpack_from(endian + "I", desc, 0)[0]
        elif ntype == 4 and not result.get("gold_version"):
            result["gold_version"] = desc.split(b"\x00")[0].decode("utf-8", "replace")
    return result


def _elf_meta_template() -> Dict[str, Any]:
    """Пустая заготовка метаданных ELF (единая для файлового и IDB-парсера)."""
    return {
        "format": "",
        "needed_libs": [],
        "soname": None,
        "rpath": None,
        "runpath": None,
        "compiler": None,
        "elf_header": {},
        "elf_sections": [],
        "elf_segments": [],
        "build_id": None,
        "abi_tag": None,
        "android_api": None,
        "interpreter": None,
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

    Собирает всё, что полезно для карточки «Информация о файле» и раздела
    секций в отчёте: заголовок, программные заголовки (сегменты), таблицу
    секций, notes (Build ID, ABI-тег, уровень Android API), interpreter,
    зависимости (.dynamic), SONAME/RPATH/RUNPATH и компилятор (.comment).
    """
    meta = _elf_meta_template()

    try:
        with open(elf_path, "rb") as f:
            raw = f.read(64)
            if len(raw) < 64 or raw[:4] != _ELF_EI_MAGIC:
                return meta

            ei_class = raw[4]
            ei_data = raw[5]
            endian = '<' if ei_data == _ELF_DATA_LE else '>'

            if ei_class == _ELF_CLASS_64:
                hdr = struct.unpack(endian + '16sHHIQQQIHHHHHH', raw[:64])
                e_type, e_machine, e_version, e_entry = hdr[1], hdr[2], hdr[3], hdr[4]
                e_phoff, e_shoff, e_flags = hdr[5], hdr[6], hdr[7]
                e_phentsize, e_phnum = hdr[9], hdr[10]
                e_shentsize, e_shnum = hdr[11], hdr[12]
                elf_class_str = "ELF64"
                ph_fmt, ph_size = endian + 'IIQQQQQQ', 56
                sh_fmt, sh_size = endian + 'IIQQQQIIQQ', 64
                dyn_fmt, dyn_entry_size = endian + 'QQ', 16
                shstrndx = hdr[13]
            elif ei_class == _ELF_CLASS_32:
                hdr = struct.unpack(endian + '16sHHIIIIIHHHHHH', raw[:52])
                e_type, e_machine, e_version, e_entry = hdr[1], hdr[2], hdr[3], hdr[4]
                e_phoff, e_shoff, e_flags = hdr[5], hdr[6], hdr[7]
                e_phentsize, e_phnum = hdr[9], hdr[10]
                e_shentsize, e_shnum = hdr[11], hdr[12]
                elf_class_str = "ELF32"
                ph_fmt, ph_size = endian + 'IIIIIIII', 32
                sh_fmt, sh_size = endian + 'IIIIIIIIII', 40
                dyn_fmt, dyn_entry_size = endian + 'ii', 8
                shstrndx = hdr[13]
            else:
                return meta

            # --- Формат ---
            machine_name = _ELF_MACHINES.get(e_machine, f"machine#{e_machine}")
            etype_name = _ELF_TYPES.get(e_type, "")
            parts = [elf_class_str]
            if machine_name:
                parts.append("for " + machine_name)
            if etype_name:
                parts.append("(" + etype_name + ")")
            meta["format"] = " ".join(parts)

            meta["elf_header"] = {
                "class": elf_class_str,
                "endianness": "LSB" if ei_data == _ELF_DATA_LE else "MSB",
                "type": etype_name or str(e_type),
                "machine": machine_name,
                "entry": f"0x{e_entry:X}" if e_entry else "—",
                "flags": f"0x{e_flags:X}",
                "program_headers": e_phnum,
                "sections": e_shnum,
            }

            # --- Программные заголовки: сегменты, notes, interpreter, PT_DYNAMIC ---
            dynamic_offset = 0
            dynamic_size = 0
            for i in range(e_phnum):
                f.seek(e_phoff + i * ph_size)
                ph_data = f.read(ph_size)
                if len(ph_data) < ph_size:
                    break
                if ei_class == _ELF_CLASS_64:
                    p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, p_align = struct.unpack(ph_fmt, ph_data)
                else:
                    p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, p_align = struct.unpack(ph_fmt, ph_data)

                meta["elf_segments"].append({
                    "type": _ELF_SEGMENT_TYPES.get(p_type, f"#{p_type}"),
                    "flags": "".join(_elf_flag_names(p_flags, _ELF_SEGMENT_FLAGS)),
                    "offset": f"0x{p_offset:X}",
                    "vaddr": f"0x{p_vaddr:X}",
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "align": p_align,
                })

                if p_type == _ELF_PT_DYNAMIC:
                    dynamic_offset = p_offset
                    dynamic_size = p_filesz
                elif p_type == _ELF_PT_INTERP:
                    f.seek(p_offset)
                    meta["interpreter"] = (
                        f.read(p_filesz).split(b'\x00')[0].decode('utf-8', 'replace')
                    )
                elif p_type == _ELF_PT_NOTE:
                    f.seek(p_offset)
                    meta.update(
                        {k: v for k, v in _parse_elf_notes(f.read(p_filesz), endian).items()}
                    )

            # --- Зависимости из .dynamic ---
            if dynamic_offset > 0 and dynamic_size > 0:
                strtab_addr = None
                strtab_size = None
                needed_offsets = []
                soname_offset = rpath_offset = runpath_offset = None

                for d in range(dynamic_size // dyn_entry_size):
                    f.seek(dynamic_offset + d * dyn_entry_size)
                    d_data = f.read(dyn_entry_size)
                    if len(d_data) < dyn_entry_size:
                        break
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
                    # .dynstr ищем по sh_addr среди секций; если таблицы секций
                    # нет (stripped ELF), переводим vaddr → файловое смещение
                    # через PT_LOAD-сегменты.
                    strtab_offset = 0
                    strtab_len = 0
                    for s in range(e_shnum):
                        f.seek(e_shoff + s * sh_size)
                        sh_data = f.read(sh_size)
                        if len(sh_data) < sh_size:
                            break
                        if ei_class == _ELF_CLASS_64:
                            _, _, _, sh_addr, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)
                        else:
                            _, _, _, sh_addr, sh_offset, sh_size_sh, _, _, _, _ = struct.unpack(sh_fmt, sh_data)
                        if sh_addr == strtab_addr:
                            strtab_offset = sh_offset
                            strtab_len = sh_size_sh
                            break

                    if strtab_offset == 0:
                        strtab_len = strtab_size or 0
                        for seg in meta["elf_segments"]:
                            if seg["type"] != "LOAD":
                                continue
                            p_vaddr = int(seg["vaddr"], 16)
                            p_offset = int(seg["offset"], 16)
                            if p_vaddr <= strtab_addr < p_vaddr + seg["memsz"]:
                                strtab_offset = p_offset + (strtab_addr - p_vaddr)
                                break

                    if strtab_offset > 0 and strtab_len > 0:
                        f.seek(strtab_offset)
                        strtab = f.read(strtab_len)

                        def _str_at(off):
                            if off is None or off >= strtab_len:
                                return None
                            return strtab[off:].split(b'\x00')[0].decode('utf-8', 'replace') or None

                        for off in needed_offsets:
                            lib_name = _str_at(off)
                            if lib_name and lib_name not in meta["needed_libs"]:
                                meta["needed_libs"].append(lib_name)
                        meta["soname"] = _str_at(soname_offset)
                        meta["rpath"] = _str_at(rpath_offset)
                        meta["runpath"] = _str_at(runpath_offset)

            # --- Таблица секций + компилятор из .comment ---
            if e_shoff and e_shnum:
                shstrtab = b""
                if shstrndx < e_shnum:
                    f.seek(e_shoff + shstrndx * sh_size)
                    shstr_data = f.read(sh_size)
                    if len(shstr_data) >= sh_size:
                        fields = struct.unpack(sh_fmt, shstr_data)
                        shstr_off, shstr_len = fields[4], fields[5]
                        f.seek(shstr_off)
                        shstrtab = f.read(shstr_len)

                for s in range(e_shnum):
                    f.seek(e_shoff + s * sh_size)
                    sh_data = f.read(sh_size)
                    if len(sh_data) < sh_size:
                        break
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                     sh_size_sh, _sh_link, _sh_info, _sh_align, sh_entsize) = struct.unpack(sh_fmt, sh_data)

                    sec_name = ""
                    if shstrtab and sh_name < len(shstrtab):
                        sec_name = shstrtab[sh_name:].split(b'\x00')[0].decode('utf-8', 'replace')

                    meta["elf_sections"].append({
                        "name": sec_name or f"<{sh_name}>",
                        "type": _ELF_SECTION_TYPES.get(sh_type, f"#{sh_type}"),
                        "flags": "".join(_elf_flag_names(sh_flags, _ELF_SECTION_FLAGS)),
                        "addr": f"0x{sh_addr:X}",
                        "offset": f"0x{sh_offset:X}",
                        "size": sh_size_sh,
                        "entsize": sh_entsize,
                    })

                    if sec_name == ".comment" and sh_size_sh:
                        f.seek(sh_offset)
                        text = f.read(sh_size_sh).decode('utf-8', 'replace')
                        for token in text.split("\x00"):
                            token = token.strip()
                            if not token:
                                continue
                            if "clang version" in token:
                                meta["compiler"] = "Clang " + token.split("clang version", 1)[1].strip().split()[0]
                                break
                            if token.startswith("GCC:"):
                                version = token.split("GCC:", 1)[1].strip().lstrip("(GNU) ").split()[0]
                                meta["compiler"] = "GNU C/C++ " + version
                                break

            if meta["compiler"] is None:
                meta["compiler"] = _infer_compiler(meta["needed_libs"])

    except Exception as e:
        print(f"[IDAPython] Ошибка парсинга ELF {elf_path}: {e}")

    return meta


# -------------------------------------------------------------------- #
#  Чтение ELF-метаданных из загруженного образа IDA
# -------------------------------------------------------------------- #
def _idb_read(addr: int, size: int) -> bytes:
    """Читает байты из адресного пространства IDA.

    Сначала пробуем прочитать весь диапазон одним вызовом. Если он частично
    выходит за пределы загруженного сегмента (``get_bytes`` вернёт ``None``),
    переходим к поблочному чтению и останавливаемся на первом недоступном
    блоке. Так корректно обрабатываются строковые таблицы на границе сегментов.
    """
    if size <= 0:
        return b""
    limit = min(size, 64 << 20)  # защита от абсурдных DT_STRSZ

    try:
        data = ida_bytes.get_bytes(addr, limit)
        if data:
            return data
    except Exception:
        pass

    block = 4096
    chunks: List[bytes] = []
    offset = 0
    while offset < limit:
        chunk_size = min(block, limit - offset)
        try:
            chunk = ida_bytes.get_bytes(addr + offset, chunk_size)
        except Exception:
            chunk = None
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _read_elf_metadata_from_idb() -> Dict[str, Any]:
    """Извлекает метаданные ELF из образа, загруженного в IDA.

    Нужен, когда исходный файл недоступен (анализ ведётся по готовой ``.i64``)
    либо когда IDA разместила образ со смещением: non-PIE ELF (``ET_EXEC``)
    грузится по ``imagebase`` (например 0x400000), а не с нуля.

    Адресация IDA для ELF совпадает с виртуальными адресами (``p_vaddr``),
    поэтому ELF-заголовок и таблица программных заголовков читаются по адресу
    ``imagebase`` + файловое смещение, а ``DT_STRTAB``/notes/interpreter —
    прямо по их vaddr. Секции берутся из сегментов IDA: исходная таблица
    секций в образе не сохраняется.
    """
    meta = _elf_meta_template()

    # 1. Ищем ELF-заголовок: сначала по imagebase, затем по адресу 0.
    candidates: List[int] = []
    try:
        imagebase = ida_nalt.get_imagebase()
        if imagebase:
            candidates.append(imagebase)
    except Exception:
        pass
    candidates.append(0)

    header = None
    base = 0
    for addr in candidates:
        try:
            raw = ida_bytes.get_bytes(addr, 64)
        except Exception:
            raw = None
        if raw and len(raw) >= 64 and raw[:4] == _ELF_EI_MAGIC:
            header = raw
            base = addr
            break
    if header is None:
        return meta

    ei_class = header[4]
    ei_data = header[5]
    if ei_class not in (_ELF_CLASS_32, _ELF_CLASS_64):
        return meta
    endian = '<' if ei_data == _ELF_DATA_LE else '>'

    try:
        if ei_class == _ELF_CLASS_64:
            fields = struct.unpack(endian + '16sHHIQQQIHHHHHH', header[:64])
            e_type, e_machine, e_version, e_entry = fields[1], fields[2], fields[3], fields[4]
            e_phoff, e_flags = fields[5], fields[7]
            e_phentsize, e_phnum = fields[9], fields[10]
            e_shnum = fields[12]
            elf_class_str = "ELF64"
            ph_fmt, ph_size = endian + 'IIQQQQQQ', 56
            dyn_fmt, dyn_entry_size = endian + 'QQ', 16
        else:
            fields = struct.unpack(endian + '16sHHIIIIIHHHHHH', header[:52])
            e_type, e_machine, e_version, e_entry = fields[1], fields[2], fields[3], fields[4]
            e_phoff, e_flags = fields[5], fields[7]
            e_phentsize, e_phnum = fields[9], fields[10]
            e_shnum = fields[12]
            elf_class_str = "ELF32"
            ph_fmt, ph_size = endian + 'IIIIIIII', 32
            dyn_fmt, dyn_entry_size = endian + 'ii', 8
    except struct.error:
        return meta

    machine_name = _ELF_MACHINES.get(e_machine, f"machine#{e_machine}")
    etype_name = _ELF_TYPES.get(e_type, "")
    parts = [elf_class_str]
    if machine_name:
        parts.append("for " + machine_name)
    if etype_name:
        parts.append("(" + etype_name + ")")
    meta["format"] = " ".join(parts)

    meta["elf_header"] = {
        "class": elf_class_str,
        "endianness": "LSB" if ei_data == _ELF_DATA_LE else "MSB",
        "type": etype_name or str(e_type),
        "machine": machine_name,
        "entry": f"0x{e_entry:X}" if e_entry else "—",
        "flags": f"0x{e_flags:X}",
        "program_headers": e_phnum,
        "sections": e_shnum,
    }

    # 2. Программные заголовки: сегменты, notes, interpreter, PT_DYNAMIC.
    dynamic_addr = 0
    dynamic_size = 0
    for i in range(e_phnum):
        raw = ida_bytes.get_bytes(base + e_phoff + i * ph_size, ph_size)
        if not raw or len(raw) < ph_size:
            continue
        if ei_class == _ELF_CLASS_64:
            p_type, p_flags, _, p_vaddr, _, p_filesz, p_memsz, p_align = struct.unpack(ph_fmt, raw)
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, p_align = struct.unpack(ph_fmt, raw)

        meta["elf_segments"].append({
            "type": _ELF_SEGMENT_TYPES.get(p_type, f"#{p_type}"),
            "flags": "".join(_elf_flag_names(p_flags, _ELF_SEGMENT_FLAGS)),
            "offset": f"0x{0:X}",
            "vaddr": f"0x{p_vaddr:X}",
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
        })

        if p_type == _ELF_PT_DYNAMIC:
            dynamic_addr = p_vaddr
            dynamic_size = p_filesz
        elif p_type == _ELF_PT_INTERP:
            blob = _idb_read(p_vaddr, p_filesz)
            if blob:
                meta["interpreter"] = blob.split(b'\x00')[0].decode('utf-8', 'replace')
        elif p_type == _ELF_PT_NOTE:
            blob = _idb_read(p_vaddr, p_filesz)
            if blob:
                meta.update(_parse_elf_notes(blob, endian))

    # 3. Секции из сегментов IDA (исходная таблица секций не сохраняется).
    meta["elf_sections"] = _ida_segments_as_sections()

    if dynamic_addr <= 0 or dynamic_size <= 0:
        meta["compiler"] = _infer_compiler(meta["needed_libs"])
        return meta

    # 4. Разбираем записи .dynamic.
    strtab_addr = None
    strtab_size = 0
    needed_offsets: List[int] = []
    soname_offset = rpath_offset = runpath_offset = None
    for d in range(dynamic_size // dyn_entry_size):
        raw = ida_bytes.get_bytes(dynamic_addr + d * dyn_entry_size, dyn_entry_size)
        if not raw or len(raw) < dyn_entry_size:
            break
        tag, val = struct.unpack(dyn_fmt, raw)
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

    if strtab_addr is not None and strtab_size > 0:
        dynstr = _idb_read(strtab_addr, strtab_size)
        if dynstr:
            def _string_at(offset: int) -> Optional[str]:
                if offset is None or offset < 0 or offset >= len(dynstr):
                    return None
                value = dynstr[offset:].split(b"\x00")[0].decode("utf-8", "replace")
                return value or None

            for offset in needed_offsets:
                lib_name = _string_at(offset)
                if lib_name and lib_name not in meta["needed_libs"]:
                    meta["needed_libs"].append(lib_name)
            meta["soname"] = _string_at(soname_offset)
            meta["rpath"] = _string_at(rpath_offset)
            meta["runpath"] = _string_at(runpath_offset)

    # .comment не раскрывается в адресном пространстве IDA (неаллоцируемая
    # секция), поэтому компилятор выводим по набору зависимостей.
    meta["compiler"] = _infer_compiler(meta["needed_libs"])

    return meta


def _ida_segments_as_sections() -> List[Dict[str, Any]]:
    """Представляет сегменты IDA как список секций для карточки отчёта.

    Когда исходного файла нет, точная таблица секций ELF недоступна — но у
    IDA есть разметка адресного пространства (сегменты с классами и правами),
    которая даёт сопоставимую картину.
    """
    sections: List[Dict[str, Any]] = []
    try:
        import ida_segment  # noqa: WPS433 (локальный импорт — модуль есть только в IDA)

        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if not seg:
                continue
            perm = getattr(seg, "perm", 0)
            flags = "".join(name for bit, name in ((4, "R"), (2, "W"), (1, "X")) if perm & bit)
            sections.append({
                "name": ida_segment.get_segm_name(seg),
                "type": ida_segment.get_segm_class(seg) or "—",
                "flags": flags,
                "addr": f"0x{seg.start_ea:X}",
                "offset": "—",
                "size": seg.end_ea - seg.start_ea,
                "entsize": 0,
            })
    except Exception:
        pass
    return sections


def _merge_elf_metadata(primary: Optional[Dict[str, Any]],
                        fallback: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Объединяет метаданные ELF из образа IDA и из файла на диске.

    Значения из ``primary`` имеют приоритет; ``fallback`` заполняет только
    пустые поля (например, компилятор из ``.comment``, который в адресном
    пространстве IDA недоступен, так как секция неаллоцируемая).
    """
    empty = _elf_meta_template()
    if not primary:
        merged = dict(fallback or empty)
        merged.setdefault("compiler", None)
        return merged

    merged = dict(primary)
    if fallback:
        for key in ("format", "soname", "rpath", "runpath", "compiler",
                    "build_id", "abi_tag", "android_api", "interpreter"):
            if not merged.get(key) and fallback.get(key):
                merged[key] = fallback[key]
        if not merged.get("needed_libs") and fallback.get("needed_libs"):
            merged["needed_libs"] = fallback["needed_libs"]
        # Заголовок и сегменты: у файла они точнее, дополняем пустые поля.
        if not merged.get("elf_header") and fallback.get("elf_header"):
            merged["elf_header"] = fallback["elf_header"]
        if not merged.get("elf_segments") and fallback.get("elf_segments"):
            merged["elf_segments"] = fallback["elf_segments"]
        # Секции: файл даёт настоящую таблицу секций; из IDA — только
        # приблизительная разметка по сегментам, поэтому она лишь запасной вариант.
        if not merged.get("elf_sections") and fallback.get("elf_sections"):
            merged["elf_sections"] = fallback["elf_sections"]
    return merged


def _source_file_matches_db(file_path: str) -> bool:
    """Проверяет, что файл на диске — тот же, по которому построена база.

    Сравниваем CRC32 файла со значением, сохранённым в базе. Если база не
    хранит контрольную сумму, считаем файл доверенным (обратная совместимость).
    """
    try:
        db_crc = ida_nalt.retrieve_input_file_crc32()
    except Exception:
        return True
    if db_crc is None:
        return True
    try:
        crc = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                crc = zlib.crc32(chunk, crc)
        return (int(db_crc) & 0xFFFFFFFF) == (crc & 0xFFFFFFFF)
    except Exception:
        return False


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
        "elf_segments": [],
        "elf_header": {},
        "needed_libs": [],
        "soname": None,
        "rpath": None,
        "runpath": None,
        "compiler": None,
        "format": "",
        "build_id": None,
        "abi_tag": None,
        "android_api": None,
        "interpreter": None,
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

    # --- Зависимости и метаданные (ELF) ---
    if is_elf:
        # Источник №1 — образ, загруженный в IDA: он всегда соответствует
        # проанализированной базе и работает и для PIE, и для non-PIE ELF.
        idb_meta = _read_elf_metadata_from_idb()

        # Источник №2 — файл на диске. Дополняет тем, чего нет в адресном
        # пространстве IDA (компилятор из неаллоцируемой секции .comment,
        # точная таблица секций, смещения сегментов).
        # Используется только если файл совпадает с базой по CRC32 — иначе
        # есть риск подхватить устаревшую копию рядом с .i64.
        file_meta = None
        if current_file_path and os.path.exists(current_file_path):
            if _source_file_matches_db(current_file_path):
                file_meta = _read_elf_metadata(current_file_path)
            else:
                print(f"[IDAPython] Файл {current_file_path} не совпадает с базой "
                      "(CRC32) — метаданные берутся только из IDA")

        # Приоритет — файл: он даёт полную и точную картину (таблица секций,
        # notes, .comment). Образ IDA закрывает пробелы, когда файла нет.
        meta = _merge_elf_metadata(file_meta, idb_meta)
        data["needed_libs"] = meta["needed_libs"]
        data["soname"] = meta["soname"]
        data["rpath"] = meta["rpath"]
        data["runpath"] = meta["runpath"]
        data["compiler"] = meta["compiler"]
        data["format"] = meta["format"]
        data["elf_header"] = meta["elf_header"]
        data["elf_sections"] = meta["elf_sections"]
        data["elf_segments"] = meta["elf_segments"]
        data["build_id"] = meta["build_id"]
        data["abi_tag"] = meta["abi_tag"]
        data["android_api"] = meta["android_api"]
        data["interpreter"] = meta["interpreter"]
        sources = []
        if file_meta and file_meta.get("needed_libs"):
            sources.append("file")
        if idb_meta and idb_meta.get("needed_libs"):
            sources.append("idb")
        print(f"[IDAPython] ELF зависимости ({'+'.join(sources) or 'нет'}): "
              f"{data['needed_libs']}")
        print(f"[IDAPython] ELF: секций {len(data['elf_sections'])}, "
              f"сегментов {len(data['elf_segments'])}, "
              f"build_id={data['build_id']}, API={data['android_api']}")
        if current_file_path and os.path.exists(current_file_path):
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