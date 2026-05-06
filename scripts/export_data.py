"""
IDAPython-скрипт для экспорта данных из IDA Pro в JSON.
Запускается через idat.exe -A -Sexport_data.py <файл.i64>
Совместим с IDA Pro 9.3.

Псевдокод добавляется только при установленной переменной окружения IDA_PSEUDOCODE=1
или при передаче аргумента "pseudocode=1" в командной строке скрипта.
Пример: idat.exe -A -S"export_data.py pseudocode=1" target.i64
"""
import json
import os
from typing import List, Dict, Any, Optional

import idaapi
import idautils
import idc
import ida_nalt
import ida_bytes


# ------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------
def _is_elf_file() -> bool:
    """Проверяет, является ли файл ELF по первым байтам."""
    try:
        raw = ida_bytes.get_bytes(0, 4)
        return raw[:4] == b'\x7fELF'
    except Exception:
        return False


def _format_hexdump_with_ascii(data: bytes, start_addr: int = 0) -> str:
    """Возвращает строку hex-дампа с ASCII-представлением."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        addr = f'{start_addr + offset:08x}'
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{addr}  {hex_part:<48}  |{ascii_part}|')
    return '\n'.join(lines)


def _pseudocode_enabled() -> bool:
    """Возвращает True, если псевдокод должен быть сгенерирован."""
    # 1. Проверяем аргументы командной строки скрипта
    for arg in idc.ARGV:
        if arg.startswith("pseudocode="):
            return arg.split("=", 1)[1].strip().lower() in ("1", "true", "yes")
    # 2. Переменная окружения
    return os.environ.get('IDA_PSEUDOCODE', '0') == '1'


def _try_init_hexrays() -> bool:
    """
    Инициализирует декомпилятор Hex‑Rays.
    Возвращает True, если декомпилятор готов к работе.
    """
    try:
        import ida_hexrays
        # init_hexrays_plugin() сама загружает плагин и инициализирует его
        if ida_hexrays.init_hexrays_plugin():
            print("[IDAPython] Плагин Hex‑Rays успешно инициализирован.")
            return True
        else:
            print("[IDAPython] Не удалось инициализировать Hex‑Rays. "
                  "Проверьте наличие лицензии Hex‑Rays и правильность пути к idat.exe.")
            return False
    except ImportError:
        print("[IDAPython] Модуль ida_hexrays не найден. "
              "Убедитесь, что используете IDA Pro с Hex‑Rays (не IDA Free).")
        return False


def _decompile_function(ea: int, hexrays_available: bool) -> str:
    """
    Декомпилирует функцию по адресу ea.
    Возвращает строку с псевдокодом или сообщение об ошибке.
    """
    if not hexrays_available:
        return "Декомпилятор недоступен. Проверьте лицензию Hex‑Rays."

    try:
        import ida_hexrays
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)
        else:
            return "Декомпиляция не удалась (возможно, функция слишком большая или повреждена)."
    except ida_hexrays.DecompilationFailure as e:
        return f"Ошибка декомпиляции: {e}"
    except Exception as e:
        return f"Неизвестная ошибка декомпиляции: {e}"


# ------------------------------------------------------------
# Основная функция экспорта
# ------------------------------------------------------------
def export_to_json(output_path: Optional[str] = None) -> None:
    """
    Собирает данные из открытой базы IDA и записывает JSON.
    """
    idaapi.auto_wait()  # гарантируем завершение автоанализа

    if output_path is None:
        idb_path = idc.get_idb_path()
        output_path = idb_path + ".export.json"

    is_elf = _is_elf_file()

    # Информация о версии IDA
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

    # Нужен ли псевдокод?
    pseudocode_enabled = _pseudocode_enabled()
    if pseudocode_enabled:
        print("[IDAPython] Генерация псевдокода включена.")
        hexrays_available = _try_init_hexrays()
    else:
        print("[IDAPython] Генерация псевдокода отключена.")
        hexrays_available = False

    # ----------------------------------------------------------------
    # Функции
    # ----------------------------------------------------------------
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        if not func:
            continue
        size = func.size()

        # Дизассемблирование
        instructions = []
        for head in idautils.Heads(ea, ea + size):
            mnem = idc.print_insn_mnem(head)
            op_str = idc.print_operand(head, 0)
            if mnem:
                instructions.append(f"0x{head:X}  {mnem} {op_str}")
        disassembly_text = '\n'.join(instructions)

        # Hex-дамп
        try:
            raw = ida_bytes.get_bytes(ea, size)
            hexdump = _format_hexdump_with_ascii(raw, ea) if raw else ""
        except Exception:
            hexdump = "недоступно"

        # Псевдокод
        pseudocode = ""
        if pseudocode_enabled:
            pseudocode = _decompile_function(ea, hexrays_available)

        data["functions"].append({
            "name": name,
            "start_ea": f"0x{ea:X}",
            "size": size,
            "instructions_text": disassembly_text,
            "hexdump": hexdump,
            "pseudocode": pseudocode
        })

    # ----------------------------------------------------------------
    # Импорты и ELF-зависимости
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
                raw_imports.append({
                    "name": name,
                    "module": module_name,
                    "address": f"0x{ea:X}"
                })
            return True

        try:
            ida_nalt.enum_import_names(mod_index, callback)
        except AttributeError:
            pass

    if is_elf:
        needed = set()
        sections = set()
        for imp in raw_imports:
            mod = imp["module"]
            if mod.startswith('.'):
                sections.add(mod)
                imp["module"] = "ELF Section"
            else:
                needed.add(mod)
        data["needed_libs"] = sorted(list(needed))
        data["elf_sections"] = sorted(list(sections))
    else:
        data["needed_libs"] = []
        data["elf_sections"] = []

    data["imports"] = raw_imports

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
                exports.append({
                    "name": name,
                    "address": f"0x{addr:X}",
                    "ordinal": entry
                })

    if not exports:
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if name and not name.startswith(("sub_", "j_", "def_", "nullsub_")):
                exports.append({
                    "name": name,
                    "address": f"0x{ea:X}",
                    "ordinal": len(exports)
                })

    data["exports"] = exports
    data["functions"].sort(key=lambda f: int(f["start_ea"], 16))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[IDAPython] Данные экспортированы в {output_path}")
    idc.qexit(0)


if __name__ == "__main__":
    export_to_json()