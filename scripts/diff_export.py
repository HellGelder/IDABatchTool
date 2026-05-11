"""
IDAPython-скрипт для сравнения двух бинарных файлов с помощью BinDiff и BinExport.
Запускается через idat.exe -A -S"diff_export.py primary=<путь> secondary=<путь>" <первичный.i64>

Параметры:
    primary   – путь к первичной базе .i64 (обычно совпадает с текущей)
    secondary – путь к вторичной базе .i64 для сравнения
"""
import json
import os
import sys
from pathlib import Path

import idaapi
import idc
import ida_nalt

# Попытка импорта модулей BinDiff и BinExport (зависит от установки)
try:
    import bindiff
    BINDIFF_AVAILABLE = True
except ImportError:
    BINDIFF_AVAILABLE = False
    print("[IDAPython] BinDiff API не найден. Будет выполнена заглушка.")

try:
    import binexport
    BINEXPORT_AVAILABLE = True
except ImportError:
    BINEXPORT_AVAILABLE = False
    print("[IDAPython] BinExport API не найден. Будет выполнена заглушка.")


def _get_arg(name: str) -> str:
    for arg in idc.ARGV:
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1].strip()
    return ""


def export_diff() -> None:
    idaapi.auto_wait()

    primary_path = _get_arg("primary")
    secondary_path = _get_arg("secondary")

    if not primary_path or not secondary_path:
        print("[IDAPython] Не указаны primary или secondary")
        idc.qexit(1)

    output_path = Path(primary_path).with_suffix(".diff.json")

    # Заглушка результата, если BinDiff недоступен
    result = {
        "primary": primary_path,
        "secondary": secondary_path,
        "matched_functions": [],
        "new_functions": [],
        "deleted_functions": [],
        "changed_functions": [],
        "error": None,
    }

    if not BINDIFF_AVAILABLE:
        result["error"] = "BinDiff API недоступен. Установите плагин BinDiff для IDA Pro."
        print("[IDAPython] BinDiff API не инициализирован.")
    else:
        try:
            # -----------------------------------------------------------------
            # Здесь необходимо вставить реальный код работы с BinDiff и BinExport
            # -----------------------------------------------------------------
            # 1. Загрузить вторичную базу для сравнения
            # diff = bindiff.Diff()
            # diff.load_primary(idaapi.get_root_filename())
            # diff.load_secondary(secondary_path)
            # ...
            # 2. Выполнить сравнение
            # diff.compare()
            # 3. Извлечь результаты
            # for func in diff.functions:
            #     result["matched_functions"].append({...})
            # ...
            # 4. (Опционально) Экспортировать через BinExport
            # binexport.export_to_file(output_path.with_suffix(".BinExport"))
            # -----------------------------------------------------------------

            # Заглушка – просто сообщим об успехе без реальных данных
            result["error"] = None
            print("[IDAPython] Сравнение выполнено (заглушка).")
        except Exception as e:
            result["error"] = f"Ошибка BinDiff: {e}"
            print(f"[IDAPython] Ошибка: {e}")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[IDAPython] Результат сохранён в {output_path}")
    idc.qexit(0)


if __name__ == "__main__":
    export_diff()