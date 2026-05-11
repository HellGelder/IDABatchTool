"""
IDAPython-скрипт для экспорта текущей базы в BinExport и перемещения результата.
Основан на поведении BinExport 12 для IDA 9.x: плагин создаёт файл в
%TEMP%/BinDiff/primary/<original_name>.BinExport.
Параметры:
    outputdir=<путь>   – каталог назначения
    tag=<строка>       – метка (primary/secondary)
Результат: {outputdir}/{stem}_{tag}.BinExport
"""
import os
import shutil
import time
import idaapi
import idc

BINEXPORT_ACTION = "BinExportBinary"
PLUGIN_NAMES = [
    "binexport12_ida64",
    "binexport12_ida",
    "zynamics_binexport_9",
    "zynamics_binexport_8",
    "zynamics_binexport_7",
]

WAIT_INTERVAL = 0.5
MAX_WAIT = 120

# Определяем временную директорию явно, как в GUI
TEMP_ROOT = os.environ.get("TEMP", os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"))
BINEXPORT_TEMP_DIR = os.path.join(TEMP_ROOT, "BinDiff", "primary")


def _get_arg(name: str) -> str:
    for arg in idc.ARGV:
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1].strip()
    return ""


def export_binexport() -> None:
    idaapi.auto_wait()

    output_dir = _get_arg("outputdir")
    tag = _get_arg("tag") or "unknown"
    if not output_dir:
        print("[IDAPython] Ошибка: не указан outputdir")
        idc.qexit(1)

    idb_path = idc.get_idb_path()
    if not idb_path:
        print("[IDAPython] Не удалось получить путь к базе")
        idc.qexit(1)

    input_file = idc.get_input_file_path()
    if not input_file:
        print("[IDAPython] Не удалось получить путь к исходному файлу")
        idc.qexit(1)

    export_filename = os.path.basename(input_file) + ".BinExport"
    temp_file_path = os.path.join(BINEXPORT_TEMP_DIR, export_filename)

    # 1. Создаём временную папку BinDiff\primary, если её нет
    os.makedirs(BINEXPORT_TEMP_DIR, exist_ok=True)

    # 2. Удаляем возможный старый файл, чтобы не пропустить новый
    try:
        os.remove(temp_file_path)
    except FileNotFoundError:
        pass

    # 3. Запускаем плагин BinExport
    exported = False
    for name in PLUGIN_NAMES:
        if idaapi.load_plugin(name):
            print(f"[IDAPython] Запуск run_plugin({name}, 2)")
            idaapi.run_plugin(name, 2)
            exported = True
            break

    if not exported:
        print("[IDAPython] Плагин BinExport не найден")
        idc.qexit(1)

    # 4. Ожидаем появления файла
    waited = 0.0
    while waited < MAX_WAIT:
        if os.path.isfile(temp_file_path):
            print(f"[IDAPython] Файл создан: {temp_file_path}")
            break
        time.sleep(WAIT_INTERVAL)
        waited += WAIT_INTERVAL
    else:
        # Запасной путь: возможно, файл создался в папке с IDB
        fallback = os.path.join(os.path.dirname(idb_path), export_filename)
        if os.path.isfile(fallback):
            temp_file_path = fallback
            print(f"[IDAPython] Файл найден в папке базы: {fallback}")
        else:
            print(f"[IDAPython] Файл {export_filename} не найден через {MAX_WAIT}с")
            if os.path.isdir(BINEXPORT_TEMP_DIR):
                print(f"[IDAPython] Содержимое {BINEXPORT_TEMP_DIR}: {os.listdir(BINEXPORT_TEMP_DIR)}")
            else:
                print("[IDAPython] Временная папка всё ещё не существует!")
            idc.qexit(1)

    # 5. Перемещаем с переименованием
    stem = os.path.splitext(os.path.basename(idb_path))[0]
    dest = os.path.join(output_dir, f"{stem}_{tag}.BinExport")
    os.makedirs(output_dir, exist_ok=True)
    try:
        shutil.move(temp_file_path, dest)
        print(f"[IDAPython] Файл перемещён: {temp_file_path} → {dest}")
    except Exception as e:
        print(f"[IDAPython] Ошибка перемещения: {e}")
        idc.qexit(1)

    idc.qexit(0)


if __name__ == "__main__":
    export_binexport()