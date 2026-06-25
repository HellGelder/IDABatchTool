"""
IDAPython-скрипт для экспорта графа потока управления (CFG) функции как SVG.

Запускается через idat.exe -A -Sexport_cfg.py <файл.i64>

Параметры:
    target_func=<addr> — адрес функции в десятичном или hex (0x...) формате
    output=<path>     — путь к выходному SVG-файлу

Если target_func не указан, экспортируются CFG всех функций в output_dir.
"""
import json
import os
import sys
from pathlib import Path

import idaapi
import idautils
import idc
import ida_graph
import ida_funcs


def _get_argv_param(prefix: str):
    for arg in idc.ARGV:
        if arg.startswith(prefix + "="):
            return arg.split("=", 1)[1].strip()
    return None


def export_cfg_svg(ea: int, output_path: str) -> bool:
    """Экспортирует CFG функции как SVG."""
    try:
        svg_data = ida_graph.export_to_svg(ea)
        if not svg_data:
            return False
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(svg_data)
        return True
    except Exception:
        return False


def export_all_cfgs(output_dir: str) -> dict:
    """Экспортирует CFG всех функций."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        safe_name = name.replace("/", "_").replace("\\", "_").replace(":", "_")
        svg_path = out / f"{safe_name}_{ea:x}.svg"
        if export_cfg_svg(ea, str(svg_path)):
            results[name] = str(svg_path.relative_to(out))
        else:
            results[name] = None
    return results


def main():
    idaapi.auto_wait()

    target_func = _get_argv_param("target_func")
    output = _get_argv_param("output")

    if target_func:
        # Одиночная функция
        try:
            ea = int(target_func, 16) if target_func.startswith("0x") else int(target_func)
        except ValueError:
            print(f"[CFG Export] Некорректный адрес: {target_func}")
            idc.qexit(1)
            return
        if not output:
            output = f"cfg_{ea:x}.svg"
        ok = export_cfg_svg(ea, output)
        print(f"[CFG Export] {'OK' if ok else 'FAIL'}: {target_func} -> {output}")
    else:
        # Все функции
        output_dir = output or "cfg_export"
        results = export_all_cfgs(output_dir)
        manifest_path = os.path.join(output_dir, "cfg_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[CFG Export] Экспортировано CFG: {len(results)} функций -> {output_dir}")

    idc.qexit(0)


if __name__ == "__main__":
    main()