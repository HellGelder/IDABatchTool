"""Генератор HTML-отчётов с детерминированной группировкой модулей и описаниями."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Set
from jinja2 import Environment, FileSystemLoader, select_autoescape
from urllib.parse import quote

from ida_batch_tool.classifier import classify_module, get_module_category_and_description
from ida_batch_tool.reporting.utils import compute_back_link

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

_INTERNAL_EXTS = {'.dll', '.so', '.dylib', '.exe', '.sys', '.bin', '.elf', '.o', '.ko', '.dex'}


def _is_internal_module(module_name: str, input_dir: Optional[Path]) -> bool:
    if input_dir is None:
        return False
    name_lower = module_name.lower()
    for f in input_dir.rglob('*'):
        if f.is_file() and f.name.lower() == name_lower:
            return True
    stem = Path(module_name).stem.lower()
    for ext in _INTERNAL_EXTS:
        for f in input_dir.rglob(f'*{ext}'):
            if f.stem.lower() == stem:
                return True
    return False


class ReportGenerator:
    """Создаёт HTML-отчёты из JSON-файлов экспорта."""

    CATEGORY_COLORS = {
        "System": "#4CAF50",
        "Crypto": "#FF9800",
        "Network": "#2196F3",
        "Graphics": "#9C27B0",
        "Runtime": "#00BCD4",
        "Data": "#795548",
        "Internal": "#607D8B",
        "Unknown": "#F44336",
    }

    CATEGORY_LABELS = {
        "Системные библиотеки ОС": "System",
        "Криптография и безопасность": "Crypto",
        "Сеть и коммуникации": "Network",
        "Графика и мультимедиа": "Graphics",
        "Среды выполнения, научные и ML-библиотеки": "Runtime",
        "Работа с данными, архивация и XML": "Data",
        "Внутренние модули проекта": "Internal",
        "Неопознанные модули": "Unknown",
    }

    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.report_template = self.env.get_template("report.html")
        self.index_template = self.env.get_template("index.html")

    def _classify_with_context(self, module_name: str, input_dir: Optional[Path]) -> str:
        if _is_internal_module(module_name, input_dir):
            return "Собственный модуль проекта (внутренняя библиотека)"
        return classify_module(module_name)

    def _category_label_for_module(self, module_name: str, input_dir: Optional[Path]) -> str:
        desc = self._classify_with_context(module_name, input_dir)
        if "Собственный модуль" in desc:
            return "Internal"
        cat_ru, _ = get_module_category_and_description(module_name)
        return self.CATEGORY_LABELS.get(cat_ru, "Unknown")

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None,
                           reports_dir: Optional[Path] = None,
                           input_dir: Optional[Path] = None) -> Path:
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)

        is_elf: bool = data.get("is_elf", False)

        # --- Блок known/unknown (не используется в новом шаблоне, оставлен для совместимости) ---
        if is_elf:
            needed_libs = data.get("needed_libs", [])
            known = []
            unknown = []
            for lib in needed_libs:
                desc = self._classify_with_context(lib, input_dir)
                if "Собственный модуль" in desc:
                    known.append(lib)
                elif "Неопознанный" in desc:
                    unknown.append(lib)
                else:
                    known.append(lib)
            data["known_modules"] = sorted(known)
            data["unknown_modules"] = sorted(unknown)
            if "elf_sections" not in data:
                data["elf_sections"] = []
        else:
            known: List[str] = []
            unknown: List[str] = []
            elf: List[str] = []
            seen: Set[str] = set()
            for imp in data.get("imports", []):
                mod = imp.get("module")
                if not mod or mod.lower() == "unknown":
                    continue
                if mod in seen:
                    continue
                seen.add(mod)
                if mod.startswith("."):
                    elf.append(mod)
                    continue
                desc = self._classify_with_context(mod, input_dir)
                if "Собственный модуль" in desc:
                    known.append(mod)
                elif "Неопознанный" in desc:
                    unknown.append(mod)
                else:
                    known.append(mod)
            data["known_modules"] = sorted(known)
            data["unknown_modules"] = sorted(unknown)
            if "elf_sections" not in data:
                data["elf_sections"] = sorted(elf)

        # --- Построение module_deps ---
        module_deps: List[Dict[str, Any]] = []
        if is_elf:
            module_counts: Dict[str, int] = {}
            for imp in data.get("imports", []):
                resolved = imp.get("resolved_libs", [])
                if resolved:
                    for lib in resolved:
                        module_counts[lib] = module_counts.get(lib, 0) + 1
                else:
                    mod = imp.get("module", "")
                    if mod and not mod.startswith(".") and mod != "unknown":
                        module_counts[mod] = module_counts.get(mod, 0) + 1
            for mod, count in module_counts.items():
                desc = self._classify_with_context(mod, input_dir)
                cat_label = self._category_label_for_module(mod, input_dir)
                color = self.CATEGORY_COLORS.get(cat_label, "#9E9E9E")
                module_deps.append({
                    "name": mod,
                    "category": cat_label,
                    "count": count,
                    "description": desc,
                    "color": color,
                })
        else:
            module_counts: Dict[str, int] = {}
            for imp in data.get("imports", []):
                mod = imp.get("module")
                if not mod or mod.lower() == "unknown":
                    continue
                if mod.startswith("."):
                    continue
                module_counts[mod] = module_counts.get(mod, 0) + 1
            for mod, count in module_counts.items():
                desc = self._classify_with_context(mod, input_dir)
                cat_label = self._category_label_for_module(mod, input_dir)
                color = self.CATEGORY_COLORS.get(cat_label, "#9E9E9E")
                module_deps.append({
                    "name": mod,
                    "category": cat_label,
                    "count": count,
                    "description": desc,
                    "color": color,
                })

        data["module_deps"] = sorted(module_deps, key=lambda x: (x["category"], x["name"]))

        # --- Обработка module_display для импортов ---
        if is_elf:
            for imp in data.get("imports", []):
                resolved = imp.get("resolved_libs", [])
                if resolved:
                    parts = []
                    for lib in resolved:
                        if _is_internal_module(lib, input_dir):
                            parts.append(f"Internal/{lib}")
                        else:
                            parts.append(lib)
                    imp["module_display"] = "/".join(parts)
                else:
                    mod = imp.get("module", "")
                    if mod.startswith("."):
                        imp["module_display"] = "ELF Section"
                    elif mod == "unknown":
                        imp["module_display"] = "ELF"
                    else:
                        imp["module_display"] = mod
        else:
            for imp in data.get("imports", []):
                imp["module_display"] = imp.get("module", imp.get("module_display", ""))

        if "elf_sections" not in data:
            data["elf_sections"] = []
        if "exports" not in data:
            data["exports"] = []

        # Сортировка функций: экспортные вперёд
        if "functions" in data and "exports" in data:
            export_names = {exp["name"] for exp in data["exports"]}
            data["functions"].sort(
                key=lambda f: (0 if f["name"] in export_names else 1,
                               int(f["start_ea"], 16))
            )

        if output_html is None:
            output_html = json_path.with_suffix('.html')
        output_html.parent.mkdir(parents=True, exist_ok=True)

        if reports_dir is not None:
            try:
                rel = output_html.relative_to(reports_dir)
                back_link = compute_back_link(rel)
            except ValueError:
                back_link = "index.html"
        else:
            back_link = "index.html"
        data["back_link"] = back_link

        html = self.report_template.render(data)
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Индивидуальный отчёт сохранён: {output_html}")
        return output_html

    def generate_index(self, reports_dir: Path, input_dir: Path,
                       reports: List[dict], unique_modules: List[str],
                       ida_info: Optional[Dict[str, Any]] = None,
                       elf_sections: Optional[List[str]] = None) -> Path:
        for report in reports:
            report["filename"] = quote(report["filename"])

        categories: Dict[str, dict] = {}
        for mod in unique_modules:
            desc = self._classify_with_context(mod, input_dir)
            if "Собственный модуль" in desc:
                cat = "Внутренние модули проекта"
                cat_desc = "Библиотеки и исполняемые файлы, находящиеся внутри исследуемой директории."
            else:
                cat, cat_desc = get_module_category_and_description(mod)
            categories.setdefault(cat, {"description": cat_desc, "modules": []})
            categories[cat]["modules"].append({
                "name": mod,
                "desc": desc
            })

        grouped_list: List[dict] = []
        if "Внутренние модули проекта" in categories:
            info = categories.pop("Внутренние модули проекта")
            info["modules"] = sorted(info["modules"], key=lambda x: x["name"].lower())
            grouped_list.append({
                "name": "Внутренние модули проекта",
                "description": info["description"],
                "modules": info["modules"],
                "count": len(info["modules"]),
            })

        sorted_cats = sorted([c for c in categories if c != "Неопознанные модули"])
        if "Неопознанные модули" in categories:
            sorted_cats.append("Неопознанные модули")

        for cat in sorted_cats:
            info = categories[cat]
            info["modules"] = sorted(info["modules"], key=lambda x: x["name"].lower())
            grouped_list.append({
                "name": cat,
                "description": info["description"],
                "modules": info["modules"],
                "count": len(info["modules"]),
            })

        data = {
            "input_dir": str(input_dir),
            "total_modules": len(reports),
            "grouped_categories": grouped_list,
            "reports": reports,
            "ida_info": ida_info,
            "elf_sections": sorted(elf_sections or []),
        }

        index_path = reports_dir / "index.html"
        html = self.index_template.render(data)
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Сводный отчёт сохранён: {index_path}")
        return index_path