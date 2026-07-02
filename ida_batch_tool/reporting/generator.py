"""Генератор HTML-отчётов с детерминированной группировкой модулей и описаниями."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from abc import ABC, abstractmethod
from jinja2 import Environment, FileSystemLoader, select_autoescape
from urllib.parse import quote

from ida_batch_tool.classifier.platform_classifier import get_platform_classifier, classify_module
from ida_batch_tool.classifier.categories import get_module_category_and_description
from ida_batch_tool.reporting.utils import compute_back_link, normalize_display_name

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _build_internal_set(input_dir: Optional[Path]) -> Set[str]:
    if input_dir is None or not input_dir.is_dir():
        return set()
    internal = set()
    for f in input_dir.rglob('*'):
        if f.is_file():
            internal.add(f.name.lower())
            internal.add(f.stem.lower())
    return internal


class BaseReportGenerator(ABC):
    """Абстрактный генератор отчёта для отдельной платформы/формата."""

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

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.report_template = self.env.get_template("report.html")
        self.index_template = self.env.get_template("index.html")
        self._classifier = None  # будет установлен в наследниках

    @staticmethod
    def _normalize_display_name(module_name: str) -> str:
        # Делегируем канонической реализации из reporting.utils
        return normalize_display_name(module_name)

    def _is_internal_module(self, module_name: str, internal_set: Optional[Set[str]]) -> bool:
        if internal_set is None:
            return False
        name_lower = module_name.lower()
        stem = Path(module_name).stem.lower()
        return name_lower in internal_set or stem in internal_set

    def _classify_with_context(self, module_name: str, internal_set: Optional[Set[str]]) -> str:
        if self._is_internal_module(module_name, internal_set):
            return "Собственный модуль проекта (внутренняя библиотека)"
        if self._classifier:
            desc = self._classifier.classify(module_name)
            if desc:
                return desc
        return "Неопознанный модуль"

    def _classify_full(self, module_name: str, internal_set: Optional[Set[str]]) -> Tuple[str, str]:
        desc = self._classify_with_context(module_name, internal_set)
        if "Собственный модуль" in desc:
            return "Internal", desc
        cat_ru, _ = get_module_category_and_description(module_name)
        return self.CATEGORY_LABELS.get(cat_ru, "Unknown"), desc

    @abstractmethod
    def prepare_report_data(self, data: Dict[str, Any], internal_set: Optional[Set[str]]) -> Dict[str, Any]:
        ...

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None,
                           reports_dir: Optional[Path] = None,
                           input_dir: Optional[Path] = None,
                           internal_set: Optional[Set[str]] = None) -> Path:
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if internal_set is None and input_dir is not None:
            internal_set = _build_internal_set(input_dir)

        data = self.prepare_report_data(data, internal_set)

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
                       elf_sections: Optional[List[str]] = None,
                       internal_set: Optional[Set[str]] = None,
                       total_files: Optional[int] = None,
                       total_size_bytes: Optional[int] = None,
                       error_count: Optional[int] = None,
                       generation_time: Optional[str] = None) -> Path:
        for report in reports:
            report["filename"] = quote(report["filename"])

        if internal_set is None:
            internal_set = _build_internal_set(input_dir)

        categories: Dict[str, dict] = {}
        for mod in unique_modules:
            display_mod = self._normalize_display_name(mod)
            # Универсальный классификатор для сводного индекса
            if self._is_internal_module(mod, internal_set):
                desc = "Собственный модуль проекта (внутренняя библиотека)"
                cat = "Внутренние модули проекта"
                cat_desc = "Библиотеки и исполняемые файлы, находящиеся внутри исследуемой директории."
            else:
                desc = classify_module(mod)  # композитный поиск по всем платформам
                cat, cat_desc = get_module_category_and_description(mod)
            categories.setdefault(cat, {"description": cat_desc, "modules": []})
            categories[cat]["modules"].append({
                "name": display_mod,
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

        if total_files is None:
            total_files = len(reports)
        if total_size_bytes is None:
            total_size_bytes = 0
            for r in reports:
                p = Path(r.get('display_name', ''))
                if p.exists():
                    total_size_bytes += p.stat().st_size
        if error_count is None:
            error_count = 0
        if generation_time is None:
            generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        data = {
            "input_dir": str(input_dir),
            "total_modules": len(reports),
            "grouped_categories": grouped_list,
            "reports": reports,
            "ida_info": ida_info,
            "elf_sections": sorted(elf_sections or []),
            "total_files": total_files,
            "total_size_bytes": total_size_bytes,
            "error_count": error_count,
            "generation_time": generation_time,
        }

        index_path = reports_dir / "index.html"
        html = self.index_template.render(data)
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Сводный отчёт сохранён: {index_path}")
        return index_path


class WindowsReportGenerator(BaseReportGenerator):
    def __init__(self):
        super().__init__()
        self._classifier = get_platform_classifier("Windows")

    def prepare_report_data(self, data, internal_set):
        known = []
        unknown = []
        seen = set()
        for imp in data.get("imports", []):
            mod = imp.get("module")
            if not mod or mod.lower() == "unknown":
                continue
            if mod in seen:
                continue
            seen.add(mod)
            desc = self._classify_with_context(mod, internal_set)
            if "Собственный модуль" in desc:
                known.append(self._normalize_display_name(mod))
            elif "Неопознанный" in desc:
                unknown.append(self._normalize_display_name(mod))
            else:
                known.append(self._normalize_display_name(mod))
        data["known_modules"] = sorted(known)
        data["unknown_modules"] = sorted(unknown)
        data["elf_sections"] = []

        module_counts = {}
        for imp in data.get("imports", []):
            mod = imp.get("module")
            if not mod or mod.lower() == "unknown":
                continue
            short = self._normalize_display_name(mod)
            module_counts[short] = module_counts.get(short, 0) + 1
        deps = []
        for mod, count in module_counts.items():
            cat_label, desc = self._classify_full(mod, internal_set)
            color = self.CATEGORY_COLORS.get(cat_label, "#9E9E9E")
            deps.append({"name": mod, "category": cat_label, "count": count,
                         "description": desc, "color": color})
        data["module_deps"] = sorted(deps, key=lambda x: (x["category"], x["name"]))

        for imp in data.get("imports", []):
            imp["module_display"] = self._normalize_display_name(imp.get("module", ""))
        return data


class ELFReportGenerator(BaseReportGenerator):
    def __init__(self):
        super().__init__()
        self._classifier = get_platform_classifier("Linux / Android")

    def prepare_report_data(self, data, internal_set):
        needed_libs = data.get("needed_libs", [])
        known = []
        unknown = []
        for lib in needed_libs:
            desc = self._classify_with_context(lib, internal_set)
            if "Собственный модуль" in desc:
                known.append(self._normalize_display_name(lib))
            elif "Неопознанный" in desc:
                unknown.append(self._normalize_display_name(lib))
            else:
                known.append(self._normalize_display_name(lib))
        data["known_modules"] = sorted(known)
        data["unknown_modules"] = sorted(unknown)
        data["elf_sections"] = []

        module_counts = {}
        for lib in needed_libs:
            short = self._normalize_display_name(lib)
            module_counts[short] = module_counts.get(short, 0) + 1
        deps = []
        for mod, count in module_counts.items():
            cat_label, desc = self._classify_full(mod, internal_set)
            color = self.CATEGORY_COLORS.get(cat_label, "#9E9E9E")
            deps.append({"name": mod, "category": cat_label, "count": count,
                         "description": desc, "color": color})
        data["module_deps"] = sorted(deps, key=lambda x: (x["category"], x["name"]))

        for imp in data.get("imports", []):
            resolved = imp.get("resolved_libs", [])
            if resolved:
                parts = []
                for lib in resolved:
                    if self._is_internal_module(lib, internal_set):
                        parts.append(f"Internal/{self._normalize_display_name(lib)}")
                    else:
                        parts.append(self._normalize_display_name(lib))
                imp["module_display"] = "/".join(parts)
            else:
                mod = imp.get("module", "")
                if mod.startswith("."):
                    imp["module_display"] = "ELF Section"
                elif mod == "unknown":
                    imp["module_display"] = "ELF"
                else:
                    imp["module_display"] = self._normalize_display_name(mod)
        return data


class MachOReportGenerator(BaseReportGenerator):
    def __init__(self):
        super().__init__()
        self._classifier = get_platform_classifier("macOS / iOS")

    def prepare_report_data(self, data, internal_set):
        imports = data.get("imports", [])
        module_counts = {}
        for imp in imports:
            mod = imp.get("module")
            if not mod:
                continue
            short = self._normalize_display_name(mod)
            module_counts[short] = module_counts.get(short, 0) + 1

        known = []
        unknown = []
        for mod in module_counts.keys():
            desc = self._classify_with_context(mod, internal_set)
            if "Собственный модуль" in desc:
                known.append(mod)
            elif "Неопознанный" in desc:
                unknown.append(mod)
            else:
                known.append(mod)
        data["known_modules"] = sorted(known)
        data["unknown_modules"] = sorted(unknown)
        data["elf_sections"] = []

        deps = []
        for mod, count in module_counts.items():
            cat_label, desc = self._classify_full(mod, internal_set)
            color = self.CATEGORY_COLORS.get(cat_label, "#9E9E9E")
            deps.append({
                "name": mod,
                "category": cat_label,
                "count": count,
                "description": desc,
                "color": color
            })
        data["module_deps"] = sorted(deps, key=lambda x: (x["category"], x["name"]))

        # Исправление: безопасное присвоение module_display
        for imp in imports:
            if "module" in imp:
                imp["module_display"] = self._normalize_display_name(imp["module"])
            else:
                imp["module_display"] = imp.get("module_display", "")
        return data


class ReportGenerator:
    def __init__(self):
        self._windows = WindowsReportGenerator()
        self._elf = ELFReportGenerator()
        self._macho = MachOReportGenerator()

    def _select_generator(self, data: Dict[str, Any]) -> BaseReportGenerator:
        if data.get("is_macho"):
            return self._macho
        elif data.get("is_elf"):
            return self._elf
        else:
            return self._windows

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None,
                           reports_dir: Optional[Path] = None,
                           input_dir: Optional[Path] = None,
                           internal_set: Optional[Set[str]] = None) -> Path:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        gen = self._select_generator(data)
        return gen.generate_from_json(json_path, output_html, reports_dir, input_dir, internal_set)

    def generate_index(self, reports_dir: Path, input_dir: Path,
                       reports: List[dict], unique_modules: List[str],
                       ida_info: Optional[Dict[str, Any]] = None,
                       elf_sections: Optional[List[str]] = None,
                       internal_set: Optional[Set[str]] = None,
                       total_files: Optional[int] = None,
                       total_size_bytes: Optional[int] = None,
                       error_count: Optional[int] = None,
                       generation_time: Optional[str] = None) -> Path:
        return self._macho.generate_index(
            reports_dir, input_dir, reports, unique_modules,
            ida_info, elf_sections, internal_set,
            total_files, total_size_bytes, error_count, generation_time
        )
    
class DiffReportGenerator(BaseReportGenerator):
    """Генератор отчёта сравнения из .diff.json."""

    def __init__(self):
        super().__init__()
        self.diff_template = self.env.get_template("diff_report.html")
        # переназначаем report_template для использования в generate_from_json
        self.report_template = self.diff_template
        from ida_batch_tool.classifier.platform_classifier import get_platform_classifier
        self._classifier = get_platform_classifier("Linux / Android")

    def prepare_report_data(self, data: Dict[str, Any],
                            internal_set: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Дополняет данные для шаблона, сохраняя все поля из JSON."""
        data.setdefault("matched_functions", [])
        data.setdefault("matched_diaphora_only", [])
        data.setdefault("file1", {})
        data.setdefault("file2", {})
        data.setdefault("total_functions1", 0)
        data.setdefault("total_functions2", 0)
        data.setdefault("engine", "bindiff")
        data.setdefault("diaphora_matched_count", 0)
        data.setdefault("unmatched_functions1", [])
        data.setdefault("unmatched_functions2", [])
        data.setdefault("total_unmatched", 0)
        data["total_matched"] = len(data["matched_functions"])

        # Вычисляем matched_summary, если его нет (BinDiff-only или Diaphora-only)
        if "matched_summary" not in data or not data["matched_summary"]:
            mf = data.get("matched_functions", [])
            bindiff_only = sum(1 for m in mf if m.get("source") == "bindiff")
            diaphora_only = sum(1 for m in mf if m.get("source") == "diaphora")
            both = sum(1 for m in mf if m.get("source") == "both")
            data["matched_summary"] = {
                "total": len(mf),
                "bindiff_only": bindiff_only,
                "diaphora_only": diaphora_only,
                "both": both,
            }

        return data

    def generate_diff_index(self, reports_dir: Path, json_files: List[Path],
                            left_dir: Path, right_dir: Path,
                            generation_time: str = "",
                            ida_version: str = "") -> Path:
        """
        Создаёт индексный HTML-файл со сводкой всех сравнений.
        """
        pairs = []
        total_similarity = 0.0
        total_confidence = 0.0
        count = 0

        for jf in json_files:
            with open(jf, "r", encoding="utf-8") as f:
                data = json.load(f)
            stem = jf.stem.replace(".diff", "")
            html_filename = stem + ".html"
            sim = float(data.get("similarity", 0.0))
            conf = float(data.get("confidence", 0.0))
            matched = len(data.get("matched_functions", []))
            total1 = data.get("total_functions1", 0)
            hash1 = data.get("file1", {}).get("hash", "")
            hash2 = data.get("file2", {}).get("hash", "")
            real_prim = data.get("real_primary", "")
            real_sec = data.get("real_secondary", "")
            # Имя реального исполняемого файла (без .i64)
            if real_prim:
                real_name = Path(real_prim).name
            else:
                real_name = stem.replace("_i64", "")
            hexdump_sim = float(data.get("hexdump_similarity", 0.0))
            # Если hexdump 100% — используем его как основную схожесть
            display_sim = hexdump_sim if hexdump_sim >= 1.0 else sim
            pairs.append({
                "stem": real_name,
                "similarity": sim,
                "display_similarity": display_sim,
                "hexdump_similarity": hexdump_sim,
                "confidence": conf,
                "matched_count": matched,
                "total_funcs1": total1,
                "report_filename": html_filename,
                "hash1": hash1,
                "hash2": hash2,
                "engine": data.get("engine", "bindiff"),
                "diaphora_matched_count": data.get("diaphora_matched_count", 0),
            })
            total_similarity += display_sim
            total_confidence += conf
            count += 1

        avg_similarity = total_similarity / count if count else 0.0
        avg_confidence = total_confidence / count if count else 0.0

        template = self.env.get_template("diff_index.html")
        html = template.render(
            left_dir=str(left_dir),
            right_dir=str(right_dir),
            total_pairs=count,
            avg_similarity=avg_similarity,
            avg_confidence=avg_confidence,
            pairs=pairs,
            generation_time=generation_time,
            ida_version=ida_version,
        )
        index_path = reports_dir / "index.html"
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"Сводный отчёт сохранён: {index_path}")
        return index_path