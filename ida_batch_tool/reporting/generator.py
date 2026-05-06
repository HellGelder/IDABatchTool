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


class ReportGenerator:
    """Создаёт HTML-отчёты из JSON-файлов экспорта."""

    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.report_template = self.env.get_template("report.html")
        self.index_template = self.env.get_template("index.html")

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None,
                           reports_dir: Optional[Path] = None) -> Path:
        """
        Генерирует индивидуальный HTML-отчёт из JSON-файла экспорта.
        Возвращает путь к созданному HTML-файлу.
        """
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)

        is_elf: bool = data.get("is_elf", False)

        # Для PE формируем списки опознанных/неопознанных модулей
        if not is_elf:
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
                category = classify_module(mod)
                if "Неопознанный" in category:
                    unknown.append(mod)
                else:
                    known.append(mod)

            data["known_modules"] = sorted(known)
            data["unknown_modules"] = sorted(unknown)
            if "elf_sections" not in data:
                data["elf_sections"] = sorted(elf)

        if "elf_sections" not in data:
            data["elf_sections"] = []

        if "exports" not in data:
            data["exports"] = []

        if output_html is None:
            output_html = json_path.with_suffix('.html')
        output_html.parent.mkdir(parents=True, exist_ok=True)

        # Вычисляем ссылку на индекс
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
        """
        Создаёт индексный файл index.html в reports_dir.

        :param reports: список словарей {'filename': относительный_путь, 'display_name': текст}
        :param unique_modules: список имён модулей (не секций) – для ELF это имена .so библиотек
        :param elf_sections: список обнаруженных секций ELF
        """
        # Кодируем пробелы в ссылках
        for report in reports:
            report["filename"] = quote(report["filename"])

        # Группировка модулей по категориям
        categories: Dict[str, dict] = {}
        for mod in unique_modules:
            cat, desc = get_module_category_and_description(mod)
            categories.setdefault(cat, {"description": desc, "modules": []})
            categories[cat]["modules"].append({
                "name": mod,
                "desc": classify_module(mod)
            })

        grouped_list: List[dict] = []
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