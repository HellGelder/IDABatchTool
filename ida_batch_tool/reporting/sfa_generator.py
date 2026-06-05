# ida_batch_tool/reporting/sfa_generator.py
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ida_batch_tool.config.loader import get_sf_db_path
from ida_batch_tool.reporting.utils import compute_back_link

TEMPLATES_DIR = Path(__file__).parent / "templates"


class SfaReportGenerator:
    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.report_template = self.env.get_template("sfa_report.html")
        self.index_template = self.env.get_template("sfa_index.html")

    def generate_report_from_json(self, json_path: Path, output_html: Path, reports_dir: Path = None) -> None:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        file_name = data.get("file_name", "")
        imports = data.get("imports", [])

        db_path = Path(get_sf_db_path()) / "win32api.db"
        if not db_path.exists():
            html = self.report_template.render(
                file_name=file_name,
                error="База данных системных функций не найдена. Выполните синхронизацию в настройках.",
                system_calls=[],
                back_link="index.html"
            )
            output_html.write_text(html, encoding="utf-8")
            return

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        system_calls = []
        for imp in imports:
            func_name = imp.get("name")
            if not func_name:
                continue
            cursor.execute(
                "SELECT id, dll_name, return_type, n_arguments FROM functions WHERE name = ?",
                (func_name,)
            )
            row = cursor.fetchone()
            if not row:
                continue
            func_id, dll_name, return_type, n_arguments = row
            cursor.execute(
                "SELECT idx, name, type, in_out FROM parameters WHERE function_id = ? ORDER BY idx",
                (func_id,)
            )
            params = []
            for p in cursor.fetchall():
                params.append({
                    "idx": p[0],
                    "name": p[1],
                    "type": p[2],
                    "in_out": p[3] or "in"
                })
            system_calls.append({
                "name": func_name,
                "dll": dll_name,
                "return_type": return_type or "unknown",
                "expected_args": n_arguments or len(params),
                "params": params,
                "address": imp.get("address", ""),
                "module": imp.get("module", ""),
                "warning": None
            })
        conn.close()

        back_link = "index.html"
        if reports_dir:
            try:
                rel = output_html.relative_to(reports_dir)
                back_link = compute_back_link(rel)
            except ValueError:
                pass

        html = self.report_template.render(
            file_name=file_name,
            system_calls=system_calls,
            error=None,
            back_link=back_link
        )
        output_html.write_text(html, encoding="utf-8")

    def generate_index(self, reports_dir: Path, input_dir: Path, reports: list,
                       ida_info: dict = None, total_files: int = 0,
                       total_size_bytes: int = 0, generation_time: str = "") -> Path:
        if not generation_time:
            generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        data = {
            "input_dir": str(input_dir),
            "total_files": total_files,
            "total_size_bytes": total_size_bytes,
            "reports": reports,
            "generation_time": generation_time,
        }
        html = self.index_template.render(data)
        index_path = reports_dir / "index.html"
        index_path.write_text(html, encoding="utf-8")
        return index_path