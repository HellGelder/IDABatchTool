import json
import sqlite3
import subprocess
import re
import shutil
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
        self._doc_cache = {}
        self._log_file = None
        self._npx_path = None

    def _init_log(self, reports_dir: Path):
        if self._log_file is None:
            log_path = reports_dir / "sfa_debug.log"
            self._log_file = open(log_path, "w", encoding="utf-8")
            self._log(f"=== SFA Debug Log started at {datetime.now().isoformat()} ===\n")

    def _log(self, message: str):
        print(message)
        if self._log_file:
            self._log_file.write(message + "\n")
            self._log_file.flush()

    def close_log(self):
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _get_npx_path(self):
        if self._npx_path:
            return self._npx_path
        # Ищем npx в PATH
        npx = shutil.which("npx")
        if npx:
            self._npx_path = npx
            return npx
        # Стандартные пути на Windows
        possible_paths = [
            r"C:\Program Files\nodejs\npx.cmd",
            r"C:\Program Files\nodejs\npx.exe",
            r"C:\ProgramData\chocolatey\bin\npx.exe"
        ]
        for p in possible_paths:
            if Path(p).exists():
                self._npx_path = p
                return p
        return None

    def _search_function(self, func_name):
        npx = self._get_npx_path()
        if not npx:
            self._log("[ERROR] npx not found. Please install Node.js and ensure it's in PATH.")
            return []
        self._log(f"[DEBUG] Running: {npx} @microsoft/learn-cli search {func_name}")
        try:
            proc = subprocess.run(
                [npx, "@microsoft/learn-cli", "search", func_name],
                capture_output=True,
                text=True,
                timeout=15,
                encoding='utf-8'
            )
            if proc.returncode != 0:
                self._log(f"[ERROR] npx search failed: {proc.stderr}")
                return []
            output = proc.stdout
            # Парсим результаты
            results = []
            lines = output.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i]
                # Ищем строку вида "[1] Some Title"
                if re.match(r'^\[\d+\]', line):
                    title_match = re.match(r'^\[\d+\]\s+(.+)$', line)
                    title = title_match.group(1).strip() if title_match else "Untitled"
                    url = ""
                    if i+1 < len(lines) and (lines[i+1].startswith('http://') or lines[i+1].startswith('https://')):
                        url = lines[i+1].strip()
                        i += 1
                    i += 1
                    while i < len(lines) and lines[i].strip() == "":
                        i += 1
                    md_lines = []
                    while i < len(lines) and not re.match(r'^\[\d+\]', lines[i]):
                        md_lines.append(lines[i])
                        i += 1
                    markdown_text = "\n".join(md_lines).strip()
                    if markdown_text:
                        results.append({
                            "title": title,
                            "url": url,
                            "markdown": markdown_text
                        })
                else:
                    i += 1
            return results
        except Exception as e:
            self._log(f"[ERROR] Exception: {e}")
            return []

    def generate_report_from_json(self, json_path: Path, output_html: Path, reports_dir: Path = None) -> None:
        if reports_dir:
            self._init_log(reports_dir)
        self._log(f"[INFO] Processing {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        file_name = data.get("file_name", "")
        imports = data.get("imports", [])
        self._log(f"[INFO] Found {len(imports)} imports in {file_name}")

        db_path = Path(get_sf_db_path()) / "win32api.db"
        if not db_path.exists():
            self._generate_error_report(file_name, output_html, "База сигнатур не найдена. Выполните синхронизацию.", reports_dir)
            return

        cache_file = Path(get_sf_db_path()) / "doc_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    self._doc_cache = json.load(f)
                self._log(f"[INFO] Loaded doc_cache with {len(self._doc_cache)} entries")
            except Exception as e:
                self._log(f"[WARN] Failed to load doc_cache: {e}")

        conn = sqlite3.connect(str(db_path))
        try:
            cursor = conn.cursor()

            system_calls = []
            for imp in imports:
                func_name = imp.get("name")
                if not func_name:
                    continue
                self._log(f"[DEBUG] Processing import: {func_name}")

                cursor.execute("SELECT dll_name, return_type, n_arguments FROM functions WHERE name = ?", (func_name,))
                row = cursor.fetchone()
                if not row:
                    self._log(f"[DEBUG] No signature in DB for {func_name}")
                    continue
                dll_name, return_type, n_arguments = row

                cursor.execute(
                    "SELECT idx, name, type, in_out FROM parameters WHERE function_id = (SELECT id FROM functions WHERE name = ?) ORDER BY idx",
                    (func_name,)
                )
                params = [{"idx": p[0], "name": p[1] or f"arg{p[0]}", "type": p[2] or "unknown", "in_out": p[3] or "in"} for p in cursor.fetchall()]
                self._log(f"[DEBUG] Found {len(params)} parameters for {func_name}")

                # Получаем результаты поиска
                results = []
                if func_name in self._doc_cache:
                    results = self._doc_cache[func_name]
                    self._log(f"[INFO] Using cached results for {func_name} (count: {len(results)})")
                else:
                    results = self._search_function(func_name)
                    if results:
                        self._doc_cache[func_name] = results
                        with open(cache_file, "w", encoding="utf-8") as f:
                            json.dump(self._doc_cache, f, indent=2, ensure_ascii=False)
                        self._log(f"[INFO] Fetched and cached {len(results)} results for {func_name}")
                    else:
                        self._log(f"[ERROR] No results for {func_name}")

                system_calls.append({
                    "name": func_name,
                    "dll": dll_name,
                    "return_type": return_type or "unknown",
                    "expected_args": n_arguments or len(params),
                    "params": params,
                    "address": imp.get("address", ""),
                    "module": imp.get("module", ""),
                    "warning": None,
                    "search_results": results
                })
        finally:
            conn.close()
        self._log(f"[INFO] Generated {len(system_calls)} system calls")

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
        self._log(f"[INFO] Report saved to {output_html}")

    def _generate_error_report(self, file_name: str, output_html: Path, error_msg: str, reports_dir: Path = None) -> None:
        if reports_dir:
            self._init_log(reports_dir)
        back_link = "index.html"
        if reports_dir:
            try:
                rel = output_html.relative_to(reports_dir)
                back_link = compute_back_link(rel)
            except ValueError:
                pass
        html = self.report_template.render(
            file_name=file_name,
            system_calls=[],
            error=error_msg,
            back_link=back_link
        )
        output_html.write_text(html, encoding="utf-8")
        self._log(f"[INFO] Error report saved to {output_html}")

    def generate_index(self, reports_dir: Path, input_dir: Path, reports: list,
                       ida_info: dict = None,
                       total_files: int = 0, total_size_bytes: int = 0,
                       generation_time: str = "") -> Path:
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
        self.close_log()
        return index_path