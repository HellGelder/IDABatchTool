# ida_batch_tool/reporting/sfa_generator.py
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
import yaml
import markdown

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
        self._func_url_map = None
        self._doc_cache = {}
        self._log_file = None
        self._docs_dir = None

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

    # ----------------------------------------------------------------
    # Построение словаря имя_функции -> URL из всех TOC.yml
    # ----------------------------------------------------------------
    def _build_func_url_map(self):
        db_dir = Path(get_sf_db_path())
        self._docs_dir = db_dir / "win32_docs"
        if not self._docs_dir.exists():
            self._log(f"[ERROR] docs_dir not found: {self._docs_dir}")
            return {}

        func_url = {}

        def href_to_url(href, base_path):
            if not href:
                return None
            href_str = str(href)
            if href_str.startswith(('http://', 'https://')):
                return href_str
            # строим относительный путь от корня docs_dir
            if href_str.startswith('/'):
                rel_path = href_str.lstrip('/')
            else:
                full_path = (base_path / href_str).resolve()
                try:
                    rel_path = full_path.relative_to(self._docs_dir).as_posix()
                except ValueError:
                    rel_path = href_str
            if rel_path.endswith('.md'):
                url_path = rel_path[:-3]
                if 'sdk-api-src/content' in url_path:
                    url_path = url_path.replace('sdk-api-src/content', 'api')
                return f"https://learn.microsoft.com/en-us/windows/win32/{url_path}"
            return None

        def process_items(items, current_base):
            if not items:
                return
            for item in items:
                if not isinstance(item, dict):
                    continue
                # если элемент имеет name и href
                if 'name' in item and 'href' in item:
                    href = item['href']
                    name = item['name']
                    if href and isinstance(href, str):
                        if href.endswith('.md') and 'nf-' in href:
                            url = href_to_url(href, current_base)
                            if url:
                                func_url[name] = url
                        elif href.endswith('.yml'):
                            sub_toc_path = current_base / href
                            if sub_toc_path.exists():
                                self._process_toc_file(sub_toc_path, func_url)
                # рекурсивно обрабатываем вложенные items
                if 'items' in item and isinstance(item['items'], list):
                    process_items(item['items'], current_base)

        def process_toc_file(toc_path, func_url):
            try:
                with open(toc_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                if data is None:
                    return
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict) and 'items' in data:
                    items = data['items']
                else:
                    return
                process_items(items, toc_path.parent)
            except Exception as e:
                self._log(f"[ERROR] Failed to parse {toc_path}: {e}")

        # делаем process_toc_file методом класса, чтобы была возможность рекурсивно вызывать
        self._process_toc_file = process_toc_file

        root_toc = self._docs_dir / "toc.yml"
        if root_toc.exists():
            self._process_toc_file(root_toc, func_url)
        else:
            for toc in self._docs_dir.rglob("toc.yml"):
                self._process_toc_file(toc, func_url)

        self._log(f"[INFO] Built URL mapping for {len(func_url)} functions")
        return func_url

    # ----------------------------------------------------------------
    # Загрузка документации через microsoft-learn-cli
    # ----------------------------------------------------------------
    def _fetch_doc_markdown(self, url):
        self._log(f"[INFO] Fetching {url} ...")
        try:
            proc = subprocess.run(
                ["npx", "--yes", "@microsoft/learn-cli", "fetch", url, "--json"],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8'
            )
            if proc.returncode != 0:
                self._log(f"[ERROR] CLI error for {url}: {proc.stderr}")
                return None
            data = json.loads(proc.stdout)
            markdown_content = data.get("content", "")
            if not markdown_content:
                self._log(f"[ERROR] Empty content for {url}")
                return None
            self._log(f"[INFO] Fetched {len(markdown_content)} chars for {url}")
            return markdown_content
        except subprocess.TimeoutExpired:
            self._log(f"[ERROR] Timeout fetching {url}")
            return None
        except json.JSONDecodeError as e:
            self._log(f"[ERROR] JSON decode error for {url}: {e}")
            return None
        except FileNotFoundError:
            self._log("[ERROR] npx not found – install Node.js")
            return None
        except Exception as e:
            self._log(f"[ERROR] Unexpected error fetching {url}: {e}")
            return None

    def _markdown_to_html(self, md_text):
        try:
            return markdown.markdown(md_text, extensions=['extra', 'codehilite'])
        except Exception as e:
            self._log(f"[ERROR] Markdown conversion error: {e}")
            return f"<pre>{md_text}</pre>"

    # ----------------------------------------------------------------
    # Генерация отчёта для одного JSON
    # ----------------------------------------------------------------
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

        # Строим словарь URL (один раз)
        if self._func_url_map is None:
            self._func_url_map = self._build_func_url_map()

        # Загружаем кэш документации
        cache_file = Path(get_sf_db_path()) / "doc_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    self._doc_cache = json.load(f)
                self._log(f"[INFO] Loaded doc_cache with {len(self._doc_cache)} entries")
            except Exception as e:
                self._log(f"[WARN] Failed to load doc_cache: {e}")

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        system_calls = []
        for imp in imports:
            func_name = imp.get("name")
            if not func_name:
                continue
            self._log(f"[DEBUG] Processing function: {func_name}")

            cursor.execute("SELECT dll_name, return_type, n_arguments FROM functions WHERE name = ?", (func_name,))
            row = cursor.fetchone()
            if not row:
                self._log(f"[DEBUG] No signature found for {func_name} in DB")
                continue
            dll_name, return_type, n_arguments = row
            self._log(f"[DEBUG] Signature: dll={dll_name}, return={return_type}, n_args={n_arguments}")

            cursor.execute(
                "SELECT idx, name, type, in_out FROM parameters WHERE function_id = (SELECT id FROM functions WHERE name = ?) ORDER BY idx",
                (func_name,)
            )
            params = []
            for p in cursor.fetchall():
                params.append({
                    "idx": p[0],
                    "name": p[1] if p[1] else f"arg{p[0]}",
                    "type": p[2] if p[2] else "unknown",
                    "in_out": p[3] if p[3] else "in"
                })
            self._log(f"[DEBUG] Found {len(params)} parameters for {func_name}")

            doc_html = None
            url = self._func_url_map.get(func_name)
            if url:
                self._log(f"[DEBUG] URL found: {url}")
                if func_name in self._doc_cache:
                    doc_html = self._doc_cache[func_name]
                    self._log(f"[INFO] Using cached doc for {func_name}")
                else:
                    md = self._fetch_doc_markdown(url)
                    if md:
                        doc_html = self._markdown_to_html(md)
                        self._doc_cache[func_name] = doc_html
                        with open(cache_file, "w", encoding="utf-8") as f:
                            json.dump(self._doc_cache, f, indent=2, ensure_ascii=False)
                        self._log(f"[INFO] Fetched and cached doc for {func_name}")
                    else:
                        doc_html = f"<p>❌ Не удалось загрузить документацию для <code>{func_name}</code> (ошибка fetch).</p>"
                        self._log(f"[ERROR] Failed to fetch doc for {func_name}")
            else:
                doc_html = f"<p>❌ Ссылка на документацию для <code>{func_name}</code> не найдена в TOC.yml.</p>"
                self._log(f"[ERROR] No URL mapping for {func_name}")

            system_calls.append({
                "name": func_name,
                "dll": dll_name,
                "return_type": return_type or "unknown",
                "expected_args": n_arguments or len(params),
                "params": params,
                "address": imp.get("address", ""),
                "module": imp.get("module", ""),
                "warning": None,
                "doc_html": doc_html
            })

        conn.close()
        self._log(f"[INFO] Generated {len(system_calls)} system calls for {file_name}")

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

    # ----------------------------------------------------------------
    # Вспомогательные методы
    # ----------------------------------------------------------------
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