import json
import subprocess
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional, List as TypedList
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ida_batch_tool.database.sfa_doc_cache import DocCacheManager
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
        self._doc_cache: DocCacheManager | None = None
        self._log_file = None
        self._npx_path = None
        # Загружаем marked.min.js один раз
        self._marked_js = self._load_marked_js()

    @staticmethod
    def _load_marked_js() -> str:
        """Загружает содержимое marked.min.js для inline-встраивания в HTML."""
        src = TEMPLATES_DIR / "vendor" / "marked.min.js"
        if src.is_file():
            try:
                return src.read_text(encoding="utf-8")
            except Exception:
                pass
        return ""

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
                encoding='utf-8',
                errors='replace',
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
                    if i+1 < len(lines) and (lines[i+1].strip().startswith('http://') or lines[i+1].strip().startswith('https://')):
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
                            "markdown": markdown_text,
                            "markdown_html": self._render_markdown(markdown_text),
                        })
                else:
                    i += 1
            return results
        except Exception as e:
            self._log(f"[ERROR] Exception: {e}")
            return []

    @staticmethod
    def _render_markdown(text: str) -> str:
        """Рендерит Markdown в HTML (если доступна библиотека markdown)."""
        try:
            import markdown
            return markdown.markdown(text, extensions=['fenced_code', 'codehilite'])
        except ImportError:
            # fallback: если библиотека не установлена — возвращаем как есть
            return ""

    def generate_report_from_json(
        self,
        json_path: Path,
        output_html: Path,
        reports_dir: Path = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> None:
        """Генерирует HTML-отчёт СФ из JSON-файла экспорта IDA.

        Args:
            json_path: путь к .export.json.
            output_html: куда писать .sfa.html.
            reports_dir: корневая папка отчётов (для кэша и лога).
            progress_callback: вызывается после каждой обработанной функции
                с аргументами (function_name, current_idx, total_in_file).
        """
        if reports_dir:
            self._init_log(reports_dir)
        self._log(f"[INFO] Processing {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        file_name = data.get("file_name", "")
        imports = data.get("imports", [])
        total_imports = len(imports)
        self._log(f"[INFO] Found {total_imports} imports in {file_name}")

        # Создаём/открываем DocCacheManager (потокобезопасный кэш)
        cache_db = reports_dir / "mslearn_cache.db" if reports_dir else None
        if cache_db:
            try:
                self._doc_cache = DocCacheManager(cache_db)
                self._log(f"[INFO] MS Learn cache: {cache_db} ({self._doc_cache.count()} функций)")
            except Exception as e:
                self._log(f"[WARN] Failed to open cache DB: {e}")
                self._doc_cache = None
        else:
            self._doc_cache = None

        system_calls = []
        for idx, imp in enumerate(imports):
            func_name = imp.get("name")
            if not func_name:
                continue
            self._log(f"[DEBUG] Processing import: {func_name}")

            # Сообщаем прогресс (перед обработкой функции)
            if progress_callback:
                progress_callback(func_name, idx, total_imports)

            # Пытаемся взять dll_name из импорта JSON-экспорта IDA
            dll_name = imp.get("module", "") or "—"

            # Получаем результаты поиска (из кэша или Microsoft Learn)
            results = []
            if self._doc_cache and self._doc_cache.has_function(func_name):
                results = self._doc_cache.get_results(func_name)
                # Берём dll_name из кэша, если там сохранили
                cached_dll = self._doc_cache.get_dll_name(func_name)
                if cached_dll:
                    dll_name = cached_dll
                self._log(f"[INFO] Using cached results for {func_name} (count: {len(results)})")
            else:
                results = self._search_function(func_name)
                if results:
                    # Извлекаем dll_name из результатов Microsoft Learn (если есть)
                    for r in results:
                        md = r.get("markdown", "")
                        dll_match = re.search(r'[Dd][Ll][Ll]\s*:\s*(\S+\.dll)', md)
                        if dll_match:
                            dll_name = dll_match.group(1)
                            break

                    if self._doc_cache:
                        try:
                            # Асинхронная запись: не блокирует поток
                            self._doc_cache.save_results(func_name, results, dll_name=dll_name)
                            self._log(f"[INFO] Fetched and cached {len(results)} results for {func_name}")
                        except Exception as e:
                            self._log(f"[WARN] Failed to save cache: {e}")
                else:
                    self._log(f"[ERROR] No results for {func_name}")

            system_calls.append({
                "name": func_name,
                "dll": dll_name,
                "return_type": "—",
                "expected_args": 0,
                "params": [],
                "address": imp.get("address", ""),
                "module": imp.get("module", ""),
                "warning": None,
                "search_results": results,
            })

        self._log(f"[INFO] Generated {len(system_calls)} system calls")

        back_link = "index.html"
        if reports_dir:
            try:
                rel = output_html.relative_to(reports_dir)
                back_link = compute_back_link(rel)
            except ValueError:
                pass

        # Сбрасываем кэш-менеджер (ждём завершения всех записей)
        if self._doc_cache:
            self._doc_cache.flush()

        html = self.report_template.render(
            file_name=file_name,
            system_calls=system_calls,
            error=None,
            back_link=back_link,
            marked_js=self._marked_js,
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
            back_link=back_link,
            marked_js=self._marked_js,
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