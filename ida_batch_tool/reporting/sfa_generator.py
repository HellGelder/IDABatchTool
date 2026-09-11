import json
import subprocess
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional, List as TypedList, FrozenSet
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ida_batch_tool.database.sfa_doc_cache import DocCacheManager
from ida_batch_tool.database.sfa_function_index import SfaFunctionIndex
from ida_batch_tool.database.man_pages_db import ManPagesDatabase
from ida_batch_tool.classifier.system_modules import is_system_module, normalize_platform
from ida_batch_tool.reporting.utils import compute_back_link, compute_executables_size

TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass(frozen=True)
class SfaReportStats:
    """Статистика одного отчёта СФ для сводного индексного отчёта.

    Attributes:
        found_count: функций с найденной документацией.
        notfound_count: функций без документации.
        total_count: всего системных функций в отчёте.
        notfound_names: имена функций без документации (для агрегации
            уникального количества по всем модулям).
    """
    found_count: int
    notfound_count: int
    total_count: int
    notfound_names: FrozenSet[str] = field(default_factory=frozenset)


def _decode_bytes(data: bytes) -> str:
    """Декодирует байты из subprocess с автоопределением кодировки.

    На Windows npx(Node) может выводить в UTF-8 или в OEM (cp866) кодировке.
    Пробуем UTF-8, затем системную кодовую страницу, затем latin-1 (не падает).
    """
    if not data:
        return ""
    for enc in ("utf-8", "cp866", "cp1251", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")


def _normalize_func_name(func_name: str) -> str:
    """Нормализует имя функции для поиска в Microsoft Learn.

    Для C++ имён вида ``std::basic_streambuf<...>::sputc(char)``
    извлекает последний сегмент верхнего уровня: ``sputc``.
    Для операторов ``operator<<`` / ``operator>>`` сохраняет их как есть.
    """
    name = func_name.strip()
    if not name:
        return name

    # Ищем последний :: на верхнем уровне (глубина 0 — не внутри <> или ())
    depth = 0
    last_top_level_sep = -1
    for i, ch in enumerate(name):
        if ch in ("<", "(", "{"):
            depth += 1
        elif ch in (">", ")", "}"):
            depth -= 1
        elif ch == ":" and depth == 0 and i + 1 < len(name) and name[i + 1] == ":":
            last_top_level_sep = i

    if last_top_level_sep >= 0:
        # Берём сегмент после последнего :: верхнего уровня
        rest = name[last_top_level_sep + 2:].strip()
        # Убираем аргументы
        paren_idx = rest.find("(")
        if paren_idx >= 0:
            rest = rest[:paren_idx].strip()
        if rest:
            return rest

    # Не C++ имя или не получилось выделить — убираем аргументы
    paren_idx = name.find("(")
    if paren_idx >= 0:
        name = name[:paren_idx].strip()

    return name


def _sanitize_for_shell(func_name: str) -> str:
    """Экранирует имя функции для передачи npx через cmd.exe.

    npx.cmd — это cmd.exe-скрипт, поэтому ``<< >> | & ;`` ломают парсинг.
    Удаляем их полностью — для поиска это несущественно (Microsoft Learn
    ищет по подстроке, ``operator`` найдет всё).
    """
    result = func_name.replace("<<", "").replace(">>", "")
    result = result.replace("<", "").replace(">", "")
    result = result.replace("|", "").replace("&", "").replace(";", "")
    return result.strip()


class SfaReportGenerator:
    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.report_template = self.env.get_template("sfa_report.html")
        self.index_template = self.env.get_template("sfa_index.html")
        self._doc_cache: DocCacheManager | None = None
        self._man_pages: ManPagesDatabase | None = None
        self._man_pages_checked = False
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

    def _open_manpages(
        self,
        reports_dir: Optional[Path],
        manpages_db_path: Optional[Path],
    ) -> Optional[ManPagesDatabase]:
        """Открывает БД man-pages для платформы Linux/Android.

        Порядок поиска: явно переданный путь (из настроек), затем
        ``manpages.db`` рядом с папкой отчётов, затем в родительской папке.
        Результат поиска кэшируется: БД открывается один раз на весь прогон,
        а не для каждого файла отчёта.
        """
        # Повторный вызов (следующий файл) — возвращаем уже открытую БД.
        if self._man_pages is not None:
            return self._man_pages
        if self._man_pages_checked:
            return None

        candidates: list[Path] = []
        if manpages_db_path:
            candidates.append(Path(manpages_db_path))
        if reports_dir:
            candidates.append(Path(reports_dir) / "manpages.db")
            candidates.append(Path(reports_dir).parent / "manpages.db")

        for candidate in candidates:
            if candidate.is_file():
                db = ManPagesDatabase(candidate)
                if db.open():
                    self._log(
                        f"[INFO] man-pages DB: {candidate} "
                        f"(функций: {db.count()}, версия: {db.version()})"
                    )
                    self._man_pages = db
                    self._man_pages_checked = True
                    return db
                db.close()

        # Не нашли — запоминаем, чтобы не повторять поиск и не спамить в лог.
        self._man_pages_checked = True
        searched = ", ".join(str(c) for c in candidates) or "пути не заданы"
        self._log(
            f"[WARN] БД man-pages не найдена (искали: {searched}). "
            "Документация Linux недоступна. Укажите путь в настройках "
            "и выполните синхронизацию man-pages."
        )
        return None

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

        # Нормализуем имя для поиска, экранируем спецсимволы для npx
        search_name = _normalize_func_name(func_name)
        safe_name = _sanitize_for_shell(search_name)
        if not safe_name:
            self._log(f"[WARN] {func_name}: пустое имя после нормализации")
            return []

        self._log(f"[INFO] Searching: {func_name} → {safe_name}")
        try:
            proc = subprocess.run(
                [npx, "@microsoft/learn-cli", "search", safe_name],
                capture_output=True,
                text=False,
                timeout=45,
            )
            # Декодируем с автоопределением кодировки
            stdout = _decode_bytes(proc.stdout)
            stderr = _decode_bytes(proc.stderr)

            if proc.returncode != 0:
                self._log(f"[WARN] npx search returned {proc.returncode}: {stderr[:200]}")
                # Даже при ошибке пытаемся распарсить stdout (npx может выдать
                # результат на stdout, а предупреждения — на stderr)
                if not stdout.strip():
                    return []

            # Парсим результаты — берём только первый
            results = []
            lines = stdout.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i]
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
                    break  # только первый результат
                else:
                    i += 1
            return results
        except subprocess.TimeoutExpired:
            self._log(f"[ERROR] npx search timed out (30s) for {func_name}")
            return []
        except Exception as e:
            self._log(f"[ERROR] Exception searching {func_name}: {e}")
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
        function_index: Optional[SfaFunctionIndex] = None,
        reuse_cache: bool = False,
        imports: Optional[list] = None,
        file_name_hint: str = "",
        platform: str = "Windows",
        manpages_db_path: Optional[Path] = None,
    ) -> SfaReportStats:
        """Генерирует HTML-отчёт СФ.

        Отбор функций ведётся по системным библиотекам указанной платформы.
        Источник документации зависит от платформы:

        * Windows — Microsoft Learn (``npx @microsoft/learn-cli``);
        * Linux / Android — локальная БД man-pages (``manpages.db``),
          подготовленная офлайн-импортёром. Сеть при генерации не нужна.

        Args:
            json_path: путь к .export.json (используется для адресации).
            output_html: куда писать .sfa.html.
            reports_dir: корневая папка отчётов (для кэша и лога).
            progress_callback: вызывается после каждой обработанной функции.
            function_index: индекс известных системных функций (опционально).
            reuse_cache: если True — не вызывать npx, только mslearn_cache.db.
            imports: список импортов (если None — читается из json_path).
            file_name_hint: отображаемое имя файла (если imports передан).
            platform: целевая платформа анализа (ключ ``PLATFORM_EXTENSIONS``).
            manpages_db_path: путь к БД man-pages (для Linux/Android). Если не
                задан, ищется ``manpages.db`` рядом с папкой отчётов.

        Returns:
            Статистика отчёта, включая имена недокументированных функций.
        """
        if reports_dir:
            self._init_log(reports_dir)
        self._log(f"[INFO] Processing {json_path}")

        platform = normalize_platform(platform)
        # Источник документации определяется платформой.
        use_manpages = platform == "Linux / Android"

        if use_manpages:
            man_pages = self._open_manpages(reports_dir, manpages_db_path)
            docs_available = bool(man_pages and man_pages.available())
        else:
            self._man_pages = None
            # Документация Microsoft Learn применима только к Windows API.
            docs_available = platform == "Windows"

        if imports is not None:
            # Reuse-режим: импорты переданы из index БД
            file_name = file_name_hint or json_path.stem
            all_imports = imports
        else:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            file_name = data.get("file_name", "")
            all_imports = data.get("imports", [])

        total_imports = len(all_imports)
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
        skipped = 0
        skipped_not_in_index = 0
        for idx, imp in enumerate(all_imports):
            func_name = imp.get("name")
            if not func_name:
                continue
            module = imp.get("module", "") or ""

            # Определяем, является ли модуль псевдо-модулем ELF (.dynsym).
            # Для таких функций библиотека неизвестна — системность
            # определяется по наличию документации в БД man-pages.
            is_pseudo_module = module.strip().lower() in (".dynsym", ".dynsec", "unknown", "")

            # Фильтр 1: только системные библиотеки выбранной платформы.
            #
            # Для ELF IDA иногда не может определить библиотеку и ставит
            # псевдо-модуль (.dynsym, .dynsec, unknown). Такие импорты
            # не отсекаются здесь — мы проверим их по man-pages позже.
            if not is_system_module(module, platform) and not is_pseudo_module:
                self._log(f"[DEBUG] {func_name} ({module}) — не системная библиотека ({platform})")
                skipped += 1
                continue

            # Фильтр 2: проверка по индексу системных функций (если доступен).
            # Для псевдо-модулей индекс не хранит функции.
            if function_index and function_index.available and not is_pseudo_module:
                if not function_index.is_known(func_name):
                    self._log(f"[DEBUG] {func_name} — нет в индексе системных функций")
                    skipped_not_in_index += 1
                    skipped += 1
                    continue

            self._log(f"[DEBUG] Processing import: {func_name}")

            # Сообщаем прогресс (перед обработкой функции)
            if progress_callback:
                progress_callback(func_name, idx, total_imports)

            # Пытаемся взять dll_name из импорта JSON-экспорта IDA.
            # Для ELF-псевдо-модулей (.dynsym) пишем «—», так как
            # библиотека неизвестна.
            dll_name = imp.get("module", "") or "—"
            if dll_name.strip().lower() in (".dynsym", ".dynsec", "unknown"):
                dll_name = "—"

            # Получаем результаты поиска (из кэша, man-pages или Microsoft Learn).
            # Для Linux/Android документация берётся из локальной БД man-pages;
            # для Windows — из Microsoft Learn (внешний вызов npx).
            results = []
            found = False
            if self._doc_cache and self._doc_cache.has_function(func_name):
                results = self._doc_cache.get_results(func_name)
                # Берём dll_name из кэша, если там сохранили
                cached_dll = self._doc_cache.get_dll_name(func_name)
                if cached_dll:
                    dll_name = cached_dll
                found = bool(results)
                self._log(f"[INFO] Using cached results for {func_name} (count: {len(results)})")
            elif use_manpages:
                # man-pages: локальный поиск, без сети.
                if self._man_pages and self._man_pages.available():
                    page = self._man_pages.get_page(func_name)
                    if page:
                        results = [page]
                        found = True
                        self._log(f"[INFO] man-pages: {func_name} → {page['title']}")
                    else:
                        self._log(f"[INFO] man-pages: страница для {func_name} не найдена")
                else:
                    self._log(f"[INFO] {func_name}: БД man-pages недоступна")
            elif reuse_cache:
                # Режим reuse: не вызываем npx, функция остаётся not-found
                self._log(f"[INFO] {func_name} не в кэше (reuse_cache=True) — пропуск")
            elif not docs_available:
                self._log(f"[INFO] {func_name}: поиск документации недоступен для {platform}")
            else:
                results = self._search_function(func_name)
                if results:
                    found = True
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

            # Для псевдо-модулей (.dynsym): если БД не знает функцию,
            # она не является системной — не добавляем в отчёт.
            if is_pseudo_module and not found:
                self._log(f"[INFO] {func_name}: не подтверждена как системная (нет в БД man-pages)")
                skipped += 1
                continue

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
                "found": found,
            })

        self._log(f"[INFO] Generated {len(system_calls)} system calls "
                  f"(skipped {skipped} non-Win32, {skipped_not_in_index} not in index)")

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
            platform=platform,
            docs_available=docs_available,
        )
        output_html.write_text(html, encoding="utf-8")
        self._log(f"[INFO] Report saved to {output_html}")

        # Возвращаем статистику для индексного отчёта
        found_count = sum(1 for sc in system_calls if sc["found"])
        notfound_names = frozenset(
            sc["name"] for sc in system_calls if not sc["found"]
        )
        return SfaReportStats(
            found_count=found_count,
            notfound_count=len(system_calls) - found_count,
            total_count=len(system_calls),
            notfound_names=notfound_names,
        )

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
            platform="Windows",
            docs_available=True,
        )
        output_html.write_text(html, encoding="utf-8")
        self._log(f"[INFO] Error report saved to {output_html}")

    def generate_index(self, reports_dir: Path, input_dir: Path, reports: list,
                       ida_info: dict = None,
                       total_files: int = 0, total_size_bytes: int = 0,
                       total_system_modules: int = 0,
                       total_system_functions: int = 0,
                       total_system_notfound: int = 0,
                       generation_time: str = "",
                       platform: str = "Windows") -> Path:
        if not generation_time:
            generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Размер считаем только по исполняемым модулям. Приоритет — значение,
        # накопленное воркером по реально проанализированным файлам (оно точнее
        # всего соответствует числу файлов в отчёте). Пересчёт по директории
        # используется лишь как запасной вариант.
        if total_size_bytes <= 0:
            total_size_bytes = compute_executables_size(input_dir)
        data = {
            "input_dir": str(input_dir),
            "platform": normalize_platform(platform),
            "total_files": total_files,
            "total_size_bytes": total_size_bytes,
            "total_system_modules": total_system_modules,
            "total_system_functions": total_system_functions,
            "total_system_notfound": total_system_notfound,
            "reports": reports,
            "generation_time": generation_time,
        }
        html = self.index_template.render(data)
        index_path = reports_dir / "index.html"
        index_path.write_text(html, encoding="utf-8")
        self.close_log()
        return index_path