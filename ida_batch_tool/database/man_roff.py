"""Разбор roff-исходников man-pages в Markdown.

Модуль читает страницы руководства Linux (man-pages) и преобразует их
в Markdown, пригодный для вставки в HTML-отчёты анализа СФ. Поддерживается
подмножество макросов, реально используемых в man-pages (статистика по
версии 6.9: ``.BR``, ``.I``, ``.B``, ``.TP``, ``.IP``, ``.nf``/``.fi``,
``.EX``/``.EE``, ``.RS``/``.RE``, ``.TS``/``.TE`` и другие).

Страницы-алиасы (``fprintf.3`` содержащая ``.so man3/printf.3``)
разворачиваются в целевую страницу, поэтому функция находится по своему
имени даже когда её описание лежит в семейной странице.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

# Секции, которые попадают в итоговую документацию, в порядке вывода.
DEFAULT_SECTIONS: tuple[str, ...] = (
    "NAME",
    "LIBRARY",
    "SYNOPSIS",
    "DESCRIPTION",
    "RETURN VALUE",
    "ERRORS",
    "ATTRIBUTES",
    "VERSIONS",
    "STANDARDS",
    "HISTORY",
    "NOTES",
    "CAVEATS",
    "BUGS",
    "EXAMPLES",
    "SEE ALSO",
)

# Макросы, начинающие новую строку абзаца.
_PARAGRAPH_MACROS = {"P", "PP", "LP", "sp", "br"}
# Макросы с отступом/структурой списка.
_INDENT_OPEN = {"RS"}
_INDENT_CLOSE = {"RE"}
_TP = {"TP", "TQ", "IP", "HP"}
_CODE_OPEN = {"nf", "EX"}
_CODE_CLOSE = {"fi", "EE"}
_TABLE_OPEN = {"TS"}
_TABLE_CLOSE = {"TE"}


@dataclass
class ManPage:
    """Разобранная страница руководства."""

    name: str
    section: str
    title: str = ""
    library: str = ""
    aliases: tuple[str, ...] = ()
    summary: str = ""
    markdown: str = ""


def _unescape_roff(text: str) -> str:
    """Преобразует типовые roff-escape-последовательности в обычный текст."""
    # \fB..\fP, \fI..\fR и т.п. — переключение шрифта, отбрасываем.
    text = re.sub(r"\\f[BPIR0-9]", "", text)
    # Экранированные пробелы и дефисы.
    text = text.replace("\\ ", " ").replace("\\-", "-")
    text = text.replace("\\&", "").replace("\\%", "")
    text = text.replace("\\e", "\\")
    # \(aq -> ' , \(dq -> " , \(co -> ©, \(em/\(en — тире
    text = text.replace("\\(aq", "'").replace("\\(dq", '"')
    text = text.replace("\\(co", "©").replace("\\(em", "—").replace("\\(en", "–")
    text = text.replace("\\[u2019]", "'").replace("\\[u201C]", '"')
    text = text.replace("\\[u201D]", '"').replace("\\[u2014]", "—")
    # Неразрывный пробел.
    text = text.replace("\\~", " ")
    # Оставшиеся экранирования одного символа.
    text = re.sub(r"\\([^\s])", r"\1", text)
    return text


def _render_inline(text: str) -> str:
    """Форматирует inline-текст: экранирование, ссылки, моноширинный шрифт."""
    text = _unescape_roff(text)
    # Ссылки вида foo(3) -> [foo(3)](#foo) не делаем: в отчёте нет якорей.
    text = html.escape(text, quote=False)
    # Жирный/моноширинный акценты оставляем обычным текстом.
    return text.strip()


class RoffParser:
    """Преобразует одну man-страницу (roff) в Markdown."""

    def __init__(self) -> None:
        self._section_map: dict[str, list[str]] = {}
        self._order: list[str] = []

    def parse(self, source: str, name: str, section: str) -> ManPage:
        """Разбирает roff-исходник и возвращает разобранную страницу."""
        self._section_map = {}
        self._order = []

        lines = source.splitlines()
        current: Optional[str] = None
        buf: list[str] = []

        def flush() -> None:
            nonlocal buf
            if current is not None and buf:
                self._section_map.setdefault(current, []).append(
                    "\n".join(buf).strip("\n")
                )
            buf = []

        def start(new_section: str) -> None:
            nonlocal current
            flush()
            key = self._norm_section(new_section)
            if key:
                if key not in self._section_map:
                    self._order.append(key)
                current = key
            else:
                current = None

        in_code = False
        index = 0
        while index < len(lines):
            raw = lines[index]

            # Продолжение по экранированию "\" в конце строки.
            while raw.endswith("\\") and not raw.endswith("\\\\") and index + 1 < len(lines):
                index += 1
                raw = raw[:-1] + lines[index]

            stripped = raw.strip()

            if stripped.startswith('."') or stripped.startswith(".\\\""):
                index += 1
                continue

            m = re.match(r"^\.([A-Za-z][A-Za-z0-9]*)\s*(.*)$", stripped)
            if not m:
                # Обычная текстовая строка.
                if not stripped:
                    if in_code:
                        buf.append("")
                    else:
                        buf.append("")
                else:
                    buf.append(_render_inline(stripped))
                index += 1
                continue

            macro = m.group(1)
            args = m.group(2)

            if macro in ("SH", "SS"):
                start(self._strip_quotes(args))
                index += 1
                continue

            if macro == "TH":
                index += 1
                continue

            if macro in _CODE_OPEN:
                in_code = True
                buf.append("```")
                index += 1
                continue

            if macro in _CODE_CLOSE:
                in_code = False
                buf.append("```")
                index += 1
                continue

            if macro in _TABLE_OPEN:
                in_code = True
                buf.append("```")
                index += 1
                continue

            if macro in _TABLE_CLOSE:
                in_code = False
                buf.append("```")
                index += 1
                continue

            if macro in _INDENT_OPEN or macro in _INDENT_CLOSE:
                index += 1
                continue

            if macro in _PARAGRAPH_MACROS:
                buf.append("")
                index += 1
                continue

            if macro in _TP:
                # .TP [indent]: следующая строка — термин, далее описание.
                term = args.strip()
                if term:
                    buf.append(f"\n**{_render_inline(term)}**")
                index += 1
                # Пропускаем необязательную строку отступа-числа.
                if index < len(lines) and re.match(r"^\.\d+$", lines[index].strip()):
                    index += 1
                continue

            if macro == "UR":
                # .UR url ... .UE — оставляем только текст ссылки.
                index += 1
                continue
            if macro == "UE":
                index += 1
                continue

            if macro in ("nf", "fi", "EX", "EE"):
                index += 1
                continue

            if macro == "so":
                # Страницу-алиас разворачивает вызывающий код (см. importer).
                index += 1
                continue

            if macro in ("br", "ce", "ad", "na", "nh", "PD", "ft", "in", "sp"):
                buf.append("")
                index += 1
                continue

            if macro in ("if", "ie", "el", "de", "ds", "rm", "nr", "tr"):
                index += 1
                continue

            # Шрифтовые макросы: .B text, .BI a b, .BR a b, .I, .IR, .RB, .RI
            text = self._format_font_macro(macro, args)
            if text is not None:
                buf.append(text)
            index += 1

        flush()

        name_line = self._first_line("NAME")
        library_line = self._first_line("LIBRARY")
        aliases = self._parse_aliases(name_line)
        summary = self._parse_summary(name_line)

        markdown = self._render_markdown()

        return ManPage(
            name=name,
            section=section,
            title=self._strip_page_suffix(name_line),
            library=library_line,
            aliases=aliases,
            summary=summary,
            markdown=markdown,
        )

    # ─── вспомогательные ────────────────────────────────────────────

    @staticmethod
    def _strip_quotes(text: str) -> str:
        text = text.strip()
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            return text[1:-1]
        return text

    @staticmethod
    def _norm_section(title: str) -> str:
        """Нормализует заголовок секции (``RETURN VALUE`` и т.п.)."""
        title = _unescape_roff(title)
        title = re.sub(r"\s+", " ", title).strip()
        return title.upper()

    def _format_font_macro(self, macro: str, args: str) -> Optional[str]:
        """Форматирует шрифтовые макросы (``.B``, ``.BI``, ``.BR`` и др.)."""
        raw = args.strip()
        if not raw:
            return None
        if macro in ("B", "I", "SM", "SB"):
            return _render_inline(raw)

        # Макросы с чередованием шрифтов: собираем части с учётом кавычек.
        parts = re.findall(r'"(?:[^"\\]|\\.)*"|\S+', raw)
        chunks: list[str] = []
        bold = macro.startswith("B")
        for part in parts:
            part = self._strip_quotes(part)
            if not part:
                continue
            chunks.append(part)
            bold = not bold
        joined = " ".join(chunks).replace(" ,", ",").replace(" .", ".")
        return _render_inline(joined)

    def _first_line(self, section: str) -> str:
        blocks = self._section_map.get(section)
        if not blocks:
            return ""
        text = "\n".join(blocks)
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return " ".join(lines)

    @staticmethod
    def _parse_aliases(name_line: str) -> tuple[str, ...]:
        """Извлекает имена функций из строки NAME: ``printf, fprintf - ...``."""
        if not name_line:
            return ()
        head = re.split(r"\s+-\s+", name_line, maxsplit=1)[0]
        names = [n.strip() for n in head.split(",") if n.strip()]
        return tuple(names)

    @staticmethod
    def _parse_summary(name_line: str) -> str:
        """Извлекает краткое описание из строки NAME (часть после дефиса)."""
        parts = re.split(r"\s+-\s+", name_line, maxsplit=1)
        return parts[1].strip() if len(parts) == 2 else ""

    @staticmethod
    def _strip_page_suffix(name_line: str) -> str:
        head = re.split(r"\s+-\s+", name_line, maxsplit=1)[0].strip()
        return head

    def _render_markdown(self) -> str:
        """Собирает Markdown-документ из разобранных секций."""
        out: list[str] = []
        for section in DEFAULT_SECTIONS:
            body = self._section_map.get(section)
            if not body:
                continue
            text = self._clean_block("\n".join(body))
            if not text:
                continue
            title = section.title() if section != "SEE ALSO" else "See also"
            out.append(f"### {title}\n\n{text}")
        return "\n\n".join(out).strip()

    @staticmethod
    def _clean_block(text: str) -> str:
        """Убирает лишние пустые строки и висячие пробелы."""
        text = re.sub(r"[ \t]+\n", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        # Пустые строки между строками внутри код-блока схлопываем.
        text = re.sub(r"```\n\n+", "```\n", text)
        return text.strip()


def parse_man_page(source: str, name: str, section: str) -> ManPage:
    """Удобная обёртка: разбирает одну страницу."""
    return RoffParser().parse(source, name, section)


_ALIAS_RE = re.compile(r"^\.so\s+(\S+)\s*$", re.M)


def find_alias_target(source: str) -> Optional[str]:
    """Если страница является алиасом (``.so man3/printf.3``), вернуть цель."""
    if len(source) > 512:
        # Страница-алиас — это буквально одна строка ``.so ...``.
        m = _ALIAS_RE.search(source)
        return m.group(1) if m else None
    m = _ALIAS_RE.match(source.strip())
    return m.group(1) if m else None
