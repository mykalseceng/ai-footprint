"""Layout and consistency checks on the rendered HTML, so an unreadable page fails ``--validate``.

Every page's tables are checked: no cell longer than ``MAX_CELL`` visible characters, no
table longer than ``MAX_ROWS`` rows, no token longer than ``MAX_RUN`` without a break point,
and no blank cell in a descriptive column. Every "Your questions" answer must have the same
shape: at most one sentence of text, then a table whose cells hold one fact. Dates must
read ``YYYY-MM-DD HH:MM UTC``, never raw ISO. The checks read the finished HTML, so they
catch any renderer or collector that produces a wall of text.
"""

import html
import re

from ai_footprint.model import CheckResult, CommandValidation

MAX_CELL = 260
MAX_ROWS = 80
MAX_RUN = 48
MAX_BULLET = 180
_FAQ = re.compile(r'<dl class="faq">(.*?)</dl>', re.S)
_ANSWER = re.compile(r"<dd>(.*?)</dd>", re.S)
_PARA = re.compile(r"<p>(.*?)</p>", re.S)
_ITEM = re.compile(r"<li>(.*?)</li>", re.S)
_BOUNDARY = re.compile(r"[.!?] [A-Z`~/]")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
DESCRIPTIVE = frozenset({"Says it does", "Tools it declares", "Contains"})
_SECTION = re.compile(r'<section class="view" id="([^"]+)">(.*?)</section>', re.S)
_TABLE = re.compile(r"<table>(.*?)</table>", re.S)
_HEAD = re.compile(r"<th>(.*?)</th>", re.S)
_ROW = re.compile(r"<tr>(.*?)</tr>", re.S)
_CELL = re.compile(r"<td>(.*?)</td>", re.S)
_TAG = re.compile(r"<[^>]+>")


def _text(fragment: str) -> str:
    return html.unescape(_TAG.sub("", fragment)).strip()


def check_page(page_id: str, body: str) -> CommandValidation:
    """Checks for one page: cell length, table length and blank descriptive cells."""
    validation = CommandValidation(command=f"page {page_id}")
    longest, longest_cell, rows_max, blanks = 0, "", 0, 0
    run, run_text = 0, ""
    for table in _TABLE.findall(body):
        headers = [_text(h) for h in _HEAD.findall(table)]
        rows = [r for r in _ROW.findall(table) if "<td" in r]
        rows_max = max(rows_max, len(rows))
        for row in rows:
            for index, cell in enumerate(_CELL.findall(row)):
                text = _text(cell)
                if len(text) > longest:
                    longest, longest_cell = len(text), text[:60]
                for token in _text(cell.replace("<wbr>", " ")).replace("-", " ").split():
                    if len(token) > run:
                        run, run_text = len(token), token[:40]
                if index < len(headers) and headers[index] in DESCRIPTIVE and not text:
                    blanks += 1
    validation.checks.append(
        CheckResult(
            f"table cells at most {MAX_CELL} characters",
            longest <= MAX_CELL,
            f"longest {longest}" + (f": {longest_cell}…" if longest > MAX_CELL else ""),
        )
    )
    validation.checks.append(
        CheckResult(f"tables at most {MAX_ROWS} rows", rows_max <= MAX_ROWS, f"longest {rows_max}")
    )
    validation.checks.append(
        CheckResult(
            f"no cell token longer than {MAX_RUN} characters without a break point",
            run <= MAX_RUN,
            f"longest {run}" + (f": {run_text}…" if run > MAX_RUN else ""),
        )
    )
    validation.checks.append(
        CheckResult("no blank cell in a descriptive column", blanks == 0, f"{blanks} blank")
    )
    validation.checks.extend(_answer_checks(body))
    iso = len(_ISO.findall(_text(body)))
    validation.checks.append(
        CheckResult("dates read YYYY-MM-DD HH:MM UTC, never raw ISO", iso == 0, f"{iso} raw")
    )
    return validation


def _answer_checks(body: str) -> list[CheckResult]:
    """Every answer: one sentence of text at most, then a table whose cells hold one fact."""
    long_text, bullets, long_cell, sample = 0, 0, 0, ""
    for dl in _FAQ.findall(body):
        for answer in _ANSWER.findall(dl):
            for para in _PARA.findall(answer):
                if _BOUNDARY.search(_text(para)):
                    long_text += 1
            bullets += len(_ITEM.findall(answer))
            for cell in _CELL.findall(answer):
                text = _text(cell)
                if len(text) > MAX_BULLET or _BOUNDARY.search(text):
                    long_cell += 1
                    sample = sample or text[:60]
    return [
        CheckResult("answers: at most one sentence of text", long_text == 0, f"{long_text} longer"),
        CheckResult("answers: tables, not bullet lists", bullets == 0, f"{bullets} bullets"),
        CheckResult(
            f"answer cells: one fact of at most {MAX_BULLET} characters",
            long_cell == 0,
            f"{long_cell} longer" + (f": {sample}…" if long_cell else ""),
        ),
    ]


def check_report(page: str) -> list[CommandValidation]:
    """One validation per page of the rendered report."""
    return [check_page(page_id, body) for page_id, body in _SECTION.findall(page)]
