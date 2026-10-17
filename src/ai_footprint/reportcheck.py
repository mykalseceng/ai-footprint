"""Consistency checks on both outputs, so an unreadable page fails ``--validate``.

The static report (``report_html``) is checked from its finished HTML: no cell longer than
``MAX_CELL`` visible characters, no table longer than ``MAX_ROWS`` rows, no token longer
than ``MAX_RUN`` without a break point, and no blank cell in a descriptive column. The
dashboard is checked from the run's document (``document.build``), the data it renders.

On both, every "Your questions" answer must have the same shape: at most one sentence of
text, then a table whose cells each hold one fact of at most ``MAX_BULLET`` characters.
Dates must read ``YYYY-MM-DD HH:MM UTC``, never raw ISO, and every skill, MCP server and
plugin row must say what it does, even if only with a placeholder.

The wording check reads every sentence this tool writes (figures, statements, answers,
summaries, check titles, the dashboard's own labels) for words that rate or overclaim:
the audit reports signals to review, so "finding", "exposed", "critical", "vulnerable" and
the like never appear in its own text. Collected text (manifest descriptions, quoted names
and paths) is data, not a claim, and is skipped.
"""

import html
import re
from collections.abc import Iterator
from typing import Any

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
EXTENSION_PAGES = {"mcp": {"mcp", "connector"}, "skills": {"skill"}, "plugins": {"plugin"}}
OVERCLAIM = re.compile(
    r"\b(findings?|exposed|vulnerab\w*|critical|severity|high[- ]risk|risk scores?|"
    r"compromised|insecure|breach(?:ed)?)\b",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"`[^`]*`|'[^']*'|\"[^\"]*\"")
_JS_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`')


# --- the static report --------------------------------------------------------------------------


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


# --- the dashboard's document ----------------------------------------------------------------


def _strings(value: object) -> Iterator[str]:
    """Every string inside nested dicts and lists."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _date_check(written: object) -> CheckResult:
    raw = sum(len(_ISO.findall(text)) for text in _strings(written))
    return CheckResult("dates read YYYY-MM-DD HH:MM UTC, never raw ISO", raw == 0, f"{raw} raw")


def _answer_data_checks(answers: list[dict[str, Any]]) -> list[CheckResult]:
    """Every answer: one sentence of text at most, then cells that hold one fact each."""
    long_text = sum(1 for answer in answers if _BOUNDARY.search(answer["text"]))
    long_cell, sample = 0, ""
    for answer in answers:
        for row in answer["rows"]:
            for cell in row:
                if len(cell) > MAX_BULLET or _BOUNDARY.search(cell):
                    long_cell += 1
                    sample = sample or cell[:60]
    return [
        CheckResult("answers: at most one sentence of text", long_text == 0, f"{long_text} longer"),
        CheckResult(
            f"answer cells: one fact of at most {MAX_BULLET} characters",
            long_cell == 0,
            f"{long_cell} longer" + (f": {sample}…" if long_cell else ""),
        ),
    ]


def _description_check(rows: list[dict[str, Any]]) -> CheckResult:
    blank = [row["name"] for row in rows if not row["description"].strip()]
    if any(row["kind"] == "plugin" for row in rows):
        blank += [row["name"] for row in rows if not row["access"].strip()]
    return CheckResult(
        "every row says what it does",
        not blank,
        f"{len(blank)} blank" + (f": {', '.join(blank[:3])}" if blank else ""),
    )


def check_document(document: dict[str, Any]) -> list[CommandValidation]:
    """One validation per dashboard page whose text is written from the audit."""
    views = document["views"]
    pages = [
        CommandValidation("page summary", [_date_check(views["machine"])]),
        *(
            CommandValidation(
                f"page tool-{name}", [_date_check(tool), *_answer_data_checks(tool["answers"])]
            )
            for name, tool in views["tools"].items()
        ),
    ]
    for page, kinds in EXTENSION_PAGES.items():
        rows = [row for row in views["extensions"] if row["kind"] in kinds]
        pages.append(
            CommandValidation(
                f"page {page}", [_date_check(views["pages"][page]), _description_check(rows)]
            )
        )
    pages.append(CommandValidation("page host", [_date_check(views["host"])]))
    return pages


# --- wording: signals, not findings ---------------------------------------------------------


def _written(document: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(where, text) for every sentence this tool writes, never collected data."""
    views = document["views"]
    yield from (("figures", t) for t in _strings(views["figures"]))
    yield from (("lenses", t) for t in _strings(views["lenses"]))
    yield from (("summary", t) for t in _strings(views["machine"]))
    yield from (("pages", t) for t in _strings(views["pages"]))
    yield ("method", views["method"])
    yield ("host", views["host"]["scope"])
    for question in views["host"]["questions"]:
        yield ("host", question["question"])
        yield ("host", question["answer"])
    for name, tool in views["tools"].items():
        yield from ((f"tool-{name}", t) for t in _strings([tool["headline"], tool["lenses"]]))
        for answer in tool["answers"]:
            yield from ((f"tool-{name}", t) for t in [answer["question"], answer["text"]])
            yield from ((f"tool-{name}", t) for t in answer["headers"])
    for labels in views["fix_labels"].values():
        yield from (("fixes", label["label"]) for label in labels)
    for check in document["checklist"]:
        yield ("checklist", check["check"])
        yield ("checklist", check["unchecked"])
    exposures = [x for t in document["tools"] for x in t["exposures"]]
    for exposure in exposures + document["host_exposures"]:
        yield (exposure["id"], exposure["label"])
        yield (exposure["id"], exposure["statement"])
        if exposure["fix"]:
            yield (exposure["id"], exposure["fix"]["summary"])


def _overclaims(where: str, text: str) -> list[str]:
    return [f"{where}: {m.group(0)!r}" for m in OVERCLAIM.finditer(_QUOTED.sub("", text))]


def check_wording(document: dict[str, Any], script: str) -> CommandValidation:
    """No word that rates or overclaims, in the document's sentences or the dashboard's labels."""
    written = [hit for where, text in _written(document) for hit in _overclaims(where, text)]
    labels = [
        hit
        for literal in _JS_STRING.findall(script)
        for hit in _overclaims("dashboard", literal[1:-1])
    ]
    return CommandValidation(
        "wording: signals to review, never rated",
        [
            CheckResult(
                "no rating or overclaiming word in the sentences this tool writes",
                not written,
                f"{len(written)} found" + (f": {'; '.join(written[:3])}" if written else ""),
            ),
            CheckResult(
                "no rating or overclaiming word in the dashboard's labels",
                not labels,
                f"{len(labels)} found" + (f": {'; '.join(labels[:3])}" if labels else ""),
            ),
        ],
    )
