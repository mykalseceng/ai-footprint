from ai_footprint import reportcheck


def page(body: str, page_id: str = "p") -> str:
    return f'<section class="view" id="{page_id}">{body}</section>'


def test_long_cells_blank_descriptions_and_long_tables_fail():
    long_cell = "x" * (reportcheck.MAX_CELL + 1)
    body = (
        "<table><thead><tr><th>Name</th><th>Says it does</th></tr></thead><tbody>"
        f"<tr><td>a</td><td>{long_cell}</td></tr><tr><td>b</td><td></td></tr></tbody></table>"
    )
    [validation] = reportcheck.check_report(page(body))
    failed = [c.name for c in validation.checks if not c.passed]
    assert failed == [
        f"table cells at most {reportcheck.MAX_CELL} characters",
        f"no cell token longer than {reportcheck.MAX_RUN} characters without a break point",
        "no blank cell in a descriptive column",
    ]
    rows = "".join(f"<tr><td>{i}</td></tr>" for i in range(reportcheck.MAX_ROWS + 1))
    [validation] = reportcheck.check_report(page(f"<table><tbody>{rows}</tbody></table>"))
    assert [c.name for c in validation.checks if not c.passed] == [
        f"tables at most {reportcheck.MAX_ROWS} rows"
    ]


def test_markup_is_stripped_before_measuring():
    cell = "<code>" + "a" * 40 + "<wbr>" + "b" * 40 + "</code>"
    body = f"<table><tr><td>{cell}</td></tr></table>"
    [validation] = reportcheck.check_report(page(body, "q"))
    assert validation.ok and validation.command == "page q"


def test_tokens_without_a_break_point_fail_but_hyphens_and_wbr_count_as_breaks():
    hash_cell = "a" * (reportcheck.MAX_RUN + 1)
    [bad] = reportcheck.check_report(page(f"<table><tr><td>{hash_cell}</td></tr></table>"))
    assert [c.name for c in bad.checks if not c.passed] == [
        f"no cell token longer than {reportcheck.MAX_RUN} characters without a break point"
    ]
    broken = "<wbr>".join(["b" * 30] * 3) + " " + "-".join(["c" * 30] * 3)
    [ok] = reportcheck.check_report(page(f"<table><tr><td>{broken}</td></tr></table>"))
    assert ok.ok


def test_answers_must_be_one_sentence_then_a_table_of_single_facts_and_no_raw_iso():
    faq = (
        '<dl class="faq"><dt>Q</dt><dd><p>One sentence. Two sentences.</p>'
        "<ul><li>a bullet</li></ul><table><tr><td>Fact one. Fact two.</td><td>"
        + "x" * (reportcheck.MAX_BULLET + 1)
        + "</td></tr></table></dd></dl><p>seen 2026-10-08T21:04:47+00:00</p>"
    )
    [validation] = reportcheck.check_report(page(faq))
    failed = {c.name: c.detail for c in validation.checks if not c.passed}
    assert failed == {
        f"no cell token longer than {reportcheck.MAX_RUN} characters without a break point": (
            "longest 181: " + "x" * 40 + "…"
        ),
        "answers: at most one sentence of text": "1 longer",
        "answers: tables, not bullet lists": "1 bullets",
        f"answer cells: one fact of at most {reportcheck.MAX_BULLET} characters": (
            "2 longer: Fact one. Fact two.…"
        ),
        "dates read YYYY-MM-DD HH:MM UTC, never raw ISO": "1 raw",
    }
    good = (
        '<dl class="faq"><dt>Q</dt><dd><p>One sentence.</p>'
        "<table><tr><td>Fact.</td></tr></table></dd></dl>"
    )
    assert reportcheck.check_report(page(good))[0].ok
