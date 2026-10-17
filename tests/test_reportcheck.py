from ai_footprint import reportcheck


def answer(text: str = "", rows: list[list[str]] | None = None) -> dict:
    return {"question": "Q", "text": text, "headers": ["A"], "rows": rows or [], "links": []}


def extension(name: str, kind: str, description: str = "does a thing", access: str = "x") -> dict:
    return {"name": name, "kind": kind, "description": description, "access": access}


def document(answers: list[dict], extensions: list[dict] | None = None, headline: str = "") -> dict:
    return {
        "views": {
            "machine": {"headline": [headline], "lenses": []},
            "tools": {"claude": {"headline": [], "lenses": [], "answers": answers}},
            "extensions": extensions or [],
            "pages": {"mcp": "", "skills": "", "plugins": ""},
            "host": {"scope": "", "questions": []},
        }
    }


def failed(doc: dict) -> dict[str, dict[str, str]]:
    return {
        v.command: {c.name: c.detail for c in v.checks if not c.passed}
        for v in reportcheck.check_document(doc)
        if not v.ok
    }


def test_answers_must_be_one_sentence_then_cells_of_one_fact():
    long_cell = "x" * (reportcheck.MAX_BULLET + 1)
    doc = document([answer("One sentence. Two sentences.", [["Fact one. Fact two."], [long_cell]])])
    assert failed(doc) == {
        "page tool-claude": {
            "answers: at most one sentence of text": "1 longer",
            f"answer cells: one fact of at most {reportcheck.MAX_BULLET} characters": (
                "2 longer: Fact one. Fact two.…"
            ),
        }
    }


def test_raw_iso_dates_fail_on_the_page_that_shows_them():
    doc = document([answer("Seen 2026-10-08T21:04:47+00:00.")], headline="At 2026-10-08T21:04.")
    result = failed(doc)
    assert result["page summary"] == {"dates read YYYY-MM-DD HH:MM UTC, never raw ISO": "1 raw"}
    assert result["page tool-claude"] == {"dates read YYYY-MM-DD HH:MM UTC, never raw ISO": "1 raw"}


def test_extension_rows_must_say_what_they_do():
    rows = [
        extension("blank-skill", "skill", description=" "),
        extension("empty-plugin", "plugin", access=""),
        extension("fine", "mcp"),
    ]
    result = failed(document([], rows))
    assert result == {
        "page skills": {"every row says what it does": "1 blank: blank-skill"},
        "page plugins": {"every row says what it does": "1 blank: empty-plugin"},
    }


def test_consistent_document_passes_every_page():
    doc = document([answer("One sentence.", [["Fact."]])], [extension("s", "skill")])
    validations = reportcheck.check_document(doc)
    assert [v.command for v in validations] == [
        "page summary",
        "page tool-claude",
        "page mcp",
        "page skills",
        "page plugins",
        "page host",
    ]
    assert all(v.ok for v in validations)


def wording(doc: dict, script: str = 'const label = "Signals";') -> dict[str, str]:
    full = {
        **doc,
        "checklist": [],
        "tools": [],
        "host_exposures": [],
    }
    full["views"] = {
        **doc["views"],
        "figures": {"machine": [], "tools": {}},
        "lenses": [],
        "method": "The audit is read-only.",
        "fix_labels": {},
        "host": {"scope": "", "questions": []},
    }
    validation = reportcheck.check_wording(full, script)
    return {c.name: c.detail for c in validation.checks if not c.passed}


def test_wording_rejects_rating_words_in_written_sentences_but_not_in_quoted_data():
    clean = document([answer("Two signals to review.")])
    assert wording(clean) == {}
    rated = document([answer("One critical finding.")])
    assert wording(rated) == {
        "no rating or overclaiming word in the sentences this tool writes": (
            "2 found: tool-claude: 'critical'; tool-claude: 'finding'"
        )
    }
    quoted = document([answer("Skill `vulnerability-scanner` is loaded.")])
    assert wording(quoted) == {}


def test_wording_rejects_rating_words_in_dashboard_labels():
    doc = document([])
    assert wording(doc, 'pageHead("Findings", sub); pill("exposed");') == {
        "no rating or overclaiming word in the dashboard's labels": (
            "2 found: dashboard: 'Findings'; dashboard: 'exposed'"
        )
    }
