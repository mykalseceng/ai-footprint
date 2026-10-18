"""The keys inventory lists what is stored, where, and an owner only when the data records one."""

import copy
import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint import document, figurecheck, keys, tokens
from ai_footprint.audit import run_audit
from ai_footprint.model import AuditReport, CommandValidation
from ai_footprint.tokens import inspect_token
from tests.conftest import (
    FAKE_DEEPSEEK,
    FakeSystem,
    build_claude_home,
    build_codex_home,
    build_opencode_home,
    build_pi_home,
    make_jwt,
)


class QuietFakeSystem(FakeSystem):
    def validate_probes(self) -> list[CommandValidation]:
        return []


@pytest.fixture(scope="module")
def audited() -> Iterator[tuple[AuditReport, dict]]:
    home = Path(tempfile.mkdtemp(prefix="aifp-keys-", dir="/tmp"))
    home.chmod(0o755)
    build_claude_home(home)
    build_codex_home(home)
    build_opencode_home(home)
    build_pi_home(home)
    audit, checklist = run_audit(system=QuietFakeSystem(), home=home, scan=False)
    yield audit, json.loads(json.dumps(document.build(audit, checklist)))
    shutil.rmtree(home)


def test_last_four_characters_are_kept_only_for_long_non_jwt_values():
    assert inspect_token("key", FAKE_DEEPSEEK, now=0).last4 == FAKE_DEEPSEEK[-4:]
    assert inspect_token("key", "ollama", now=0).last4 == ""
    jwt = make_jwt({"sub": "x", "exp": 9_999_999_999})
    assert inspect_token("access", jwt, now=0).last4 == ""


def test_the_same_key_in_several_tools_and_stores_is_one_row(audited):
    audit, _doc = audited
    [deepseek] = [r for r in keys.rows(audit) if r.provider == "DeepSeek"]
    assert deepseek.kind == tokens.API_KEY
    assert deepseek.shown == FAKE_DEEPSEEK[:6] + "…" + FAKE_DEEPSEEK[-4:]
    assert deepseek.used_by == ["OpenCode", "pi"]
    assert {(loc.tool, loc.store) for loc in deepseek.locations} == {
        ("OpenCode", "plaintext file"),
        ("OpenCode", "SQLite table credential"),
        ("pi", "plaintext file"),
    }


def test_owner_comes_only_from_recorded_data(audited):
    audit, _doc = audited
    rows = keys.rows(audit)
    [anthropic] = [r for r in rows if r.provider == "Anthropic"]
    assert (anthropic.owner, anthropic.owner_source) == (
        "user@example.com",
        "~/.claude.json oauthAccount.emailAddress",
    )
    for row in rows:
        if row.kind == tokens.API_KEY:
            assert (row.owner, row.owner_source) == ("", "")


def test_no_key_value_reaches_the_document(audited):
    _audit, doc = audited
    assert FAKE_DEEPSEEK not in json.dumps(doc)


# --- the key validator --------------------------------------------------------------------


def failures(doc: dict) -> list[str]:
    return [
        f"{v.command}: {c.name}: {c.detail}"
        for v in figurecheck.check_figures(doc)
        for c in v.checks
        if not c.passed
    ]


def tampered(doc: dict, change) -> dict:
    copied = copy.deepcopy(doc)
    change(copied)
    return copied


def deepseek(doc: dict) -> dict:
    return next(r for r in doc["views"]["keys"] if r["provider"] == "DeepSeek")


def test_validator_accepts_the_real_rows(audited):
    _audit, doc = audited
    assert failures(doc) == []


@pytest.mark.parametrize(
    "change",
    [
        lambda d: deepseek(d).update(owner="someone@example.com", owner_source="a guess"),
        lambda d: deepseek(d)["locations"].pop(),
        lambda d: deepseek(d).update(shown="sk-fff…0000"),
        lambda d: deepseek(d).update(kind="OAuth login"),
        lambda d: d["views"]["keys"].remove(deepseek(d)),
        lambda d: next(f for f in d["views"]["figures"]["machine"] if f["id"] == "api_keys").update(
            value=99, display="99"
        ),
    ],
    ids=["invented owner", "dropped location", "altered key", "wrong type", "missing row", "count"],
)
def test_validator_catches_a_tampered_key_row(audited, change):
    _audit, doc = audited
    assert failures(tampered(doc, change))
