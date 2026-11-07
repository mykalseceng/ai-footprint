"""Golden snapshot of every output for the fixture homes.

The run's document, the static report and the doctor text are compared, after
normalising paths and times, with files under ``tests/golden``. A change to any output
fails this test; when the change is intended, regenerate with ``AIFP_UPDATE_GOLDEN=1``.
"""

import json
import os
import re
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from ai_footprint.audit import run_audit
from ai_footprint.model import CommandValidation
from ai_footprint.reporting import document, report_html
from ai_footprint.reporting.report_text import Style, render_doctor
from tests.conftest import (
    FakeSystem,
    build_claude_home,
    build_codex_home,
    build_opencode_home,
    build_pi_home,
)

GOLDEN = Path(__file__).parent / "golden"
FIXED_HOME = Path("/tmp/aifp-golden")  # a fixed path keeps wrapped paths stable
UPDATE = os.environ.get("AIFP_UPDATE_GOLDEN") == "1"
VOLATILE = (
    (re.compile(r"\b1[7-9]\d{8}(\d{3})?\b"), "<EPOCH>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(\+00:00|Z| UTC)?"), "<TIME>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "<DATE>"),
    (re.compile(r"\b\d+(\.\d+)? ?(ms|seconds?|s)\b"), "<DURATION>"),
    (re.compile(r"\bin \d+ (days?|hours?|minutes?)\b"), "in <SPAN>"),
    (re.compile(r"\b\d+ (days?|hours?|minutes?) ago\b"), "<SPAN> ago"),
    (re.compile(r"\b(expired|expires) \d+ (days?|hours?|minutes?)\b"), r"\1 <SPAN>"),
    (re.compile(r"[0-9a-f]{12,64}"), "<HEX>"),
    (re.compile(r"sha256-[A-Za-z0-9+/=]+"), "sha256-<HASH>"),
)


class QuietFakeSystem(FakeSystem):
    def validate_probes(self) -> list[CommandValidation]:
        return []


@pytest.fixture
def home() -> Iterator[Path]:
    path = FIXED_HOME
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(mode=0o755)
    path.chmod(0o755)
    yield path
    shutil.rmtree(path)


def normalise(text: str, home: Path) -> str:
    text = text.replace(str(home.resolve()), "<HOME>").replace(str(home), "<HOME>")
    for pattern, replacement in VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def outputs(home: Path) -> dict[str, str]:
    build_claude_home(home)
    build_codex_home(home)
    build_opencode_home(home)
    build_pi_home(home)
    system = QuietFakeSystem(other_users=("guest",))
    audit, checklist = run_audit(system=system, home=home, scan=True, workers=1)
    data = document.build(audit, checklist)
    doctor, _code = render_doctor(audit, checklist, Style(enabled=False))
    return {
        "document.json": json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True),
        "report.html": report_html.render(audit, checklist, data["views"]),
        "doctor.txt": doctor,
    }


@pytest.mark.parametrize("name", ["document.json", "report.html", "doctor.txt"])
def test_output_matches_golden(home: Path, name: str) -> None:
    actual = normalise(outputs(home)[name], home)
    path = GOLDEN / name
    if UPDATE or not path.exists():
        path.write_text(actual, encoding="utf-8")
    assert actual == path.read_text(encoding="utf-8")
