from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ai_footprint.secrets import scan_bytes, scan_paths
from ai_footprint.tokens import fingerprint
from tests.conftest import FAKE_ANTHROPIC_ACCESS, FAKE_API_KEY, FAKE_DEEPSEEK

AWS = "AKIAABCDEFGHIJKLMNOP"


def kinds(data: bytes) -> list[str]:
    return [kind for kind, _fp, _last4 in scan_bytes(data, len(data))]


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (FAKE_ANTHROPIC_ACCESS, "anthropic_oauth_access"),
        (FAKE_API_KEY, "anthropic_api_key"),
        (FAKE_DEEPSEEK, "generic_sk_key"),
        (AWS, "aws_access_key"),
        ("ghp_" + "a" * 36, "github_token"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "private_key"),
        ("AIza" + "b" * 35, "google_api_key"),
    ],
)
def test_each_pattern_detects_its_format(value: str, kind: str):
    assert kind in kinds(f'{{"v": "{value}"}}'.encode())


def test_boundary_patterns_ignore_matches_inside_words():
    assert "generic_sk_key" not in kinds(b"task-" + b"a" * 40)
    assert "aws_access_key" not in kinds(b"XAKIAABCDEFGHIJKLMNOP")


def test_matches_starting_past_the_limit_are_left_for_the_next_chunk():
    data = b" " * 10 + AWS.encode()
    assert scan_bytes(data, 10) == []
    assert scan_bytes(data, 11) != []


def test_scan_reports_counts_and_never_values(tmp_path: Path):
    (tmp_path / "a.jsonl").write_text(f"{FAKE_API_KEY}\n{FAKE_API_KEY}\n{AWS}\n")
    (tmp_path / "b.log").write_text(AWS)
    scan = scan_paths([tmp_path], workers=1)
    summary = {k.kind: k for k in scan.kinds}
    assert summary["anthropic_api_key"].unique == 1
    assert summary["aws_access_key"].files == 2
    assert summary["anthropic_api_key"].last4 == ["QQQQ"]
    assert FAKE_API_KEY not in repr(scan)
    assert AWS not in repr(scan)


def test_known_credentials_are_located(tmp_path: Path):
    (tmp_path / "t.jsonl").write_text(FAKE_ANTHROPIC_ACCESS)
    scan = scan_paths(
        [tmp_path], workers=1, known={fingerprint(FAKE_ANTHROPIC_ACCESS): "current access token"}
    )
    assert scan.current_credential_hits == [f"current access token found in {tmp_path}/t.jsonl"]


def test_own_credentials_inside_their_store_are_not_copies(tmp_path: Path):
    store = tmp_path / "auth.json"
    store.write_text(f"{FAKE_ANTHROPIC_ACCESS} {AWS}")
    (tmp_path / "log.txt").write_text(FAKE_ANTHROPIC_ACCESS)
    known = {fingerprint(FAKE_ANTHROPIC_ACCESS): "current token"}
    scan = scan_paths([tmp_path], workers=1, known=known, stores=[store])
    assert scan.current_credential_hits == [f"current token found in {tmp_path}/log.txt"]
    summary = {k.kind: k.files for k in scan.kinds}
    assert summary == {"anthropic_oauth_access": 1, "aws_access_key": 1}


def test_markers_are_counted_with_file_totals(tmp_path: Path):
    for name in ("1.jsonl", "2.jsonl"):
        (tmp_path / name).write_text('"apiRefusalCategory":"cyber" x "apiRefusalCategory":"cyber"')
    scan = scan_paths(
        [tmp_path], workers=1, markers={"cyber": ("refusals", b'"apiRefusalCategory":"cyber"')}
    )
    assert scan.markers[0].count == 4
    assert scan.markers[0].file_count == 2


def test_unreadable_files_are_reported(tmp_path: Path):
    locked = tmp_path / "locked.log"
    locked.write_text(AWS)
    locked.chmod(0o000)
    try:
        scan = scan_paths([tmp_path], workers=1)
    finally:
        locked.chmod(0o600)
    assert any("locked.log" in u for u in scan.unreadable)


def test_symlinks_are_not_followed(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s").write_text(AWS)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside / "s")
    assert scan_paths([root], workers=1).kinds == []


def test_missing_roots_are_skipped(tmp_path: Path):
    assert scan_paths([tmp_path / "nope"], workers=1).files_scanned == 0


@settings(max_examples=40, deadline=None)
@given(prefix=st.integers(min_value=0, max_value=300), chunk=st.integers(min_value=8, max_value=64))
def test_secret_straddling_chunk_boundaries_is_counted_once(
    tmp_path_factory: pytest.TempPathFactory, prefix: int, chunk: int
):
    root = tmp_path_factory.mktemp("chunks")
    (root / "f").write_bytes(b" " * prefix + AWS.encode() + b" " * 7)
    scan = scan_paths([root], workers=1, chunk_bytes=chunk)
    assert [(k.kind, k.unique) for k in scan.kinds] == [("aws_access_key", 1)]


def test_documentation_placeholders_are_not_counted():
    assert kinds(b"key AKIAIOSFODNN7EXAMPLE here") == []
    assert kinds(b'"AIza' + b"b" * 31 + b'XXXX"') == []
    assert kinds(b"key AKIAABCDEFGHIJKLMNOP here") == ["aws_access_key"]


def test_excluded_folders_are_skipped_and_listed(tmp_path: Path):
    (tmp_path / "plugins" / "vendor").mkdir(parents=True)
    (tmp_path / "plugins" / "vendor" / "readme.md").write_text(FAKE_API_KEY)
    (tmp_path / "history.jsonl").write_text(FAKE_DEEPSEEK)
    scan = scan_paths([tmp_path], workers=1, exclude=[tmp_path / "plugins", tmp_path / "gone"])
    assert [k.kind for k in scan.kinds] == ["generic_sk_key"]
    assert scan.excluded == [str(tmp_path / "plugins")]
    assert scan.files_scanned == 1
