import grp
import pwd
import shutil
import tempfile
from pathlib import Path

import pytest

from ai_footprint.fsinfo import (
    describe,
    human_size,
    readable_by_group,
    readable_by_others,
    tilde,
    tree_stats,
)
from ai_footprint.model import Category


def test_world_readable_file_in_open_tree_is_exposed():
    root = Path(tempfile.mkdtemp(dir="/tmp"))
    try:
        root.chmod(0o755)
        target = root / "config.json"
        target.write_text("{}")
        target.chmod(0o644)
        assert readable_by_others(target)
    finally:
        shutil.rmtree(root)


def test_world_readable_file_inside_private_folder_is_not_exposed():
    root = Path(tempfile.mkdtemp(dir="/tmp"))
    try:
        private = root / "private"
        private.mkdir(mode=0o700)
        root.chmod(0o755)
        target = private / "config.json"
        target.write_text("{}")
        target.chmod(0o644)
        assert not readable_by_others(target)
    finally:
        shutil.rmtree(root)


def test_describe_totals_tree_without_following_symlinks(tmp_path: Path):
    (tmp_path / "a").write_bytes(b"x" * 10)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"y" * 5)
    (tmp_path / "link").symlink_to("/etc/hosts")
    artifact = describe(tmp_path, label="t", category=Category.LOG, description="d")
    assert (artifact.size_bytes, artifact.file_count, artifact.is_dir) == (15, 2, True)


def test_missing_path_is_marked_absent(tmp_path: Path):
    artifact = describe(tmp_path / "nope", label="t", category=Category.LOG, description="d")
    assert not artifact.exists


def test_human_size_uses_decimal_units():
    assert human_size(512) == "512 B"
    assert human_size(999) == "999 B"
    assert human_size(1000) == "1 KB"
    assert human_size(945_032_111) == "945.0 MB"
    assert human_size(3 * 1000**4) == "3.0 TB"


def test_tilde_replaces_home_only_at_a_path_boundary():
    home = "/Users/al"
    assert tilde("/Users/al", home) == "~"
    assert tilde("/Users/al/.claude", home) == "~/.claude"
    assert tilde("/Users/alice/.claude", home) == "/Users/alice/.claude"
    assert tilde("node /Users/al/x.js, then /Users/al", home) == "node ~/x.js, then ~"
    assert tilde("/Users/al/x", "") == "/Users/al/x"


def _group_tree(root_mode: int, file_mode: int) -> tuple[Path, Path]:
    root = Path(tempfile.mkdtemp(dir="/tmp"))
    target = root / "history.jsonl"
    target.write_text("{}")
    target.chmod(file_mode)
    root.chmod(root_mode)
    info = target.stat()
    if grp.getgrgid(info.st_gid).gr_name == pwd.getpwuid(info.st_uid).pw_name:
        shutil.rmtree(root)
        pytest.skip("the file's group is the owner's personal group")
    return root, target


@pytest.mark.parametrize(
    ("root_mode", "file_mode", "readable"),
    [(0o750, 0o640, True), (0o700, 0o640, False), (0o750, 0o600, False)],
)
def test_group_readability_follows_group_bits_through_parents(
    root_mode: int, file_mode: int, readable: bool
):
    root, target = _group_tree(root_mode, file_mode)
    try:
        group = grp.getgrgid(target.stat().st_gid).gr_name
        assert readable_by_group(target) == (group if readable else "")
        assert not readable_by_others(target)
    finally:
        root.chmod(0o700)
        shutil.rmtree(root)


def test_group_readability_of_missing_path_is_empty(tmp_path: Path):
    assert readable_by_group(tmp_path / "nope") == ""


def test_tree_stats_counts_files_readable_through_every_folder(tmp_path: Path):
    root = tmp_path / "projects"
    (root / "open").mkdir(parents=True)
    (root / "closed").mkdir()
    (root / "open" / "a.jsonl").write_text("{}")
    (root / "open" / "b.jsonl").write_text("{}")
    (root / "closed" / "c.jsonl").write_text("{}")
    (root / "open" / "a.jsonl").chmod(0o644)
    (root / "open" / "b.jsonl").chmod(0o600)
    (root / "closed" / "c.jsonl").chmod(0o644)
    (root / "closed").chmod(0o700)
    root.chmod(0o755)
    (root / "open").chmod(0o755)
    totals = tree_stats(root)
    assert (totals.file_count, totals.group_files, totals.other_files) == (3, 1, 1)
