import shutil
import tempfile
from pathlib import Path

from ai_footprint.fsinfo import describe, human_size, readable_by_others
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


def test_human_size_units():
    assert human_size(512) == "512 B"
    assert human_size(3 * 1024**2) == "3.0 MB"
