from pathlib import Path

import pytest

from ai_footprint.collectors.common import search_file


@pytest.mark.parametrize("offset", range(8))
def test_marker_split_across_chunks_is_found(tmp_path: Path, offset: int):
    target = tmp_path / "bin"
    target.write_bytes(b"x" * offset + b"/api/oauth/revoke" + b"y" * 9)

    found = search_file(target, ["/api/oauth/revoke", "absent"], chunk_bytes=4)

    assert found == {"/api/oauth/revoke": True, "absent": False}


def test_markers_reported_independently(tmp_path: Path):
    target = tmp_path / "bin"
    target.write_bytes(b"\x00\xffalpha\x00" * 1000 + b"beta")

    found = search_file(target, ["alpha", "beta", "gamma"], chunk_bytes=64)

    assert found == {"alpha": True, "beta": True, "gamma": False}


def test_stops_reading_once_every_marker_is_found(tmp_path: Path, monkeypatch):
    target = tmp_path / "bin"
    target.write_bytes(b"alpha" + b"z" * 1000)
    reads: list[int] = []
    real_open = Path.open

    def counting_open(self: Path, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        real_read = handle.read

        def read(size: int = -1) -> bytes:
            reads.append(size)
            return real_read(size)

        handle.read = read
        return handle

    monkeypatch.setattr(Path, "open", counting_open)

    assert search_file(target, ["alpha"], chunk_bytes=16) == {"alpha": True}
    assert len(reads) == 1


def test_empty_file_matches_nothing(tmp_path: Path):
    target = tmp_path / "empty"
    target.write_bytes(b"")

    assert search_file(target, ["alpha"]) == {"alpha": False}


def test_missing_file_matches_nothing(tmp_path: Path):
    assert search_file(tmp_path / "missing", ["alpha"]) == {"alpha": False}


def test_no_markers_returns_empty(tmp_path: Path):
    target = tmp_path / "bin"
    target.write_bytes(b"alpha")

    assert search_file(target, []) == {}
