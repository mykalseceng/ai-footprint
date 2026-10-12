"""Filesystem facts: size, file counts, dates, and *effective* permissions.

"Readable by others" means another local account can actually read the item: every parent
directory grants others execute (traverse), and the item grants others read (plus execute
for directories). A 644 file inside a 700 directory is not readable by others.
"""

import datetime
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path

from ai_footprint.model import Artifact, Category


@dataclass
class TreeStats:
    """Aggregate size and timestamps for a file or directory tree."""

    size_bytes: int = 0
    file_count: int = 0
    oldest: float | None = None
    newest: float | None = None

    def add(self, size: int, mtime: float) -> None:
        """Fold one file into the totals."""
        self.size_bytes += size
        self.file_count += 1
        self.oldest = mtime if self.oldest is None else min(self.oldest, mtime)
        self.newest = mtime if self.newest is None else max(self.newest, mtime)


def mode_string(mode: int) -> str:
    """Octal permission bits, e.g. ``644``."""
    return format(stat.S_IMODE(mode), "o")


def owner_name(uid: int) -> str:
    """User name for a uid, or the number when unknown."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def iso_date(timestamp: float | None) -> str:
    """UTC date (YYYY-MM-DD) for a POSIX timestamp, or empty."""
    if timestamp is None:
        return ""
    return datetime.datetime.fromtimestamp(timestamp, datetime.UTC).date().isoformat()


def parents_traversable_by_others(path: Path) -> bool:
    """True when every ancestor directory grants others execute permission."""
    for parent in path.parents:
        try:
            mode = parent.stat().st_mode
        except OSError:
            return False
        if not mode & stat.S_IXOTH:
            return False
    return True


def readable_by_others(path: Path) -> bool:
    """True when another local account can read ``path`` given all parent permissions."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    if stat.S_ISDIR(mode):
        allowed = bool(mode & stat.S_IROTH and mode & stat.S_IXOTH)
    else:
        allowed = bool(mode & stat.S_IROTH)
    return allowed and parents_traversable_by_others(path)


def tree_stats(path: Path) -> TreeStats:
    """Walk ``path`` without following symlinks and total regular files."""
    totals = TreeStats()
    try:
        info = path.lstat()
    except OSError:
        return totals
    if stat.S_ISREG(info.st_mode):
        totals.add(info.st_size, info.st_mtime)
        return totals
    if not stat.S_ISDIR(info.st_mode):
        return totals
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                entry = Path(root, name).lstat()
            except OSError:
                continue
            if stat.S_ISREG(entry.st_mode):
                totals.add(entry.st_size, entry.st_mtime)
    return totals


def count_other_readable(path: Path) -> tuple[int, int]:
    """Count (total, readable-by-others) regular files under a directory."""
    total = exposed = 0
    if not path.is_dir():
        return (1, int(readable_by_others(path))) if path.is_file() else (0, 0)
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            file_path = Path(root, name)
            if not file_path.is_file() or file_path.is_symlink():
                continue
            total += 1
            exposed += int(readable_by_others(file_path))
    return total, exposed


def describe(path: Path, *, label: str, category: Category, description: str) -> Artifact:
    """Build an ``Artifact`` with size, dates, owner, and effective permissions."""
    artifact = Artifact(label=label, path=str(path), category=category, description=description)
    try:
        info = path.stat()
    except OSError:
        return artifact
    totals = tree_stats(path)
    artifact.exists = True
    artifact.is_dir = stat.S_ISDIR(info.st_mode)
    artifact.size_bytes = totals.size_bytes
    artifact.file_count = totals.file_count
    artifact.mode = mode_string(info.st_mode)
    artifact.owner = owner_name(info.st_uid)
    artifact.other_readable = readable_by_others(path)
    artifact.group_writable = bool(info.st_mode & stat.S_IWGRP)
    artifact.other_writable = bool(info.st_mode & stat.S_IWOTH)
    artifact.oldest = iso_date(totals.oldest)
    artifact.newest = iso_date(totals.newest)
    return artifact


def human_size(size: int) -> str:
    """Compact size string, e.g. ``598 MB``."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in {"B", "KB"} else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def read_text(path: Path, limit: int = 2_000_000) -> str:
    """Read a text file up to ``limit`` bytes, returning empty on any error."""
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""
