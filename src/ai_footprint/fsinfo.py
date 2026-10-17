"""Filesystem facts: size, file counts, dates, and *effective* permissions.

"Readable by others" means another local account can actually read the item: every parent
directory grants others execute (traverse), and the item grants others read (plus execute
for directories). A 644 file inside a 700 directory is not readable by others.
"""

import datetime
import grp
import os
import pwd
import re
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


def tilde(text: str, home: str) -> str:
    """``text`` with the home directory shown as ``~`` wherever it is a whole path prefix.

    ``/Users/al`` becomes ``~`` in ``/Users/al/x`` but not in ``/Users/alice/x``.
    """
    root = home.rstrip("/")
    if not root:
        return text
    return re.sub(re.escape(root) + r"(?=$|[/\s\"'`),;:\]])", "~", text)


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


def _group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def readable_by_group(path: Path) -> str:
    """Name of the item's group when its other members can read it, else empty.

    A member of the group reaches the item when every parent directory grants it execute,
    through the group bits for directories in the same group and the other bits elsewhere.
    A group named after the owner is the owner's personal group and has no other members.
    """
    try:
        info = path.stat()
    except OSError:
        return ""
    group = _group_name(info.st_gid)
    if group == owner_name(info.st_uid):
        return ""
    needed = stat.S_IRGRP | (stat.S_IXGRP if stat.S_ISDIR(info.st_mode) else 0)
    if info.st_mode & needed != needed:
        return ""
    for parent in path.parents:
        try:
            parent_info = parent.stat()
        except OSError:
            return ""
        bit = stat.S_IXGRP if parent_info.st_gid == info.st_gid else stat.S_IXOTH
        if not parent_info.st_mode & bit:
            return ""
    return group


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
    artifact.group_readable = readable_by_group(path)
    artifact.group_writable = bool(info.st_mode & stat.S_IWGRP)
    artifact.other_writable = bool(info.st_mode & stat.S_IWOTH)
    artifact.oldest = iso_date(totals.oldest)
    artifact.newest = iso_date(totals.newest)
    return artifact


def human_size(size: int) -> str:
    """Compact size string in decimal units, as Finder shows them, e.g. ``598.0 MB``."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in {"B", "KB"} else f"{value:.1f} {unit}"
        value /= 1000
    return f"{size} B"


def read_text(path: Path, limit: int = 2_000_000) -> str:
    """Read a text file up to ``limit`` bytes, returning empty on any error."""
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def outermost(artifacts: list[Artifact]) -> list[Artifact]:
    """Listed locations not inside another listed location, so their sizes can be added."""
    paths = sorted({a.path.rstrip("/") for a in artifacts})
    outer = {p for p in paths if not any(p.startswith(q + "/") for q in paths if q != p)}
    seen: set[str] = set()
    kept = []
    for artifact in artifacts:
        path = artifact.path.rstrip("/")
        if path in outer and path not in seen:
            seen.add(path)
            kept.append(artifact)
    return kept


def disk_bytes(artifacts: list[Artifact], category: Category | None = None) -> int:
    """Bytes on disk for the outermost locations, optionally of one category."""
    return sum(
        a.size_bytes for a in outermost(artifacts) if category is None or a.category is category
    )
