"""Full-content secret scan of AI-tool data stores, in parallel, keeping no values.

Files are split into fixed byte ranges so one 2 GB SQLite file spreads across all cores.
Each worker reads its range plus an overlap and keeps only matches that *start* inside its
range, so nothing is double counted. Workers return the secret kind, a fingerprint, and the
last four characters. The values themselves never leave the worker.
"""

import os
import re
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ai_footprint.model import MarkerHit, SecretKindSummary, SecretScan
from ai_footprint.tokens import fingerprint

CHUNK_BYTES = 32 * 1024 * 1024
OVERLAP_BYTES = 16 * 1024
MAX_LOCATIONS = 8


@dataclass(frozen=True)
class SecretPattern:
    """A secret format. Patterns start with a literal so the regex engine can skip fast."""

    kind: str
    label: str
    regex: bytes
    boundary: bool = False


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "anthropic_oauth_access",
        "Anthropic OAuth access token",
        rb"sk-ant-oat01-[A-Za-z0-9_\-]{80,}",
    ),
    SecretPattern(
        "anthropic_oauth_refresh",
        "Anthropic OAuth refresh token",
        rb"sk-ant-ort01-[A-Za-z0-9_\-]{80,}",
    ),
    SecretPattern("anthropic_api_key", "Anthropic API key", rb"sk-ant-api03-[A-Za-z0-9_\-]{80,}"),
    SecretPattern("openai_project_key", "OpenAI project API key", rb"sk-proj-[A-Za-z0-9_\-]{40,}"),
    SecretPattern(
        "generic_sk_key", "Provider API key (sk-…)", rb"sk-[A-Za-z0-9]{32,}", boundary=True
    ),
    SecretPattern(
        "openai_refresh", "OpenAI refresh token", rb"rt\.1\.[A-Za-z0-9_\-.]{60,}", boundary=True
    ),
    SecretPattern("github_token", "GitHub token", rb"gh[pousr]_[A-Za-z0-9]{36}", boundary=True),
    SecretPattern("github_pat", "GitHub fine-grained token", rb"github_pat_[A-Za-z0-9_]{60,}"),
    SecretPattern("aws_access_key", "AWS access key ID", rb"AKIA[0-9A-Z]{16}", boundary=True),
    SecretPattern("aws_session_key", "AWS temporary key ID", rb"ASIA[0-9A-Z]{16}", boundary=True),
    SecretPattern("google_api_key", "Google API key", rb"AIza[0-9A-Za-z_\-]{35}", boundary=True),
    SecretPattern("slack_token", "Slack token", rb"xox[abprs]-[0-9A-Za-z\-]{20,}", boundary=True),
    SecretPattern(
        "huggingface_token", "Hugging Face token", rb"hf_[A-Za-z0-9]{34,}", boundary=True
    ),
    SecretPattern("private_key", "Private key block", rb"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----"),
    SecretPattern(
        "jwt", "JWT", rb"eyJ[A-Za-z0-9_\-]{15,}\.eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{20,}"
    ),
    SecretPattern(
        "bearer_header", "Bearer authorization header", rb"Bearer [A-Za-z0-9._~+/\-]{30,}"
    ),
)

_COMPILED = tuple((p.kind, re.compile(p.regex), p.boundary) for p in PATTERNS)
LABELS = {p.kind: p.label for p in PATTERNS}
_WORD_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


@dataclass(frozen=True)
class Task:
    """A byte range of one file."""

    path: str
    start: int
    length: int


@dataclass
class ChunkResult:
    """What a worker found in its byte range."""

    path: str
    bytes_read: int = 0
    error: str = ""
    hits: list[tuple[str, str, str]] = field(default_factory=list)
    markers: dict[str, int] = field(default_factory=dict)


def _placeholder(value: str) -> bool:
    """Documentation placeholders such as AWS's ``AKIAIOSFODNN7EXAMPLE`` or ``AIza…XXXX``."""
    return "EXAMPLE" in value or value.endswith("XXXX")


def scan_bytes(data: bytes, limit: int) -> list[tuple[str, str, str]]:
    """Find secrets whose match starts before ``limit``; return (kind, fingerprint, last4).

    Patterns marked ``boundary`` are skipped when the preceding byte is alphanumeric, so
    ``task-…`` never counts as an ``sk-`` key.
    """
    hits: list[tuple[str, str, str]] = []
    for kind, pattern, boundary in _COMPILED:
        for match in pattern.finditer(data):
            start = match.start()
            if start >= limit:
                break
            if boundary and start > 0 and data[start - 1] in _WORD_BYTES:
                continue
            value = match.group().decode("ascii", errors="replace")
            if _placeholder(value):
                continue
            hits.append((kind, fingerprint(value), value[-4:]))
    return hits


def count_markers(data: bytes, limit: int, markers: Mapping[str, bytes]) -> dict[str, int]:
    """Count marker occurrences that start before ``limit``."""
    counts: dict[str, int] = {}
    for label, marker in markers.items():
        found = data[: limit + len(marker) - 1].count(marker)
        if found:
            counts[label] = found
    return counts


def scan_task(task: Task, markers: Mapping[str, bytes]) -> ChunkResult:
    """Worker entry point: read one range plus overlap and scan it."""
    result = ChunkResult(path=task.path)
    try:
        with Path(task.path).open("rb") as handle:
            handle.seek(task.start)
            data = handle.read(task.length + OVERLAP_BYTES)
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc.strerror or exc}"
        return result
    result.bytes_read = min(len(data), task.length)
    result.hits = scan_bytes(data, task.length)
    result.markers = count_markers(data, task.length, markers)
    return result


def iter_files(roots: Iterable[Path], exclude: Iterable[Path] = ()) -> Iterable[tuple[Path, int]]:
    """Yield (path, size) for regular files under each root, never following symlinks.

    Folders in ``exclude`` are skipped with everything under them.
    """
    skipped = set(exclude)
    seen: set[Path] = set()
    for root in roots:
        if root.is_file() and not root.is_symlink():
            if root not in seen:
                seen.add(root)
                yield root, root.stat().st_size
            continue
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if Path(directory, d) not in skipped]
            for name in files:
                path = Path(directory, name)
                if path in seen or path.is_symlink() or not path.is_file():
                    continue
                seen.add(path)
                yield path, path.stat().st_size


def make_tasks(files: Iterable[tuple[Path, int]], chunk_bytes: int = CHUNK_BYTES) -> list[Task]:
    """Split files into ranges, largest first so long ranges start early."""
    tasks = [
        Task(str(path), start, min(chunk_bytes, size - start))
        for path, size in files
        for start in range(0, size, chunk_bytes)
    ]
    tasks.sort(key=lambda t: t.length, reverse=True)
    return tasks


@dataclass
class _Totals:
    files: set[str] = field(default_factory=set)
    bytes_read: int = 0
    unreadable: set[str] = field(default_factory=set)
    by_kind: dict[str, dict[str, str]] = field(default_factory=lambda: defaultdict(dict))
    kind_files: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    fp_files: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    markers: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    marker_files: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    own: frozenset[str] = frozenset()
    stores: frozenset[str] = frozenset()

    def fold(self, chunk: ChunkResult) -> None:
        if chunk.error:
            self.unreadable.add(f"{chunk.path} ({chunk.error})")
            return
        self.files.add(chunk.path)
        self.bytes_read += chunk.bytes_read
        in_store = chunk.path in self.stores
        for kind, fp, last4 in chunk.hits:
            if in_store and fp in self.own:
                continue
            self.by_kind[kind][fp] = last4
            self.kind_files[kind].add(chunk.path)
            self.fp_files[fp].add(chunk.path)
        for label, count in chunk.markers.items():
            self.markers[label] += count
            self.marker_files[label].add(chunk.path)


def scan_paths(
    roots: list[Path],
    *,
    markers: Mapping[str, tuple[str, bytes]] | None = None,
    known: Mapping[str, str] | None = None,
    stores: Iterable[Path] = (),
    exclude: Iterable[Path] = (),
    workers: int | None = None,
    display: Callable[[str], str] = str,
    chunk_bytes: int = CHUNK_BYTES,
) -> SecretScan:
    """Scan every byte of every file under ``roots``.

    Args:
        roots: Files or directories to scan.
        markers: ``{key: (label, literal)}`` strings to count, e.g. refusal codes.
        known: ``{fingerprint: description}`` of the tool's current credentials, used to
            report where a live secret is also stored on disk.
        stores: The tool's own credential files. Its current credentials found there are
            expected and are neither counted nor reported as copies.
        exclude: Folders under a root that hold installed third-party code rather than your
            data (plugins, bundled packages); they are listed as not scanned.
        workers: Process count; defaults to the CPU count. ``1`` scans in-process.
        display: Formats paths for the report (e.g. replaces the home directory with ~).
        chunk_bytes: Size of each byte range handed to a worker.

    Returns:
        Counts, fingerprints and locations only.
    """
    started = time.monotonic()
    marker_bytes = {key: lit for key, (_label, lit) in (markers or {}).items()}
    existing = [r for r in roots if r.exists()]
    excluded = [p for p in exclude if p.exists()]
    tasks = make_tasks(iter_files(existing, excluded), chunk_bytes)
    totals = _Totals(own=frozenset(known or {}), stores=frozenset(str(p) for p in stores))
    for chunk in _run(tasks, marker_bytes, workers):
        totals.fold(chunk)
    scan = SecretScan(
        roots=[display(str(r)) for r in existing], excluded=[display(str(p)) for p in excluded]
    )
    scan.files_scanned = len(totals.files)
    scan.bytes_scanned = totals.bytes_read
    scan.unreadable = sorted(display(u) for u in totals.unreadable)
    scan.kinds = _summaries(totals, display)
    scan.current_credential_hits = _known_hits(totals, known or {}, display)
    scan.current_credential_values = sum(1 for fp in known or {} if totals.fp_files.get(fp))
    scan.markers = [
        MarkerHit(
            marker=key,
            label=(markers or {})[key][0],
            count=totals.markers[key],
            file_count=len(totals.marker_files[key]),
            files=sorted(display(f) for f in totals.marker_files[key])[:MAX_LOCATIONS],
        )
        for key in sorted(totals.markers)
    ]
    scan.seconds = round(time.monotonic() - started, 1)
    return scan


def _run(
    tasks: list[Task], markers: Mapping[str, bytes], workers: int | None
) -> Iterable[ChunkResult]:
    if workers == 1 or len(tasks) <= 1:
        return [scan_task(t, markers) for t in tasks]
    with ProcessPoolExecutor(max_workers=workers or os.cpu_count()) as pool:
        return list(pool.map(scan_task, tasks, [markers] * len(tasks), chunksize=4))


def _summaries(totals: _Totals, display: Callable[[str], str]) -> list[SecretKindSummary]:
    summaries = []
    for kind, label in LABELS.items():
        values = totals.by_kind.get(kind)
        if not values:
            continue
        files = sorted(totals.kind_files[kind])
        summaries.append(
            SecretKindSummary(
                kind=kind,
                label=label,
                unique=len(values),
                files=len(files),
                locations=[display(f) for f in files[:MAX_LOCATIONS]],
                last4=sorted(set(values.values()))[:MAX_LOCATIONS],
            )
        )
    return summaries


def _known_hits(
    totals: _Totals, known: Mapping[str, str], display: Callable[[str], str]
) -> list[str]:
    return [
        f"{description} found in {display(path)}"
        for fp, description in known.items()
        for path in sorted(totals.fp_files.get(fp, ()))
    ]
