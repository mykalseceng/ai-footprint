"""Find what a harness has on this machine that its profile does not describe yet.

Three offline scans, each reading only names, never values:

* files and folders inside the tool's own folders that no profile artifact covers;
* top-level keys of the tool's JSON and TOML config files that no setting or feature names;
* environment variables the installed binary reads, by the profile's prefixes, that no
  ``env`` entry or feature lists.

The results are candidates for the profile, not findings: the harness profiler researches
each one in the official docs before it is added.
"""

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path

from ai_footprint.harnesses.base import Harness, resolve, resolve_roots
from ai_footprint.harnesses.common import Context, load_jsonc
from ai_footprint.harnesses.profile import FeatureKind, path_of
from ai_footprint.model import Category

MAX_DEPTH = 3
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
CHUNK_BYTES = 8 * 1024 * 1024
CONFIG_SUFFIXES = {".json", ".jsonc", ".toml"}


def artifact_paths(ctx: Context, harness: Harness) -> list[Path]:
    """Where each profile artifact lives on this machine."""
    roots = resolve_roots(ctx, harness.profile)
    return [path_of(a.path, roots) for a in harness.profile.artifacts]


def unmapped_paths(ctx: Context, harness: Harness) -> list[Path]:
    """Entries inside the tool's own folders that no artifact covers, shallowest first.

    A folder that holds a known artifact is opened; any other entry is reported once and
    not descended into.
    """
    known = artifact_paths(ctx, harness)
    out: list[Path] = []
    for template in harness.profile.presence:
        folder = resolve(ctx, harness.profile, template)
        if folder.is_dir() and folder != ctx.home:
            _walk(folder, known, out, depth=1)
    return sorted(out)


def _walk(folder: Path, known: list[Path], out: list[Path], *, depth: int) -> None:
    try:
        entries = sorted(folder.iterdir())
    except OSError:
        return
    for entry in entries:
        if any(entry == k or k in entry.parents for k in known):
            continue
        if entry.is_dir() and depth < MAX_DEPTH and any(entry in k.parents for k in known):
            _walk(entry, known, out, depth=depth + 1)
            continue
        out.append(entry)


def known_config_keys(harness: Harness) -> set[str]:
    """Key names the profile already accounts for, without quotes or separators."""
    profile = harness.profile
    names = [s.name for s in profile.settings]
    names += [f.name for f in profile.features if f.kind is FeatureKind.SETTING]
    names += list(profile.approval_off)
    return {_bare(name).rsplit(".", 1)[-1] for name in names}


def _bare(name: str) -> str:
    return name.strip().strip('"').rstrip(":").strip()


def unknown_config_keys(ctx: Context, harness: Harness) -> dict[str, list[str]]:
    """``{config file: [top-level keys no setting or feature names]}`` for existing configs."""
    known = known_config_keys(harness)
    roots = resolve_roots(ctx, harness.profile)
    out = {}
    for spec in harness.profile.artifacts:
        path = path_of(spec.path, roots)
        if spec.category is not Category.CONFIG or path.suffix not in CONFIG_SUFFIXES:
            continue
        keys = _top_level_keys(path)
        unknown = sorted(k for k in keys if k not in known)
        if unknown:
            out[ctx.display(str(path))] = unknown
    return out


def _top_level_keys(path: Path) -> list[str]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return []
    except OSError:
        return []
    if path.suffix == ".toml":
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            return []
    else:
        data = load_jsonc(path)
    return list(data) if isinstance(data, dict) else []


def known_env(harness: Harness) -> set[str]:
    """Variables the profile already lists."""
    profile = harness.profile
    return {v.name for v in profile.env} | {
        f.name for f in profile.features if f.kind is FeatureKind.ENV
    }


def unknown_env(binary: str, harness: Harness) -> list[str]:
    """Variables with the profile's prefixes that the binary names and the profile does not."""
    prefixes = harness.profile.env_prefixes
    if not binary or not prefixes:
        return []
    pattern = re.compile(
        rb"(?<![A-Za-z0-9_])(?:" + b"|".join(re.escape(p.encode()) for p in prefixes) + rb")"
        rb"[A-Z0-9_]*[A-Z0-9]"
    )
    found = {m.decode() for m in _scan(Path(binary), pattern)}
    return sorted(found - known_env(harness) - set(prefixes))


def _scan(path: Path, pattern: re.Pattern[bytes]) -> set[bytes]:
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    found: set[bytes] = set()
    budget = MAX_BINARY_BYTES
    for file in files:
        if budget <= 0:
            break
        budget -= _scan_file(file, pattern, found, budget)
    return found


def _scan_file(file: Path, pattern: re.Pattern[bytes], found: set[bytes], budget: int) -> int:
    """Add every match in ``file`` to ``found``; returns the bytes read.

    Windows overlap by 256 bytes. A match touching either edge of a window may be cut, so it
    is taken only from the window that holds it whole.
    """
    read = 0
    tail = b""
    try:
        with file.open("rb") as handle:
            while read < budget:
                chunk = handle.read(CHUNK_BYTES)
                read += len(chunk)
                last = not chunk or read >= budget
                window = tail + chunk
                found.update(
                    m.group()
                    for m in pattern.finditer(window)
                    if (m.start() > 0 or not tail) and (m.end() < len(window) or last)
                )
                if last:
                    break
                tail = window[-256:]
    except OSError:
        return read
    return read


def names(paths: Iterable[Path], ctx: Context) -> list[str]:
    """Paths as shown in the report."""
    return [ctx.display(str(p)) + ("/" if p.is_dir() else "") for p in paths]
