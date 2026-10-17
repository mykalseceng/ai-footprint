"""Helpers shared by the per-tool collectors."""

import json
import re
import shlex
import stat
import tomllib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ai_footprint.fsinfo import describe, mode_string, owner_name, readable_by_others, tree_stats
from ai_footprint.model import (
    Artifact,
    BinaryInfo,
    Category,
    Credential,
    Endpoint,
    FingerprintItem,
    Setting,
    ToolPresence,
)
from ai_footprint.system import System
from ai_footprint.tokens import inspect_token

AD_HOC = "ad-hoc signed (no signing identity)"
HOST_RE = re.compile(rb"https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?=[/:\"'\s?)\\]|$)")
INTERPRETERS = frozenset({"node", "python", "python3", "bun", "deno", "uv", "npx", "uvx"})
SHELLS = frozenset({"bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/bin/zsh"})
MAX_HOST_BYTES = 256 * 1024 * 1024
SEARCH_CHUNK_BYTES = 8 * 1024 * 1024


@dataclass
class Context:
    """Inputs every collector needs."""

    home: Path
    system: System
    now: float
    live: bool = False
    scan: bool = True
    workers: int | None = None
    _marker_cache: dict[tuple[str, str], bool] = field(default_factory=dict)

    def display(self, path: str) -> str:
        """Path with the home directory shown as ``~``."""
        home = str(self.home)
        return "~" + path[len(home) :] if path.startswith(home) else path

    def binary_has(self, binary: str, markers: Iterable[str]) -> dict[str, bool]:
        """Which marker strings appear in a binary or script."""
        wanted = [m for m in markers if (binary, m) not in self._marker_cache]
        if wanted:
            found = search_file(Path(binary), wanted)
            for marker in wanted:
                self._marker_cache[(binary, marker)] = found.get(marker, False)
        return {m: self._marker_cache[(binary, m)] for m in markers}


@dataclass(frozen=True)
class ArtifactSpec:
    """A known location a tool writes to."""

    label: str
    relpath: str
    category: Category
    description: str


@dataclass(frozen=True)
class Claim:
    """A statement about a tool that is only reported when ``marker`` is in its binary.

    Endpoints, signature traits, config keys, log markers and behaviour markers are all
    registered as claims. The audit drops any claim the installed binary does not contain,
    and ``--validate`` fails on it, so a constant that was typed from memory and is wrong, or
    that a newer version removed, never reaches the report as fact.
    """

    label: str
    marker: str


def confirmed_settings(ctx: Context, binary: str, rows: list[tuple[Setting, str]]) -> list[Setting]:
    """Drop unset settings whose key the installed binary does not know.

    A value read from the config file is an observation and is always kept. A "not set"
    row is only worth showing when the binary knows the key, otherwise it suggests a
    setting the installed version does not have.
    """
    markers = [marker for _setting, marker in rows if marker]
    known = ctx.binary_has(binary, markers) if binary and markers else {}
    return [
        setting
        for setting, marker in rows
        if not marker or setting.value != "not set" or known.get(marker)
    ]


def search_file(
    path: Path, markers: Iterable[str], *, chunk_bytes: int = SEARCH_CHUNK_BYTES
) -> dict[str, bool]:
    """Report which markers occur in ``path`` (a file, or every file under a directory).

    The file is read rather than memory-mapped. macOS kills a process with SIGKILL when it
    faults in a page of a signed binary whose hash does not match the code signature, and
    Bun-built executables such as OpenCode ship such pages. Plain reads are not checked.
    """
    result = dict.fromkeys(markers, False)
    if path.is_dir():
        for file in sorted(p for p in path.rglob("*") if p.is_file()):
            found = search_file(
                file, [m for m, ok in result.items() if not ok], chunk_bytes=chunk_bytes
            )
            result.update({m: True for m, ok in found.items() if ok})
            if all(result.values()):
                break
        return result
    needles = {marker: marker.encode() for marker in result}
    overlap = max((len(n) for n in needles.values()), default=1) - 1
    tail = b""
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(chunk_bytes):
                window = tail + chunk
                for marker, needle in needles.items():
                    result[marker] = result[marker] or needle in window
                if all(result.values()):
                    break
                tail = window[-overlap:] if overlap > 0 else b""
    except OSError:
        return result
    return result


def describe_all(base: Path, specs: Iterable[ArtifactSpec]) -> list[Artifact]:
    """Describe each spec relative to ``base``, keeping only paths that exist."""
    artifacts = []
    for spec in specs:
        artifact = describe(
            base / spec.relpath,
            label=spec.label,
            category=spec.category,
            description=spec.description,
        )
        if artifact.exists:
            artifacts.append(artifact)
    return artifacts


def load_json(path: Path) -> Any:  # noqa: ANN401 - JSON documents are untyped
    """Parse JSON, returning None when missing or malformed."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_jsonc(path: Path) -> Any:  # noqa: ANN401 - JSON documents are untyped
    """Parse JSON with // and /* */ comments and trailing commas."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    text = re.sub(
        r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', lambda m: m.group(1) or "", text, flags=re.DOTALL
    )
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    try:
        return json.loads(text)
    except ValueError:
        return None


def load_toml(path: Path) -> dict[str, Any] | None:
    """Parse TOML, returning None when missing or malformed."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None


def binary_info(system: System, path: str, *, version: str = "") -> BinaryInfo:
    """Resolve a tool binary and read its signing identity and permissions."""
    resolved = Path(path).resolve()
    info = BinaryInfo(path=path, resolved=str(resolved), version=version)
    try:
        st = resolved.stat()
    except OSError:
        return info
    info.owner = owner_name(st.st_uid)
    info.mode = mode_string(st.st_mode)
    for directory in dict.fromkeys([Path(path).parent, resolved.parent]):
        if _dir_writable(directory.stat().st_mode):
            info.writable_dirs.append(str(directory))
    if system.has_probe("codesign"):
        result = system.run("codesign", ["-dv", "--verbose=2", str(resolved)])
        info.signer = signer(result.stderr)
        team = re.search(r"^TeamIdentifier=(.+)$", result.stderr, re.MULTILINE)
        info.team_id = team.group(1) if team and team.group(1) != "not set" else ""
    return info


def signer(codesign_output: str) -> str:
    """Who signed a binary, from ``codesign -dv`` output: an authority, ad-hoc, or unsigned."""
    authorities = re.findall(r"^Authority=(.+)$", codesign_output, re.MULTILINE)
    if authorities:
        return authorities[0]
    if re.search(r"^Signature=adhoc$", codesign_output, re.MULTILINE):
        return AD_HOC
    return "unsigned or not a Mach-O binary"


def provider_credential(
    ctx: Context,
    entry: dict[str, Any],
    *,
    tool: str,
    provider: str,
    store: str,
    path: Path,
    fingerprints: dict[str, str],
    label: str,
) -> Credential:
    """A provider login or key stored as ``{type, access, refresh, key, expires}``.

    Args:
        ctx: Collector inputs.
        entry: The stored entry.
        tool: Tool id.
        provider: Provider name as shown in the report.
        store: How the entry is stored, e.g. ``plaintext file``.
        path: File holding the entry.
        fingerprints: Known credential fingerprints, extended with this entry's values.
        label: How a copy of a value found elsewhere is named, e.g. ``pi openai``.
    """
    cred = Credential(
        tool,
        provider,
        store,
        str(path),
        f"{entry.get('type', '?')} credential; file mode {mode_string(path.stat().st_mode)}",
        readable_by_others=readable_by_others(path),
    )
    for name in ("access", "refresh", "key"):
        value = entry.get(name)
        if isinstance(value, str) and value:
            info = inspect_token(
                name,
                value,
                now=ctx.now,
                expires_at=entry.get("expires") if name == "access" else None,
            )
            cred.tokens.append(info)
            fingerprints.setdefault(info.fingerprint, f"{label} {name}")
    return cred


def _dir_writable(mode: int) -> bool:
    """Group- or other-writable without the sticky bit."""
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH)) and not mode & stat.S_ISVTX


def mine_hosts(paths: Iterable[Path], *, budget: int = MAX_HOST_BYTES) -> Counter[str]:
    """Count URL hosts mentioned in log files, reading at most ``budget`` bytes total."""
    counts: Counter[str] = Counter()
    remaining = budget
    for path in _files(paths):
        if remaining <= 0:
            break
        try:
            with path.open("rb") as handle:
                data = handle.read(remaining)
        except OSError:
            continue
        remaining -= len(data)
        counts.update(m.group(1).decode() for m in HOST_RE.finditer(data))
    return counts


def _files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from sorted(
                (p for p in path.rglob("*") if p.is_file() and not p.is_symlink()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )


def mined_endpoints(
    tool: str, counts: Counter[str], purposes: dict[str, str], *, top: int = 15
) -> list[Endpoint]:
    """Turn host counts from logs into endpoints, labelling known hosts."""
    return [
        Endpoint(
            tool=tool,
            host=host,
            purpose=purposes.get(host, "seen in local logs"),
            source="logs",
            count=count,
        )
        for host, count in counts.most_common(top)
    ]


def command_target(command: str, args: list[str]) -> str | None:
    """The file an MCP/hook command ultimately runs, when it can be determined."""
    name = Path(command).name
    if name in INTERPRETERS:
        scripts = [a for a in args if not a.startswith("-")]
        return scripts[0] if scripts and ("/" in scripts[0] or "." in scripts[0]) else None
    if command in SHELLS or name in {"bash", "sh", "zsh"}:
        for index, arg in enumerate(args):
            if arg.endswith("c") and arg.startswith("-") and index + 1 < len(args):
                try:
                    words = shlex.split(args[index + 1])
                except ValueError:
                    return None
                return words[0] if words else None
        return None
    return command


def is_dangling(command: str, args: list[str], *, cwd: Path | None = None) -> bool:
    """True when the program or script a command launches does not exist."""
    target = command_target(command, args)
    if target is None or "/" not in target:
        return False
    path = Path(target).expanduser()
    if not path.is_absolute() and cwd is not None:
        path = cwd / path
    return not path.exists()


def fingerprint_items(
    ctx: Context, binary: str, items: Iterable[tuple[str, str, str]]
) -> list[FingerprintItem]:
    """Fingerprint rows whose marker is in the binary; the rest are not reported."""
    rows = list(items)
    found = ctx.binary_has(binary, [marker for _label, _value, marker in rows]) if binary else {}
    return [FingerprintItem(label, value) for label, value, marker in rows if found.get(marker)]


def presence(
    name: str, display_name: str, binaries: list[BinaryInfo], paths: list[Path]
) -> ToolPresence:
    """Presence record: installed when a binary is on PATH or a data folder exists."""
    existing = [p for p in paths if p.exists()]
    return ToolPresence(
        name=name,
        display_name=display_name,
        installed=bool(binaries or existing),
        binaries=binaries,
        data_paths=[str(p) for p in existing],
        size_bytes=sum(tree_stats(p).size_bytes for p in existing),
    )
