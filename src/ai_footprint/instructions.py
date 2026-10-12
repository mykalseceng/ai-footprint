"""Find and analyse instruction files (CLAUDE.md, AGENTS.md, ...) fed to the model.

An instruction file is the cheapest persistent prompt-injection vector: anything that can
write it steers every future session. The analysis flags content an attacker would plant,
and content the owner planted that weakens the model's judgment.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ai_footprint.fsinfo import mode_string, read_text, readable_by_others
from ai_footprint.model import InstructionFile
from ai_footprint.secrets import scan_bytes

HIDDEN_CHARS = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
URL = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
AUTHORITY = re.compile(
    r"\b(attest\w*|sanction\w*|pre-?approved|already ha(s|ve) (the )?(required )?permission\w*|"
    r"trusted access|authori[sz]ed to|no need to (ask|confirm)|do not ask|never ask|"
    r"skip (the )?(confirmation|approval)s?)\b",
    re.IGNORECASE,
)
OVERRIDE = re.compile(
    r"\b(ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?"
    r"(system|previous)|you are now|developer mode|jailbreak)\b",
    re.IGNORECASE,
)
SHELL_PIPE = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(ba|z)?sh\b|base64\s+(-d|--decode)", re.IGNORECASE
)
LONG_BASE64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


@dataclass(frozen=True)
class Candidate:
    """A possible instruction-file location and which tool reads it."""

    path: Path
    scope: str
    tool: str


def analyse_text(text: str) -> list[str]:
    """Return human-readable risk markers found in instruction text."""
    markers: list[str] = []
    hidden = HIDDEN_CHARS.findall(text)
    if hidden:
        codes = sorted({f"U+{ord(c):04X}" for c in hidden})
        markers.append(f"hidden/bidi characters: {', '.join(codes[:6])}")
    authority = sorted({m.group(0).lower() for m in AUTHORITY.finditer(text)})
    if authority:
        markers.append(f"authority or attestation claims: {', '.join(authority[:5])}")
    overrides = sorted({m.group(0).lower() for m in OVERRIDE.finditer(text)})
    if overrides:
        markers.append(f"instruction-override phrasing: {', '.join(overrides[:3])}")
    hosts = sorted({m.group(1).lower() for m in URL.finditer(text)})
    if hosts:
        markers.append(f"external URLs the model may fetch: {', '.join(hosts[:6])}")
    if SHELL_PIPE.search(text):
        markers.append("download-and-execute or decode-and-run shell pattern")
    if LONG_BASE64.search(text):
        markers.append("long base64-like blob")
    secrets = scan_bytes(text.encode(), len(text.encode()))
    if secrets:
        kinds = sorted({kind for kind, _fp, _last4 in secrets})
        markers.append(f"embedded secrets: {', '.join(kinds)}")
    return markers


def collect(candidates: Iterable[Candidate]) -> list[InstructionFile]:
    """Inspect every existing candidate, merging tools that read the same file."""
    merged: dict[str, InstructionFile] = {}
    for candidate in candidates:
        path = candidate.path
        if not path.is_file():
            continue
        key = str(path.resolve())
        if key in merged:
            if candidate.tool not in merged[key].loaded_by:
                merged[key].loaded_by.append(candidate.tool)
            continue
        info = path.stat()
        merged[key] = InstructionFile(
            path=str(path),
            scope=candidate.scope,
            loaded_by=[candidate.tool],
            size_bytes=info.st_size,
            mode=mode_string(info.st_mode),
            other_readable=readable_by_others(path),
            markers=analyse_text(read_text(path)),
        )
    return sorted(merged.values(), key=lambda f: (f.scope != "global", f.path))


def project_candidates(projects: Iterable[str], names: Iterable[str], tool: str) -> list[Candidate]:
    """Instruction files a tool would load from each known project directory."""
    names = tuple(names)
    return [
        Candidate(Path(project) / name, "project", tool) for project in projects for name in names
    ]
