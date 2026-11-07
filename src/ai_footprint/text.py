"""English phrasing shared by checks, harnesses and reports."""

import re

from ai_footprint.fsinfo import tilde


def join(items: list[str]) -> str:
    """English list: "a", "a and b", "a, b and c"."""
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + f" and {items[-1]}"


_ISO = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2})?(?:\.\d+)?(?:\+00:00|Z| UTC)?")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`~/])")


def when(text: str) -> str:
    """Rewrite ISO timestamps in ``text`` as ``YYYY-MM-DD HH:MM UTC`` so dates read one way."""
    return _ISO.sub(r"\1 \2 UTC", text)


def sentences(text: str) -> list[str]:
    """Split prose into sentences at a terminator followed by a capital, backtick or path."""
    return [part for part in _SENTENCE.split(text.strip()) if part]


def short_path(path: str, home: str) -> str:
    """Path with ``~`` for home and a long last segment (a hash) cut to 12 characters."""
    shown = tilde(path, home)
    head, _, name = shown.rpartition("/")
    return f"{head}/{name[:12]}…" if len(name) > 16 else shown


def plural(count: int, word: str) -> str:
    """``3 credentials`` / ``1 credential``."""
    if count == 1:
        return f"{count} {word}"
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return f"{count} {word[:-1]}ies"
    return f"{count} {word}s"
