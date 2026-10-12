"""macOS Keychain access through the registered ``security`` probe.

Whether an item is readable without a prompt is established by behaviour, not by parsing
ACLs (``dump-keychain -a`` takes close to a minute on a large keychain): the audit reads the
item through ``/usr/bin/security`` with stdin closed. If that returns the secret, any process
running as the user can do the same with no dialog.

Secret values are returned to the caller in memory only and must be reduced to metadata
with ``tokens.inspect_token`` before anything is stored or printed.
"""

import re
import time
from dataclasses import dataclass

from ai_footprint.system import System

_ATTR = re.compile(r'"(acct|cdat|mdat)"<\w+>=(?:0x[0-9A-F]+\s+)?"?([^"\n]*)"?')
SILENT_READ_SECONDS = 5.0


@dataclass
class KeychainItem:
    """Metadata about a generic-password item."""

    service: str
    account: str = ""
    keychain: str = ""
    created: str = ""
    modified: str = ""


@dataclass
class SecretRead:
    """Result of reading an item's secret through /usr/bin/security."""

    value: str | None
    silent: bool
    seconds: float


def _stamp(raw: str) -> str:
    digits = raw.replace("\\000", "").rstrip("Z")
    if len(digits) >= 14 and digits[:14].isdigit():
        d = digits
        return f"{d[0:4]}-{d[4:6]}-{d[6:8]} {d[8:10]}:{d[10:12]}:{d[12:14]} UTC"
    return raw


def find_item(system: System, service: str) -> KeychainItem | None:
    """Look up a generic-password item's attributes (no secret)."""
    if not system.has_probe("security"):
        return None
    result = system.run("security", ["find-generic-password", "-s", service])
    if result.returncode != 0:
        return None
    item = KeychainItem(service=service)
    keychain = re.search(r'^keychain: "(.+)"$', result.stdout, re.MULTILINE)
    item.keychain = keychain.group(1) if keychain else ""
    for key, value in _ATTR.findall(result.stdout):
        if key == "acct":
            item.account = value
        elif key == "cdat":
            item.created = _stamp(value)
        elif key == "mdat":
            item.modified = _stamp(value)
    return item


def read_secret(system: System, service: str) -> SecretRead:
    """Read the item's secret in memory and record whether it came back without a prompt."""
    if not system.has_probe("security"):
        return SecretRead(None, silent=False, seconds=0.0)
    started = time.monotonic()
    result = system.run(
        "security", ["find-generic-password", "-s", service, "-w"], timeout=SILENT_READ_SECONDS * 6
    )
    seconds = time.monotonic() - started
    value = result.stdout.strip() if result.returncode == 0 else ""
    return SecretRead(
        value or None,
        silent=bool(value) and seconds < SILENT_READ_SECONDS,
        seconds=round(seconds, 2),
    )
