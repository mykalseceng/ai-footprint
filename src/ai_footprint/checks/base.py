"""Types every check shares: the context, the rule records and the exposure builder."""

import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from ai_footprint import harnesses
from ai_footprint.fsinfo import tilde
from ai_footprint.harnesses.base import RemedyContext
from ai_footprint.harnesses.profile import Capability, Remedy
from ai_footprint.model import (
    AuditReport,
    Exposure,
    Fix,
    HostReport,
    Lens,
    ToolReport,
)


@dataclass
class RuleContext:
    """Inputs shared by all rules."""

    host: HostReport
    platform: str
    home: Path

    def display(self, path: str) -> str:
        """Path with home shown as ~."""
        return tilde(path, str(self.home))

    def remedy(self, report: ToolReport, action: Remedy, **args: str) -> Fix | None:
        """The audited tool's own fix for ``action``, or None when it has none."""
        harness = harnesses.get(report.name)
        if harness is None:
            return None
        return harness.remedy(action, RemedyContext(self.platform, self.home), **args)

    def approval_off(self, report: ToolReport) -> Mapping[str, str]:
        """Setting values that turn approval off for the audited tool."""
        harness = harnesses.get(report.name)
        return harness.profile.approval_off if harness else {}

    def approval_off_flagged(self, report: ToolReport) -> tuple[str, ...]:
        """Setting keys that mean approval is off for the audited tool when flagged."""
        harness = harnesses.get(report.name)
        return harness.profile.approval_off_flagged if harness else ()

    def records_remote_control(self, report: ToolReport) -> bool:
        """The tool's harness records whether another device can drive it here."""
        harness = harnesses.get(report.name)
        return harness is not None and Capability.REMOTE_CONTROL in harness.profile.capabilities


ToolRuleFn = Callable[[ToolReport, RuleContext], list[Exposure]]
HostRuleFn = Callable[[AuditReport, RuleContext], list[Exposure]]


def _always(report: ToolReport, ctx: RuleContext) -> str:
    del report, ctx
    return ""


@dataclass(frozen=True)
class Rule:
    """A check with a checklist title and the function that states exposures.

    Attributes:
        needs: Why this check cannot run on this tool's data ("" when it can). A check whose
            input was never recorded is reported as not checked, never as clear.
    """

    id: str
    check: str
    fn: ToolRuleFn
    needs: Callable[[ToolReport, RuleContext], str] = _always


@dataclass(frozen=True)
class HostRule:
    """A check spanning tools or the host."""

    id: str
    check: str
    fn: HostRuleFn


class Check(NamedTuple):
    """One checklist line: the signals a check returned, or why it could not run."""

    scope: str
    check: str
    found: list[Exposure]
    unchecked: str = ""


Checklist = list[Check]

LABELS = {
    "no-approval": "Approval prompts skipped",
    "instructions": "Instruction file steers the model",
    "connected-apps": "Token can use your connected apps",
    "shared": "Sessions on public share links",
    "keychain-silent": "Keychain token readable without a prompt",
    "creds-plaintext": "Credentials in plaintext",
    "live-token-on-disk": "Live credentials copied into data files",
    "secrets-at-rest": "Secret-shaped values in history and logs",
    "secrets": "Secret-shaped values in history and logs",
    "autostart": "Code that runs automatically",
    "daemons": "Background processes and listening sessions",
    "dangling": "Autostart command points at a missing file",
    "duplicate-installs": "Stale second install",
    "creds-readable": "Credentials readable by other accounts",
    "data-readable": "Data readable by other accounts",
    "open-server": "Local server without a password",
    "path-hijack": "Writable folders ahead of /usr/bin",
    "binary-dirs": "Tool launchers in writable folders",
    "other-accounts": "Other local accounts",
    "shared-surfaces": "One folder steers several tools",
    "duplicate-creds": "One provider's credentials in several places",
    "trust": "Trusted folders",
    "account-data": "Work shared with provider services",
    "remote-control": "Remote control is turned on",
    "unused-logins": "Logins kept but no longer used",
    "inherited-creds": "Other credentials an agent inherits",
    "computer-control": "Software that can drive the computer",
    "backups": "History copied into backups",
    "unattended": "Long-running or orphaned AI processes",
    "other-tools": "Other AI tools on this machine",
}


def label_for(rule_id: str) -> str:
    """Short label for a rule id; numbered ids (``dangling-2``) share their rule's label."""
    for key, label in sorted(LABELS.items(), key=lambda item: len(item[0]), reverse=True):
        if rule_id.startswith(key):
            return label
    return rule_id


def quote(path: str) -> str:
    """A path shell-quoted for a fix command."""
    return shlex.quote(path)


def exposure(
    report: ToolReport,
    rule_id: str,
    lens: Lens,
    statement: str,
    *,
    evidence: list[str] | None = None,
    fix: Fix | None = None,
) -> Exposure:
    """An exposure of the tool in ``report`` under ``rule_id``, labelled for the checklist."""
    return Exposure(
        id=f"{report.name}:{rule_id}",
        tool=report.name,
        lens=lens,
        statement=statement,
        label=label_for(rule_id),
        evidence=evidence or [],
        fix=fix,
    )
