"""Turn collected facts into plain statements of exposure, each with a validated fix.

There are no severity ratings. Each exposure is filed under the attacker position it serves
(``Lens``): a stolen token, code running as you, text steering the model, or another local
account. Each rule also has a checklist title, so ``--doctor`` can say which checks are clear.
Fix commands carry the hints the validator needs: ``--help`` probes that prove a subcommand
exists, and binary markers that prove a recommended config key is real.
"""

from ai_footprint.checks import (
    local_code,
    machine,
    needs,
    other_accounts,
    provider_copies,
    steering,
    stolen_token,
)
from ai_footprint.checks.base import Check, Checklist, HostRule, Rule, RuleContext
from ai_footprint.checks.steering import approval_keys
from ai_footprint.model import AuditReport

__all__ = [
    "HOST_RULES",
    "TOOL_RULES",
    "Check",
    "Checklist",
    "RuleContext",
    "approval_keys",
    "evaluate",
]

TOOL_RULES: tuple[Rule, ...] = (
    Rule(
        "no-approval",
        "Approval not turned off by a recorded setting",
        steering.rule_no_approval,
        needs.needs_approval_setting,
    ),
    Rule(
        "instructions",
        "Instruction files contain nothing that steers the model",
        steering.rule_instructions,
    ),
    Rule(
        "token-reach",
        "Token carries no connector scopes",
        stolen_token.rule_token_reach,
        needs.needs_scopes,
    ),
    Rule(
        "shared",
        "No sessions published to share links",
        stolen_token.rule_shared_sessions,
        needs.needs_share_setting,
    ),
    Rule(
        "keychain-silent",
        "Keychain item requires a prompt",
        local_code.rule_keychain_silent,
        needs.needs_keychain,
    ),
    Rule(
        "creds-plaintext",
        "Credentials in an OS-protected store",
        local_code.rule_plaintext_credentials,
        needs.needs_credentials,
    ),
    Rule(
        "secrets",
        "No secrets in history or logs (full audit only)",
        local_code.rule_secrets,
        needs.needs_scan,
    ),
    Rule(
        "dangling",
        "No MCP server command points at a missing file",
        local_code.rule_dangling,
        needs.needs_local_mcp,
    ),
    Rule("autostart", "No automatic code execution points", local_code.rule_autostart),
    Rule(
        "daemons",
        "No process outlives its session or accepts connections from other accounts or the network",
        local_code.rule_daemons,
    ),
    Rule("duplicate-installs", "One install per tool", local_code.rule_duplicate_installs),
    Rule(
        "creds-readable",
        "Credentials not readable by other accounts",
        other_accounts.rule_credentials_exposed,
        needs.needs_credentials,
    ),
    Rule(
        "data-readable",
        "Data stores not readable by other accounts",
        other_accounts.rule_exposed_data,
        needs.needs_other_accounts,
    ),
    Rule(
        "open-server",
        "Local server requires authentication",
        other_accounts.rule_open_server,
        needs.needs_local_server,
    ),
    Rule(
        "trust",
        "No broad trusted folders and none holding instruction files",
        steering.rule_trust,
        needs.needs_trusted_folders,
    ),
    Rule(
        "account-data",
        "Provider keeps no extra copies (training, cloud tasks)",
        provider_copies.rule_account_data,
        needs.needs_data_notes,
    ),
    Rule(
        "account-signals",
        "No paired devices or unused stored logins",
        stolen_token.rule_account_signals,
        needs.needs_signal_source,
    ),
)


HOST_RULES: tuple[HostRule, ...] = (
    HostRule(
        "path-hijack",
        "PATH folders ahead of system dirs are not writable by others",
        machine.rule_path_hijack,
    ),
    HostRule(
        "binary-dirs", "Tool binaries are in folders only you can write", machine.rule_binary_dirs
    ),
    HostRule("other-accounts", "No other local accounts", machine.rule_other_accounts),
    HostRule(
        "shared-surfaces",
        "No skill or instruction file shared across tools",
        machine.rule_shared_surfaces,
    ),
    HostRule(
        "duplicate-creds", "Each provider credential stored once", machine.rule_duplicate_providers
    ),
    HostRule("inherited-creds", "Agents inherit no other credentials", machine.rule_inherited),
    HostRule("computer-control", "Nothing else can drive the computer", machine.rule_control),
    HostRule("backups", "AI-tool history is not copied into backups", machine.rule_backups),
    HostRule("unattended", "No long-running or orphaned AI processes", machine.rule_unattended),
    HostRule("other-tools", "No other AI tools keep data here", machine.rule_other_tools),
)


def evaluate(audit: AuditReport, ctx: RuleContext) -> Checklist:
    """Run every rule, attach exposures to the audit, and return the checklist.

    Every rule runs, so nothing it finds is hidden; a rule that finds nothing because its input
    was never recorded is marked not checked, with the reason.

    Returns:
        One ``Check`` per rule and tool, for the doctor view.
    """
    checklist: Checklist = []
    for tool in audit.tools:
        if not tool.installed:
            continue
        for rule in TOOL_RULES:
            found = rule.fn(tool, ctx)
            tool.exposures.extend(found)
            unchecked = "" if found else rule.needs(tool, ctx)
            checklist.append(Check(tool.display_name, rule.check, found, unchecked))
    for rule in HOST_RULES:
        found = rule.fn(audit, ctx)
        audit.host_exposures.extend(found)
        checklist.append(Check("Host", rule.check, found))
    return checklist
