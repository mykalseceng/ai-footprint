"""Plain answers to the questions a defender asks about one AI tool.

Every answer has the same shape: at most one sentence of text, then a table of values as
recorded when there is anything to list. Backtick spans mark paths and values; renderers
escape first, then turn the spans into code formatting.
"""

from collections import Counter
from dataclasses import dataclass, field

from ai_footprint import daemons
from ai_footprint.fsinfo import human_size, tilde
from ai_footprint.model import Artifact, Category, HostReport, TokenInfo, ToolReport
from ai_footprint.surface import plural, sentences, when

EVIDENCE = {
    "binary": "in the binary",
    "config": "configured",
    "credentials": "provider of a stored credential",
    "logs": "in local logs",
    "live-socket": "open now",
}


@dataclass
class Answer:
    """One question: at most one sentence of text, then a table when there is data to list."""

    question: str
    text: str = ""
    headers: tuple[str, ...] = ()
    rows: list[list[str]] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)


def _file_rows(artifacts: list[Artifact], home: str) -> list[list[str]]:
    ranked = sorted(artifacts, key=lambda a: a.size_bytes, reverse=True)
    return [
        [
            f"`{tilde(a.path, home)}`",
            human_size(a.size_bytes),
            f"{a.file_count:,}" if a.is_dir else "",
            _modified(a),
        ]
        for a in ranked
    ]


def _modified(artifact: Artifact) -> str:
    if artifact.oldest == artifact.newest:
        return artifact.newest
    return f"{artifact.oldest} to {artifact.newest}"


def _files_answer(question: str, artifacts: list[Artifact], home: str) -> Answer:
    if not artifacts:
        return Answer(question, "None found.")
    return Answer(question, "", ("Path", "Size", "Files", "Modified"), _file_rows(artifacts, home))


def _store_answer(tool: ToolReport, home: str) -> Answer:
    question = "Where is my auth token stored?"
    if not tool.credentials:
        return Answer(question, "No stored credentials were found.")
    silent = any("without a prompt" in c.protection for c in tool.credentials)
    return Answer(
        question,
        "This audit read the Keychain item without a prompt." if silent else "",
        ("Provider", "Store", "Location", "Other accounts can read"),
        [
            [
                c.provider,
                c.store,
                f"`{tilde(c.location, home)}`",
                "yes" if c.readable_by_others else "no",
            ]
            for c in tool.credentials
        ],
    )


def _signature(token: TokenInfo) -> str:
    if token.signature.startswith("present, not verified"):
        return "not verified (use --live)"
    if token.signature.startswith("none"):
        return "none (opaque)"
    return token.signature.split(",", 1)[0]


def _token_row(token: TokenInfo) -> list[str]:
    expiry = when(token.expires_at) if token.expires_at else "none recorded"
    if token.expired:
        expiry += " (expired)"
    if token.kind == "jwt":
        host = token.issuer.removeprefix("https://").rstrip("/")
        kind = f"JWT {token.algorithm} from `{host}`"
    else:
        kind = f"opaque `{token.prefix}` ({token.length} chars)"
    return [f"`{token.field}`", kind, expiry, ", ".join(token.scopes) or "none", _signature(token)]


def _expiry_answer(tool: ToolReport) -> Answer:
    question = "When does it expire, what claims does it carry, and who signs it?"
    tokens = [t for c in tool.credentials for t in c.tokens if t.field != "password"]
    if not tokens:
        return Answer(question, "No tokens to describe.")
    return Answer(
        question,
        "Claims are listed under Credentials in the inventory.",
        ("Token", "Type", "Expires", "Scopes", "Signature"),
        [_token_row(t) for t in tokens],
    )


def _readers(artifact: Artifact) -> str:
    if artifact.other_readable:
        return "any account"
    return f"group `{artifact.group_readable}`" if artifact.group_readable else ""


def _readers_answer(tool: ToolReport, host: HostReport) -> Answer:
    question = "Who can read these files?"
    accounts = (
        f"the other local accounts are {', '.join(host.other_users)}"
        if host.other_users
        else "no other local account exists today"
    )
    exposed = [a for a in tool.artifacts if _readers(a)]
    creds = [c for c in tool.credentials if c.readable_by_others]
    if not exposed and not creds:
        return Answer(
            question,
            f"No location it writes grants read access beyond your account, and {accounts}.",
        )
    stores = f", including {plural(len(creds), 'credential store')}," if creds else ""
    return Answer(
        question,
        f"{plural(len(exposed), 'location')}{stores} grant read access beyond your account, "
        f"and {accounts}.",
        ("Path", "Mode", "Readable by"),
        [[f"`{tilde(a.path, host.home)}`", a.mode, _readers(a)] for a in exposed],
    )


def _connections_answer(tool: ToolReport) -> Answer:
    question = "Which hosts does it name or connect to?"
    if not tool.endpoints:
        return Answer(question, "No endpoints recorded.")
    counts: Counter[tuple[str, str]] = Counter()
    for x in tool.endpoints:
        counts[(x.host, x.source)] += x.count
    rows = [
        [host, EVIDENCE.get(source, source), f"{count:,}" if count else ""]
        for (host, source), count in counts.items()
    ]
    return Answer(
        question,
        "Only rows marked open now are connections; the rest are names found in the binary, "
        "the config or local logs.",
        ("Host", "Evidence", "Count"),
        rows,
    )


def _signature_answer(tool: ToolReport) -> Answer:
    question = "What does it look like on the network?"
    if not tool.fingerprint:
        return Answer(question, "No signature traits were found in the installed binary.")
    binary = tool.binaries[0] if tool.binaries else None
    text = "Each trait was found in the installed binary"
    if binary and binary.signer.startswith("unsigned"):
        text += ", which is not code-signed."
    elif binary and binary.signer:
        text += f", which is signed by {binary.signer}."
    else:
        text += "."
    return Answer(
        question, text, ("Trait", "Value"), [[f.label, f"`{f.value}`"] for f in tool.fingerprint]
    )


def _instructions_answer(tool: ToolReport, home: str) -> Answer:
    question = "Which instruction files does it load, and what could they do?"
    if not tool.instructions:
        return Answer(question, "None found in the global location or in known project folders.")
    rows = [
        [
            f"`{tilde(i.path, home)}`",
            i.scope,
            ", ".join(i.loaded_by),
            "; ".join(i.markers) or "nothing flagged",
        ]
        for i in tool.instructions
    ]
    return Answer(question, "", ("File", "Scope", "Loaded by", "Flagged"), rows)


def _extensions_answer(tool: ToolReport) -> Answer:
    question = "Which skills, plugins and MCP servers are loaded?"
    if not tool.extensions:
        return Answer(question, "None.")
    counts = Counter(e.kind for e in tool.extensions)
    auto = Counter(e.kind for e in tool.extensions if e.autostart)
    return Answer(
        question,
        "What each one says it does is on the pages linked below.",
        ("Kind", "Count", "Start automatically"),
        [[kind, str(n), str(auto[kind])] for kind, n in counts.most_common()],
        links=[("mcp", "MCP servers"), ("skills", "Skills"), ("plugins", "Plugins")],
    )


def _daemons_answer(tool: ToolReport, home: str) -> Answer:
    question = "What does it keep running in the background?"
    if not tool.daemons:
        return Answer(question, "No process of this tool is detached from a session or listening.")
    rows = []
    for d in tool.daemons:
        what, listens, notes = daemons.describe(d, home)
        rows.append(
            [
                str(d.pid),
                daemons.running(d),
                "; ".join(listens) or "nothing",
                f"`{what}`",
                "; ".join(notes) or "—",
            ]
        )
    return Answer(question, "", ("PID", "Running", "Listens on", "Runs", "Notes"), rows)


def _program_answer(tool: ToolReport) -> Answer:
    question = "Am I in the provider's trusted-access program?"
    if not tool.programs:
        return Answer(question, "Not applicable to this tool.")
    return Answer(
        question,
        "",
        ("Program", "Status", "Evidence"),
        [[p.name, p.status, p.evidence[0]] for p in tool.programs],
    )


def _notes(tool: ToolReport, question: str, topic: str, fallback: str) -> Answer:
    rows = [
        [fact, n.source] for n in tool.account if n.topic == topic for fact in sentences(n.text)
    ]
    return Answer(question, "", ("Fact", "Source"), rows) if rows else Answer(question, fallback)


def _trust_answer(tool: ToolReport, home: str) -> Answer:
    question = "What does my trust list let a cloned repo do?"
    if not tool.trusted_folders:
        return Answer(question, "This tool keeps no trusted-folder list, or none are trusted.")
    count = len(tool.trusted_folders)
    return Answer(
        question,
        f"{plural(count, 'folder')} {'is' if count == 1 else 'are'} trusted.",
        ("Trusted folder",),
        [[f"`{tilde(f, home)}`"] for f in tool.trusted_folders],
    )


def _dated(answer: Answer) -> Answer:
    answer.text = when(answer.text)
    answer.rows = [[when(cell) for cell in row] for row in answer.rows]
    return answer


def for_tool(tool: ToolReport, host: HostReport) -> list[Answer]:
    """Answers for one tool, in the order a defender asks the questions."""
    return [_dated(answer) for answer in _answers(tool, host)]


def _answers(tool: ToolReport, host: HostReport) -> list[Answer]:
    home = host.home
    logs = [a for a in tool.artifacts if a.category is Category.LOG]
    sessions = [a for a in tool.artifacts if a.category is Category.SESSION]
    return [
        _files_answer("Where are the log files?", logs, home),
        _files_answer("Where are my sessions stored?", sessions, home),
        _store_answer(tool, home),
        _expiry_answer(tool),
        _readers_answer(tool, host),
        _connections_answer(tool),
        _signature_answer(tool),
        _instructions_answer(tool, home),
        _extensions_answer(tool),
        _daemons_answer(tool, home),
        _program_answer(tool),
        _trust_answer(tool, home),
        _notes(
            tool,
            "Is my data used for training, and what is copied to the cloud?",
            "data",
            "No local evidence either way; check the provider's data settings.",
        ),
        _notes(
            tool,
            "How do I revoke this token, and how would I prove it?",
            "revoke",
            "Revoke at the provider and confirm the old token is rejected.",
        ),
        _notes(
            tool,
            "Would I notice if someone else used it?",
            "detect",
            "Nothing on disk records use elsewhere; check the provider's session list.",
        ),
    ]


HOST_QUESTIONS = (
    (
        "reach",
        "What else can an agent running as me use?",
        "host:inherited-creds",
        "No other credentials were found in the usual places.",
    ),
    (
        "control",
        "What can drive this computer besides the terminal?",
        "host:computer-control",
        "No browser bridges, computer-use helpers or privacy grants were found.",
    ),
    (
        "backup",
        "Where else do copies of my history exist?",
        "host:backups",
        "Time Machine is not available, so no backup copies were checked.",
    ),
    (
        "unattended",
        "What runs when I'm not there?",
        "host:unattended",
        "No orphaned MCP servers, AI-tool processes running a day or more, or AI login items.",
    ),
    (
        "other-tools",
        "What about AI tools this audit doesn't cover?",
        "host:other-tools",
        "None found.",
    ),
)
"""(topic, question, id of the finding built from that topic's facts, answer when none)."""
