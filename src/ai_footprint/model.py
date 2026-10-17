"""Data model for an AI-tool footprint audit.

Every collector fills these dataclasses; every renderer reads them. Nothing in here ever
holds a secret value: tokens are reduced to metadata and a short fingerprint first.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class Lens(StrEnum):
    """The attacker position an exposure belongs to."""

    REMOTE = "remote"
    CODE = "code"
    MODEL = "model"
    ACCOUNT = "account"
    COPIES = "copies"

    @property
    def title(self) -> str:
        """Heading used in reports."""
        return {
            Lens.REMOTE: "From anywhere, with a stolen token",
            Lens.CODE: "Running as you on this machine",
            Lens.MODEL: "Through the model",
            Lens.ACCOUNT: "From another account on this machine",
            Lens.COPIES: "From copies kept elsewhere",
        }[self]

    @property
    def question(self) -> str:
        """The question each lens answers."""
        return {
            Lens.REMOTE: "What does a copied credential unlock, and for how long?",
            Lens.CODE: "What can malware or a hijacked session take or leave behind?",
            Lens.MODEL: "What happens when text the tool reads tells it what to do?",
            Lens.ACCOUNT: "What can other users of this machine read or plant?",
            Lens.COPIES: "Where else does this data live, outside your control?",
        }[self]


class Category(StrEnum):
    """What kind of data a file or directory holds."""

    CREDENTIAL = "credential"
    SESSION = "session"
    LOG = "log"
    CONFIG = "config"
    INSTRUCTIONS = "instructions"
    EXTENSION = "extension"
    CACHE = "cache"
    BINARY = "binary"


@dataclass(frozen=True)
class FixCommand:
    """One remediation step shown to the user.

    Attributes:
        text: Shell text exactly as printed, or a plain-language step when ``manual``.
        manual: True for steps done in a UI; these skip shell validation.
        help_probe: Argv (tool name first) whose ``--help`` must succeed, proving the
            subcommand exists in the installed version, e.g. ``("claude", "mcp", "remove")``.
        markers: Strings that must appear in the named tool's binary, proving a
            recommended config key or flag is real.
        marker_tool: Tool whose binary is searched for ``markers``.
    """

    text: str
    manual: bool = False
    help_probe: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    marker_tool: str = ""


@dataclass
class CheckResult:
    """Outcome of one validation check on a command."""

    name: str
    passed: bool
    detail: str


@dataclass
class CommandValidation:
    """All checks run against one fix command."""

    command: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when every check passed."""
        return all(check.passed for check in self.checks)


@dataclass
class Fix:
    """A remediation: a summary plus the commands that carry it out."""

    summary: str
    commands: list[FixCommand] = field(default_factory=list)
    validations: list[CommandValidation] = field(default_factory=list)


@dataclass
class Exposure:
    """One concrete way in, stated plainly, with evidence and how to close it."""

    id: str
    tool: str
    lens: Lens
    statement: str
    label: str = ""
    evidence: list[str] = field(default_factory=list)
    fix: Fix | None = None


@dataclass
class Artifact:
    """A file or directory a tool writes, with size and effective permissions."""

    label: str
    path: str
    category: Category
    description: str
    exists: bool = False
    is_dir: bool = False
    size_bytes: int = 0
    file_count: int = 0
    mode: str = ""
    owner: str = ""
    other_readable: bool = False
    group_writable: bool = False
    other_writable: bool = False
    oldest: str = ""
    newest: str = ""


@dataclass
class TokenInfo:
    """Non-secret metadata about one credential value.

    Attributes:
        last4: Last four characters of a value of 20 or more characters that is not a JWT,
            so a key can be matched to the provider console when rotating it; empty
            otherwise.
    """

    field: str
    kind: str
    description: str
    prefix: str
    length: int
    fingerprint: str
    last4: str = ""
    issuer: str = ""
    audience: str = ""
    algorithm: str = ""
    key_id: str = ""
    issued_at: str = ""
    expires_at: str = ""
    expired: bool | None = None
    scopes: list[str] = field(default_factory=list)
    claims: dict[str, str] = field(default_factory=dict)
    signature: str = "not applicable"


@dataclass
class Credential:
    """Where a tool keeps a credential and how well it is protected.

    Attributes:
        owner: The account the credential belongs to, when a file on disk records it.
        owner_source: The file and field ``owner`` was read from.
    """

    tool: str
    provider: str
    store: str
    location: str
    protection: str
    readable_by_others: bool = False
    tokens: list[TokenInfo] = field(default_factory=list)
    live_check: str = ""
    owner: str = ""
    owner_source: str = ""


@dataclass
class Extension:
    """Anything that adds code or instructions to a tool: MCP, plugin, skill, hook.

    Attributes:
        description: What the item says about itself (its own manifest or frontmatter),
            cut to two sentences. Empty when nothing on disk describes it.
        access: Tool access it declares (a skill's ``allowed-tools``), or the transport an
            MCP server uses. Empty when nothing is declared.
        identity: What makes two entries the same thing (resolved path, URL or command),
            so a skill folder reached from several tools is listed once.
    """

    tool: str
    kind: str
    name: str
    source: str
    detail: str
    autostart: bool = False
    dangling: bool = False
    notes: str = ""
    description: str = ""
    access: str = ""
    identity: str = ""


@dataclass
class InstructionFile:
    """A CLAUDE.md / AGENTS.md style file that is fed to the model as instructions."""

    path: str
    scope: str
    loaded_by: list[str]
    size_bytes: int = 0
    mode: str = ""
    other_readable: bool = False
    markers: list[str] = field(default_factory=list)


@dataclass
class Endpoint:
    """A network destination a tool talks to."""

    tool: str
    host: str
    purpose: str
    source: str
    count: int = 0


@dataclass
class FingerprintItem:
    """One trait of a tool's network or process signature, found in the installed binary."""

    label: str
    value: str


@dataclass
class BinaryInfo:
    """An installed executable for a tool."""

    path: str
    resolved: str
    version: str = ""
    signer: str = ""
    team_id: str = ""
    owner: str = ""
    mode: str = ""
    writable_dirs: list[str] = field(default_factory=list)


@dataclass
class ToolPresence:
    """Whether a tool is installed, found without running a full audit."""

    name: str
    display_name: str
    installed: bool
    binaries: list[BinaryInfo] = field(default_factory=list)
    data_paths: list[str] = field(default_factory=list)
    size_bytes: int = 0


@dataclass
class ProcessInfo:
    """A running process that belongs to a tool."""

    pid: int
    started: str
    command: str
    ppid: int = 0


@dataclass
class Listener:
    """A socket a process accepts connections on."""

    kind: str
    address: str
    mode: str = ""


@dataclass
class Daemon:
    """A tool process that outlives a session or accepts connections.

    Attributes:
        detached: Parent is launchd (pid 1): no terminal session owns it.
        days: Whole days since it started.
        notes: Observed facts: a copied binary, a self-updating loop, a version mismatch.
    """

    pid: int
    ppid: int
    started: str
    command: str
    binary: str
    detached: bool
    days: int
    listeners: list[Listener] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class AccountNote:
    """Local evidence about a provider-account setting or event."""

    topic: str
    text: str
    source: str
    concern: bool = False


@dataclass
class HostFact:
    """One observation about the machine around the tools (reach, control, backups...)."""

    topic: str
    name: str
    detail: str
    path: str = ""
    concern: bool = False


@dataclass
class Setting:
    """A configuration value that matters for exposure."""

    key: str
    value: str
    note: str
    concern: bool = False


@dataclass
class ProgramStatus:
    """Enrollment evidence for a provider's trusted-access program."""

    name: str
    status: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class SecretKindSummary:
    """Scan results for one secret type, as counts and locations only."""

    kind: str
    label: str
    unique: int
    files: int
    locations: list[str] = field(default_factory=list)
    last4: list[str] = field(default_factory=list)


@dataclass
class MarkerHit:
    """Occurrences of a literal marker string, e.g. a provider refusal code."""

    marker: str
    label: str
    count: int
    file_count: int = 0
    files: list[str] = field(default_factory=list)


@dataclass
class SecretScan:
    """Summary of a full scan of a tool's data stores."""

    roots: list[str]
    files_scanned: int = 0
    bytes_scanned: int = 0
    seconds: float = 0.0
    unreadable: list[str] = field(default_factory=list)
    kinds: list[SecretKindSummary] = field(default_factory=list)
    current_credential_hits: list[str] = field(default_factory=list)
    current_credential_values: int = 0
    markers: list[MarkerHit] = field(default_factory=list)


@dataclass
class ToolReport:
    """Everything found for one AI tool."""

    name: str
    display_name: str
    installed: bool = False
    binaries: list[BinaryInfo] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    instructions: list[InstructionFile] = field(default_factory=list)
    extensions: list[Extension] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    fingerprint: list[FingerprintItem] = field(default_factory=list)
    settings: list[Setting] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    daemons: list[Daemon] = field(default_factory=list)
    programs: list[ProgramStatus] = field(default_factory=list)
    account: list[AccountNote] = field(default_factory=list)
    trusted_folders: list[str] = field(default_factory=list)
    stats: dict[str, str] = field(default_factory=dict)
    secret_scan: SecretScan | None = None
    exposures: list[Exposure] = field(default_factory=list)

    def versions(self) -> list[str]:
        """Every distinct installed version, in PATH order."""
        return list(dict.fromkeys(b.version for b in self.binaries if b.version))


@dataclass
class PathEntry:
    """One directory on PATH and who can write to it."""

    index: int
    path: str
    exists: bool
    owner: str = ""
    group: str = ""
    mode: str = ""
    group_writable: bool = False
    other_writable: bool = False


@dataclass
class ExecRecord:
    """One external command the audit itself executed."""

    argv: list[str]
    returncode: int
    purpose: str


@dataclass
class HostReport:
    """Facts about the machine and account the audit ran on."""

    os: str
    kernel: str
    arch: str
    hostname: str
    user: str
    uid: int
    home: str
    home_mode: str
    other_users: list[str] = field(default_factory=list)
    other_user_groups: dict[str, list[str]] = field(default_factory=dict)
    path_entries: list[PathEntry] = field(default_factory=list)
    facts: list[HostFact] = field(default_factory=list)


@dataclass
class AuditReport:
    """The full audit: host, every tool, host-level exposures, and provenance."""

    generated_at: str
    auditor_version: str
    host: HostReport
    tools: list[ToolReport]
    host_exposures: list[Exposure] = field(default_factory=list)
    live: bool = False
    scanned: bool = False
    executed: list[ExecRecord] = field(default_factory=list)
    probe_validation: list[CommandValidation] = field(default_factory=list)
    option_validation: list[CommandValidation] = field(default_factory=list)
    claim_validation: list[CommandValidation] = field(default_factory=list)
    report_validation: list[CommandValidation] = field(default_factory=list)
    figure_validation: list[CommandValidation] = field(default_factory=list)

    def all_exposures(self) -> list[Exposure]:
        """Every exposure across tools and the host, grouped by lens in a fixed order."""
        found = [x for tool in self.tools for x in tool.exposures] + list(self.host_exposures)
        order = list(Lens)
        return sorted(found, key=lambda x: order.index(x.lens))
