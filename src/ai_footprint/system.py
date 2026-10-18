"""The only gateway through which the audit runs external commands.

Every probe is declared in ``PROBES`` with an absolute binary path, so the audit cannot be
PATH-hijacked the way a bare ``security`` call can. Every probe is read-only. Tool
binaries (claude, codex, opencode, pi) may only be run with ``--version`` or ``... --help``,
except that ``--capture`` launches each one idle, with no prompt, under a packet capture.
Anything else raises ``CommandRefusedError``. Every execution is logged so the report can
list exactly what the audit ran.
"""

import os
import pty
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ai_footprint.model import CheckResult, CommandValidation, ExecRecord

SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class CommandRefusedError(RuntimeError):
    """Raised when code asks to run something outside the probe registry."""


@dataclass(frozen=True)
class ProbeSpec:
    """A read-only system command the audit is allowed to run.

    Attributes:
        name: Registry key.
        candidates: Absolute paths to try in order; the first existing one is used.
        purpose: Why the audit needs it, shown in the report.
        platforms: ``sys.platform`` values the probe applies to.
        apple_signed: On macOS, require the binary to satisfy ``anchor apple``.
        env_passthrough: Variables copied from the user's environment (e.g. the ssh-agent
            socket); everything else is replaced by a fixed minimal environment.
    """

    name: str
    candidates: tuple[str, ...]
    purpose: str
    platforms: frozenset[str]
    apple_signed: bool = False
    env_passthrough: tuple[str, ...] = ()


_MAC = frozenset({"darwin"})
_ANY = frozenset({"darwin", "linux"})

PROBES: dict[str, ProbeSpec] = {
    spec.name: spec
    for spec in (
        ProbeSpec(
            "security",
            ("/usr/bin/security",),
            "Read Keychain item metadata; read token values into memory only, which also "
            "proves whether a silent read is possible",
            _MAC,
            apple_signed=True,
        ),
        ProbeSpec(
            "codesign",
            ("/usr/bin/codesign",),
            "Read code-signing identity of tool binaries; verify probe binaries",
            _MAC,
            apple_signed=True,
        ),
        ProbeSpec(
            "ps",
            ("/bin/ps", "/usr/bin/ps"),
            "List running AI-tool processes and their launch flags",
            _ANY,
            apple_signed=True,
        ),
        ProbeSpec(
            "lsof",
            ("/usr/sbin/lsof", "/usr/bin/lsof"),
            "List network sockets owned by AI-tool processes",
            _ANY,
            apple_signed=True,
        ),
        ProbeSpec(
            "dscl",
            ("/usr/bin/dscl",),
            "List local user accounts",
            _MAC,
            apple_signed=True,
        ),
        ProbeSpec(
            "id",
            ("/usr/bin/id",),
            "List group membership of other local accounts",
            _ANY,
            apple_signed=True,
        ),
        ProbeSpec(
            "tmutil",
            ("/usr/bin/tmutil",),
            "Check whether AI-tool folders are included in Time Machine backups",
            _MAC,
            apple_signed=True,
        ),
        ProbeSpec(
            "ssh-add",
            ("/usr/bin/ssh-add",),
            "Count keys loaded in ssh-agent (`ssh-add -l` prints fingerprints only)",
            _ANY,
            apple_signed=True,
            env_passthrough=("SSH_AUTH_SOCK",),
        ),
        ProbeSpec(
            "sudo",
            ("/usr/bin/sudo",),
            "Start the packet capture as root (--capture only; asks for your password)",
            _MAC,
            apple_signed=True,
        ),
        ProbeSpec(
            "tcpdump",
            ("/usr/sbin/tcpdump",),
            "Record packets with their owning process (--capture), then read the file back",
            _MAC,
            apple_signed=True,
        ),
        ProbeSpec(
            "sh",
            ("/bin/sh",),
            "Syntax-check fix commands with `sh -n` (parses, never executes)",
            _ANY,
            apple_signed=True,
        ),
    )
}

TOOL_ARG_FORMS = ("--version", "--help")


@dataclass
class ProbeResult:
    """Captured output of one probe."""

    returncode: int
    stdout: str
    stderr: str


class System:
    """Runs registered probes and logs every execution.

    Tests subclass this and override ``_execute`` so no real process is spawned.
    """

    def __init__(
        self,
        *,
        platform: str = sys.platform,
        env: Mapping[str, str] | None = None,
        verify_signatures: bool = True,
    ) -> None:
        self.platform = platform
        self.env = dict(os.environ if env is None else env)
        self.verify_signatures = verify_signatures and platform == "darwin"
        self.executed: list[ExecRecord] = []
        self._resolved: dict[str, str] = {}
        self._signature_ok: dict[str, bool] = {}

    def has_probe(self, name: str) -> bool:
        """True when the probe exists for this platform and its binary is present."""
        spec = PROBES.get(name)
        if spec is None or self.platform not in spec.platforms:
            return False
        return self._find_binary(spec) is not None

    def run(
        self,
        name: str,
        args: Sequence[str],
        *,
        stdin: str | None = None,
        timeout: float = 30,
        log: bool = True,
    ) -> ProbeResult:
        """Run a registered probe by absolute path.

        Args:
            name: Key in ``PROBES``.
            args: Arguments after the binary.
            stdin: Optional text fed to the process.
            timeout: Seconds before the process is killed.
            log: False for a probe repeated in a loop; the caller records it once with
                ``note``.

        Returns:
            The captured result.

        Raises:
            CommandRefusedError: The probe is unknown, unavailable, or fails its signature check.
        """
        binary = self._require_probe(name)
        extra = {k: self.env[k] for k in PROBES[name].env_passthrough if k in self.env}
        if not log:
            return self._execute([binary, *args], stdin, timeout, extra)
        return self._record([binary, *args], PROBES[name].purpose, stdin, timeout, extra)

    def probe_path(self, name: str) -> str:
        """Absolute path of a registered probe, after its signature check.

        Raises:
            CommandRefusedError: The probe is unknown, unavailable, or fails its signature check.
        """
        return self._require_probe(name)

    def note(self, name: str, args: Sequence[str], purpose: str) -> None:
        """Record a probe that ran repeatedly unlogged, once, with why and how often."""
        binary = self._require_probe(name)
        self.executed.append(ExecRecord(argv=[binary, *args], returncode=0, purpose=purpose))

    def interactive(self, name: str, args: Sequence[str]) -> int:
        """Run a probe attached to this terminal (``sudo -v`` asking for a password)."""
        binary = self._require_probe(name)
        # argv[0] is an absolute path from PROBES.
        code = subprocess.call([binary, *args])  # noqa: S603
        self.executed.append(
            ExecRecord(argv=[binary, *args], returncode=code, purpose=PROBES[name].purpose)
        )
        return code

    def start(self, name: str, args: Sequence[str]) -> subprocess.Popen[bytes]:
        """Start a probe in the background (the packet capture) and record it."""
        binary = self._require_probe(name)
        self.executed.append(
            ExecRecord(argv=[binary, *args], returncode=0, purpose=PROBES[name].purpose)
        )
        # argv[0] is an absolute path from PROBES.
        return subprocess.Popen(  # noqa: S603
            [binary, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def launch_idle(
        self, binary: str, *, cwd: str, env: Mapping[str, str]
    ) -> tuple[subprocess.Popen[bytes], int]:
        """Start a tool binary with no arguments in a pseudo-terminal, for the capture.

        Returns:
            The process and the terminal's controller descriptor, which the caller drains
            and closes.

        Raises:
            CommandRefusedError: ``binary`` is not an absolute path to an executable file.
        """
        path = Path(binary)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise CommandRefusedError(f"refusing to launch {binary}: not an executable path")
        controller, terminal = pty.openpty()
        # binary is an absolute path to an installed tool, checked above.
        proc = subprocess.Popen(  # noqa: S603
            [binary],
            stdin=terminal,
            stdout=terminal,
            stderr=terminal,
            cwd=cwd,
            env=dict(env),
            start_new_session=True,
        )
        os.close(terminal)
        self.executed.append(
            ExecRecord(
                argv=[binary],
                returncode=0,
                purpose="Launch idle with no prompt while the packet capture runs",
            )
        )
        return proc, controller

    def run_tool(self, binary: str, args: Sequence[str], *, timeout: float = 30) -> ProbeResult:
        """Run an AI tool binary, limited to ``--version`` or ``<subcommand...> --help``.

        Raises:
            CommandRefusedError: The arguments are not a version or help request.
        """
        if not args or args[-1] not in TOOL_ARG_FORMS:
            raise CommandRefusedError(
                f"refusing to run {binary} {' '.join(args)}: only --version or --help allowed"
            )
        if args[-1] == "--version" and len(args) != 1:
            raise CommandRefusedError(
                f"refusing {binary} {' '.join(args)}: --version takes no args"
            )
        if any(arg.startswith("-") for arg in args[:-1]):
            raise CommandRefusedError(f"refusing {binary} {' '.join(args)}: flags before --help")
        purpose = "Confirm tool version" if args[-1] == "--version" else "Confirm subcommand exists"
        return self._record([binary, *args], purpose, None, timeout)

    def validate_probes(self) -> list[CommandValidation]:
        """Check every probe for this platform: binary present, executable, signature valid."""
        results = []
        for spec in PROBES.values():
            if self.platform not in spec.platforms:
                continue
            results.append(self._validate_probe(spec))
        return results

    def _validate_probe(self, spec: ProbeSpec) -> CommandValidation:
        validation = CommandValidation(command=f"{spec.name}: {spec.purpose}")
        binary = self._find_binary(spec)
        found = binary is not None
        detail = binary or f"none of {', '.join(spec.candidates)} exist"
        validation.checks.append(CheckResult("absolute binary present", found, detail))
        if binary is None:
            return validation
        mode = Path(binary).stat().st_mode
        executable = bool(mode & stat.S_IXUSR)
        validation.checks.append(CheckResult("executable", executable, oct(mode & 0o777)))
        writable = bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
        validation.checks.append(
            CheckResult("not group/other writable", not writable, oct(mode & 0o777))
        )
        if spec.apple_signed and self.verify_signatures:
            ok = self._apple_signed(binary)
            validation.checks.append(CheckResult("Apple code signature", ok, "anchor apple"))
        return validation

    def _require_probe(self, name: str) -> str:
        spec = PROBES.get(name)
        if spec is None:
            raise CommandRefusedError(f"'{name}' is not a registered probe")
        if self.platform not in spec.platforms:
            raise CommandRefusedError(f"probe '{name}' does not apply to {self.platform}")
        binary = self._find_binary(spec)
        if binary is None:
            raise CommandRefusedError(f"probe '{name}' binary not found: {spec.candidates}")
        if spec.apple_signed and self.verify_signatures and not self._apple_signed(binary):
            raise CommandRefusedError(f"probe '{name}' at {binary} failed Apple signature check")
        return binary

    def _find_binary(self, spec: ProbeSpec) -> str | None:
        if spec.name in self._resolved:
            return self._resolved[spec.name]
        for candidate in spec.candidates:
            if Path(candidate).is_file():
                self._resolved[spec.name] = candidate
                return candidate
        return None

    def _apple_signed(self, binary: str) -> bool:
        if binary not in self._signature_ok:
            args = ["/usr/bin/codesign", "--verify", "-R=anchor apple", binary]
            result = self._record(args, "Verify probe binary is Apple-signed", None, 30)
            self._signature_ok[binary] = result.returncode == 0
        return self._signature_ok[binary]

    def _record(
        self,
        argv: list[str],
        purpose: str,
        stdin: str | None,
        timeout: float,
        extra_env: dict[str, str] | None = None,
    ) -> ProbeResult:
        result = self._execute(argv, stdin, timeout, extra_env or {})
        self.executed.append(
            ExecRecord(argv=_redact_argv(argv), returncode=result.returncode, purpose=purpose)
        )
        return result

    def _execute(
        self, argv: list[str], stdin: str | None, timeout: float, extra_env: Mapping[str, str]
    ) -> ProbeResult:
        env = {"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C", "HOME": self.env.get("HOME", "")}
        env.update(extra_env)
        try:
            # argv[0] is always an absolute path from PROBES or a resolved tool binary.
            proc = subprocess.run(  # noqa: S603
                argv,
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                check=False,
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return ProbeResult(124, "", f"timed out after {timeout}s")
        except OSError as exc:
            return ProbeResult(127, "", f"{type(exc).__name__}: {exc}")
        return ProbeResult(proc.returncode, proc.stdout, proc.stderr)

    def which_all(self, name: str) -> list[str]:
        """Every match for ``name`` on the user's PATH, in PATH order (like ``which -a``)."""
        found: list[str] = []
        for directory in self.env.get("PATH", "").split(os.pathsep):
            if not directory:
                continue
            candidate = Path(directory) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                text = str(candidate)
                if text not in found:
                    found.append(text)
        return found

    def which(self, name: str) -> str | None:
        """First match for ``name`` on the user's PATH."""
        return shutil.which(name, path=self.env.get("PATH", ""))


def _redact_argv(argv: list[str]) -> list[str]:
    """Hide the script body of `sh -n -c <script>` probes beyond a short preview."""
    if len(argv) >= 4 and argv[1:3] == ["-n", "-c"]:
        preview = argv[3].replace("\n", " ⏎ ")
        return [*argv[:3], preview[:60] + ("…" if len(preview) > 60 else "")]
    return list(argv)
