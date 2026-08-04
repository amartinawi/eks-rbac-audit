"""The single subprocess chokepoint, with the read-only guarantee enforced in code.

Every command the auditor runs against a cluster passes through ``Runner.run``,
which validates the kubectl verb against an allowlist before spawning anything.
A mutating verb raises :class:`ReadOnlyViolation` rather than executing — the
guarantee is a code path, not a promise in the README.

Two commands mutate local state but never the cluster: installing krew plugins
(writes ``~/.krew``) and ``kubectl config use-context`` (writes ``~/.kube/config``).
Those go through ``Runner.run_local``, which is separately gated and marks the
command record so the report can show exactly what touched the machine.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence

from .config import DEFAULT_TIMEOUT_SECONDS
from .models import CommandRecord


class ReadOnlyViolation(RuntimeError):
    """Raised when a command would mutate cluster state."""


class ClusterUnreachable(RuntimeError):
    """Raised when the cluster cannot be contacted at all."""


class ToolMissing(RuntimeError):
    """Raised when the kubectl binary is not on PATH."""


# --------------------------------------------------------------------------- #
# Allowlist
# --------------------------------------------------------------------------- #
# kubectl verbs that only read. `auth` and `config` are narrowed further below
# because each has both reading and mutating subcommands.
ALLOWED_VERBS = frozenset(
    {
        "get",
        "version",
        "cluster-info",
        "api-resources",
        "api-versions",
        "explain",
        "auth",
        "config",
        # krew plugins invoked as `kubectl <plugin>`; both are pure queries.
        "rbac-lookup",
        "who-can",
    }
)

# `kubectl auth can-i` asks the API server a question. `kubectl auth reconcile`
# writes RBAC objects, so only `can-i` is permitted.
ALLOWED_AUTH_SUBCOMMANDS = frozenset({"can-i"})

# `kubectl config view` / `current-context` / `get-contexts` read the kubeconfig.
# `use-context`, `set-*`, `delete-*` write it and are excluded here; the opt-in
# context switch goes through `run_local` instead.
ALLOWED_CONFIG_SUBCOMMANDS = frozenset({"view", "current-context", "get-contexts"})

# Local-only commands permitted through `run_local`, keyed by verb.
LOCAL_VERBS = frozenset({"krew", "config"})


def _krew_bin() -> str:
    """Directory holding krew-installed plugins (`kubectl-who_can`, etc.)."""
    root = os.environ.get("KREW_ROOT") or os.path.join(os.path.expanduser("~"), ".krew")
    return os.path.join(root, "bin")


def _plugin_env() -> dict[str, str]:
    """A copy of the environment with the krew bin directory on PATH.

    krew installs plugins to ``~/.krew/bin`` but does not put that directory on
    PATH for non-login shells, so ``kubectl who-can`` fails without this even
    when the plugin is installed.
    """
    env = dict(os.environ)
    krew = _krew_bin()
    path = env.get("PATH", "")
    if krew not in path.split(os.pathsep):
        env["PATH"] = os.pathsep.join([krew, path]) if path else krew
    return env


@dataclass(frozen=True)
class CommandResult:
    """The outcome of one executed command."""

    label: str
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def display(self) -> str:
        return shlex.join(self.argv)


def assert_read_only(args: Sequence[str]) -> None:
    """Raise :class:`ReadOnlyViolation` unless ``args`` is a pure read.

    ``args`` is the kubectl argument list *without* the ``kubectl`` binary.
    """
    if not args:
        raise ReadOnlyViolation("refusing to run kubectl with no arguments")

    verb = args[0]
    if verb not in ALLOWED_VERBS:
        raise ReadOnlyViolation(
            f"'kubectl {verb}' is not on the read-only allowlist; "
            f"this auditor never creates, updates, patches, or deletes cluster state"
        )

    if verb == "auth":
        sub = args[1] if len(args) > 1 else ""
        if sub not in ALLOWED_AUTH_SUBCOMMANDS:
            raise ReadOnlyViolation(
                f"'kubectl auth {sub}' is not read-only; only 'auth can-i' is permitted"
            )

    if verb == "config":
        sub = args[1] if len(args) > 1 else ""
        if sub not in ALLOWED_CONFIG_SUBCOMMANDS:
            raise ReadOnlyViolation(
                f"'kubectl config {sub}' writes the kubeconfig; "
                f"use run_local() for the opt-in context switch"
            )


class Runner:
    """Executes read-only kubectl commands and records what it ran.

    The recorded command log is the only mutable state: it is an append-only
    accumulator owned by this object and exposed as an immutable tuple. Callers
    never mutate it.
    """

    def __init__(
        self,
        context: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        allow_local_writes: bool = False,
        binary: str = "kubectl",
    ) -> None:
        self._context = context
        self._timeout = timeout
        self._allow_local_writes = allow_local_writes
        self._binary = binary
        self._records: list[CommandRecord] = []

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    @property
    def context(self) -> Optional[str]:
        return self._context

    def commands(self) -> tuple[CommandRecord, ...]:
        """Everything executed so far, in order, for the methodology section."""
        return tuple(self._records)

    def resolve_binary(self) -> str:
        """Return the absolute kubectl path, raising if it is missing."""
        found = shutil.which(self._binary, path=_plugin_env()["PATH"])
        if not found:
            raise ToolMissing(
                f"'{self._binary}' was not found on PATH. Install kubectl and retry."
            )
        return found

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #
    def run(
        self,
        label: str,
        args: Sequence[str],
        with_context: bool = True,
        note: str = "",
    ) -> CommandResult:
        """Run a read-only kubectl command.

        The context is passed as ``--context`` on every invocation rather than
        switched globally, so the operator's kubeconfig is never modified and
        two audits can run concurrently.
        """
        assert_read_only(args)
        argv = [self.resolve_binary(), *args]
        if with_context and self._context:
            argv.extend(["--context", self._context])
        return self._execute(label, argv, note)

    def run_local(self, label: str, args: Sequence[str], note: str = "") -> CommandResult:
        """Run a command that writes local state (krew install, context switch).

        Never touches cluster state. Requires ``allow_local_writes``.
        """
        if not args or args[0] not in LOCAL_VERBS:
            raise ReadOnlyViolation(f"'kubectl {' '.join(args)}' is not a permitted local command")
        if not self._allow_local_writes:
            raise ReadOnlyViolation(
                f"local writes are disabled; refusing to run 'kubectl {' '.join(args)}'"
            )
        argv = [self.resolve_binary(), *args]
        return self._execute(label, argv, note or "modifies local machine state only")

    def run_external(self, label: str, argv: Sequence[str], note: str = "") -> CommandResult:
        """Run a non-kubectl read-only command (used for the AWS CLI).

        The caller is responsible for passing a read-only command; the AWS side
        is restricted to ``describe-*`` / ``list-*`` by :mod:`eksaudit.eksapi`.
        """
        return self._execute(label, list(argv), note)

    def _execute(self, label: str, argv: Sequence[str], note: str) -> CommandResult:
        argv = list(argv)
        try:
            completed = subprocess.run(  # noqa: S603 - argv is built from an allowlist
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env=_plugin_env(),
                check=False,
            )
            result = CommandResult(
                label=label,
                argv=tuple(argv),
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        except subprocess.TimeoutExpired:
            result = CommandResult(
                label=label,
                argv=tuple(argv),
                returncode=124,
                stdout="",
                stderr=f"timed out after {self._timeout}s",
                timed_out=True,
            )
        except FileNotFoundError as exc:
            result = CommandResult(
                label=label,
                argv=tuple(argv),
                returncode=127,
                stdout="",
                stderr=str(exc),
            )

        self._records.append(
            CommandRecord(
                label=label,
                command=_redact(result.display),
                exit_code=result.returncode,
                note=note,
            )
        )
        return result


def _redact(command: str) -> str:
    """Strip the absolute binary path so recorded commands read cleanly.

    ``/usr/local/bin/kubectl get pods`` becomes ``kubectl get pods``.
    """
    parts = command.split(" ", 1)
    head = os.path.basename(parts[0])
    return head if len(parts) == 1 else f"{head} {parts[1]}"
