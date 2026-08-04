"""Read-only collection of everything the audit needs, dumped to a work directory.

Mirrors the reference ``gather.sh`` in coverage, but every command goes through
:class:`eksaudit.kubectl.Runner` so the read-only allowlist applies, and each
command's stdout/stderr is written to ``<label>.out`` / ``<label>.err`` in the
work directory for forensics (``--keep-data``).

A failed command is never fatal except for the cluster-reachability probe: the
real world produces partial results (a missing plugin, a webhook authorizer that
cannot enumerate rules, an API group the caller cannot list), and an audit that
aborts on the first such case is useless.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from .kubectl import ClusterUnreachable, CommandResult, Runner
from .tooling import ToolingStatus

# label -> kubectl arguments, for the plain `get ... -o json` dumps.
RESOURCE_DUMPS = (
    ("crb", ["get", "clusterrolebindings", "-o", "json"]),
    ("cr", ["get", "clusterroles", "-o", "json"]),
    ("rb", ["get", "rolebindings", "--all-namespaces", "-o", "json"]),
    ("r", ["get", "roles", "--all-namespaces", "-o", "json"]),
    ("sa", ["get", "serviceaccounts", "--all-namespaces", "-o", "json"]),
    ("ns", ["get", "namespaces", "-o", "json"]),
)

# label -> who-can arguments. who-can does not resolve pod subresources, so the
# pods/exec answer here is treated as a hint only; authoritative exec rights are
# read from the ClusterRole rules in analyze.py.
WHO_CAN_QUERIES = (
    ("whocan-all", ["who-can", "*", "*"]),
    ("whocan-secrets", ["who-can", "get", "secrets", "--all-namespaces"]),
    ("whocan-pods", ["who-can", "create", "pods", "--all-namespaces"]),
    ("whocan-exec", ["who-can", "create", "pods/exec", "--all-namespaces"]),
    ("whocan-csr", ["who-can", "create", "certificatesigningrequests"]),
)


@dataclass(frozen=True)
class RawDump:
    """Everything read from the cluster, parsed but not yet analysed."""

    context: str
    version_text: str = ""
    cluster_info_text: str = ""
    aws_auth: Optional[dict[str, Any]] = None
    cluster_roles: tuple[dict[str, Any], ...] = ()
    cluster_role_bindings: tuple[dict[str, Any], ...] = ()
    roles: tuple[dict[str, Any], ...] = ()
    role_bindings: tuple[dict[str, Any], ...] = ()
    service_accounts: tuple[dict[str, Any], ...] = ()
    namespaces: tuple[dict[str, Any], ...] = ()
    can_i_text: str = ""
    can_i_warning: str = ""
    rbac_lookup_text: str = ""
    who_can: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = field(default=())

    def who_can_text(self, label: str) -> str:
        for key, value in self.who_can:
            if key == label:
                return value
        return ""


# --------------------------------------------------------------------------- #
# Context handling
# --------------------------------------------------------------------------- #
def list_contexts(runner: Runner) -> tuple[str, ...]:
    """Every context name in the kubeconfig."""
    result = runner.run("contexts", ["config", "get-contexts", "-o", "name"], with_context=False)
    if not result.ok:
        return ()
    return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())


def current_context(runner: Runner) -> str:
    result = runner.run("current-context", ["config", "current-context"], with_context=False)
    return result.stdout.strip() if result.ok else ""


def switch_context(runner: Runner, context: str) -> CommandResult:
    """Opt-in kubeconfig context switch (``--use-context``).

    Writes ``~/.kube/config``. The default path passes ``--context`` per command
    instead, which is idempotent and leaves the kubeconfig untouched.
    """
    return runner.run_local(
        "use-context",
        ["config", "use-context", context],
        note="rewrites the current-context field in ~/.kube/config",
    )


def verify_reachable(runner: Runner, work_dir: str) -> tuple[str, str]:
    """Confirm the API server answers, returning (version_text, cluster_info_text).

    ``kubectl version`` prints the *client* version to stdout and exits non-zero
    when the server is unreachable, so a non-empty stdout proves nothing. The
    presence of a ``Server Version`` line is the only signal that the API server
    actually replied — without it, every subsequent command would block until it
    timed out, turning an unreachable cluster into a multi-minute hang.
    """
    version = runner.run("version", ["version"])
    _write(work_dir, version)

    if not _has_server_version(version.stdout):
        detail = [line.strip() for line in (version.stderr or "").splitlines() if line.strip()]
        raise ClusterUnreachable(
            f"cannot reach the cluster: {detail[-1] if detail else 'the API server did not respond'}"
        )

    info = runner.run("cluster-info", ["cluster-info"])
    _write(work_dir, info)
    return version.stdout, info.stdout


def _has_server_version(text: str) -> bool:
    return any(line.startswith("Server Version") for line in (text or "").splitlines())


# --------------------------------------------------------------------------- #
# Gather
# --------------------------------------------------------------------------- #
def gather(runner: Runner, work_dir: str, tooling: ToolingStatus) -> RawDump:
    """Run every read-only probe, dumping raw output into ``work_dir``."""
    os.makedirs(work_dir, exist_ok=True)
    warnings: list[str] = list(tooling.warnings)

    version_text, cluster_info_text = verify_reachable(runner, work_dir)

    aws_auth = _dump_json_object(runner, work_dir, "aws-auth",
                                 ["get", "cm", "aws-auth", "-n", "kube-system", "-o", "json"])
    if aws_auth is None:
        warnings.append(
            "no kube-system/aws-auth ConfigMap — this is not an aws-auth-managed EKS "
            "cluster, so the EKS identity-mapping sections are omitted."
        )

    dumps: dict[str, tuple[dict[str, Any], ...]] = {}
    for label, args in RESOURCE_DUMPS:
        items, warning = _dump_items(runner, work_dir, label, args)
        dumps[label] = items
        if warning:
            warnings.append(warning)

    can_i = runner.run("can-i-list", ["auth", "can-i", "--list"])
    _write(work_dir, can_i)
    can_i_warning = _first_warning_line(can_i.stderr)

    rbac_lookup_text = ""
    if tooling.has("rbac-lookup"):
        result = runner.run("rbac-lookup", ["rbac-lookup"])
        _write(work_dir, result)
        if result.ok:
            rbac_lookup_text = result.stdout
        else:
            warnings.append(f"rbac-lookup failed: {_first_warning_line(result.stderr)}")

    who_can: list[tuple[str, str]] = []
    if tooling.has("who-can"):
        for label, args in WHO_CAN_QUERIES:
            result = runner.run(label, args)
            _write(work_dir, result)
            if result.ok:
                who_can.append((label, result.stdout))
            else:
                warnings.append(
                    f"{' '.join(args)} failed: {_first_warning_line(result.stderr)}"
                )

    return RawDump(
        context=runner.context or "",
        version_text=version_text,
        cluster_info_text=cluster_info_text,
        aws_auth=aws_auth,
        cluster_roles=dumps.get("cr", ()),
        cluster_role_bindings=dumps.get("crb", ()),
        roles=dumps.get("r", ()),
        role_bindings=dumps.get("rb", ()),
        service_accounts=dumps.get("sa", ()),
        namespaces=dumps.get("ns", ()),
        can_i_text=can_i.stdout,
        can_i_warning=can_i_warning,
        rbac_lookup_text=rbac_lookup_text,
        who_can=tuple(who_can),
        warnings=tuple(warnings),
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _write(work_dir: str, result: CommandResult) -> None:
    """Persist a command's stdout/stderr next to the others, gather.sh-style."""
    try:
        with open(os.path.join(work_dir, f"{result.label}.out"), "w", encoding="utf-8") as out:
            out.write(result.stdout)
        with open(os.path.join(work_dir, f"{result.label}.err"), "w", encoding="utf-8") as err:
            err.write(result.stderr)
    except OSError:
        # A non-writable work dir must not sink the audit; the data is already
        # in memory and the report does not depend on the dumps.
        pass


def _dump_items(
    runner: Runner, work_dir: str, label: str, args: list[str]
) -> tuple[tuple[dict[str, Any], ...], str]:
    """Run a `get ... -o json` dump and return its ``items``, plus any warning."""
    result = runner.run(label, args)
    _write(work_dir, result)
    if not result.ok:
        return (), f"{' '.join(args[:3])} failed: {_first_warning_line(result.stderr)}"
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return (), f"{' '.join(args[:3])} returned unparseable JSON: {exc}"
    items = payload.get("items")
    if not isinstance(items, list):
        return (), f"{' '.join(args[:3])} returned no items list"
    return tuple(item for item in items if isinstance(item, dict)), ""


def _dump_json_object(
    runner: Runner, work_dir: str, label: str, args: list[str]
) -> Optional[dict[str, Any]]:
    """Run a `get <object> -o json` dump, returning ``None`` when absent."""
    result = runner.run(label, args)
    _write(work_dir, result)
    if not result.ok:
        return None
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _first_warning_line(stderr: str) -> str:
    """The most useful single line from a command's stderr."""
    lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
    return lines[0] if lines else ""
