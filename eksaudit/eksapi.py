"""Optional read-only enrichment from the EKS control plane.

``aws-auth`` alone cannot answer three questions that matter to an authentication
audit: which authentication mode the cluster actually honours, who holds access
through EKS *access entries* (invisible to the ConfigMap), and whether the API
endpoint and audit logging are configured safely.

Everything here is best-effort. Missing credentials, a missing AWS CLI, a
non-EKS cluster, or an IAM denial all yield ``None`` plus a warning; the audit
continues and the affected finding is marked unverified.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from typing import Any, Optional

from .config import REQUIRED_LOG_TYPES
from .kubectl import Runner
from .models import AccessEntry, AccessPolicy, EksAccess

# Only these AWS CLI operations are ever invoked. Enforced in _aws() so a future
# edit cannot quietly introduce a mutating call.
ALLOWED_AWS_OPERATIONS = frozenset(
    {"describe-cluster", "list-access-entries", "describe-access-entry",
     "list-associated-access-policies"}
)

# Beyond this many access entries the per-entry detail calls are skipped; the
# count is still reported and a warning names what was not expanded.
MAX_DETAILED_ACCESS_ENTRIES = 60

_CLUSTER_ARN = re.compile(r"^arn:aws[\w-]*:eks:(?P<region>[\w-]+):(?P<account>\d{12}):cluster/(?P<name>.+)$")
_EKS_SERVER = re.compile(r"https://[\w.-]+\.(?P<region>[\w-]+)\.eks\.amazonaws\.com")


@dataclass(frozen=True)
class ClusterRef:
    """Enough identity to call the EKS API for this context."""

    name: str
    region: str
    account_id: str = ""
    profile: str = ""

    @property
    def arn(self) -> str:
        if self.account_id:
            return f"arn:aws:eks:{self.region}:{self.account_id}:cluster/{self.name}"
        return self.name


# --------------------------------------------------------------------------- #
# Resolving the context to an EKS cluster
# --------------------------------------------------------------------------- #
def resolve_cluster(runner: Runner, context: str) -> tuple[Optional[ClusterRef], str]:
    """Identify the EKS cluster behind a kubectl context.

    Draws on three signals, most reliable first: the context name itself
    (kubeconfigs written by ``aws eks update-kubeconfig`` name contexts after the
    cluster ARN), the ``aws eks get-token`` exec arguments, and the API server
    hostname. The exec block is also the only place an ``AWS_PROFILE`` appears,
    so it is consulted even when the context name already resolved the cluster.

    Returns ``(ref, warning)`` — ``ref`` is ``None`` for non-EKS clusters.
    """
    from_name = _from_arn(context)

    view = runner.run("kubeconfig", ["config", "view", "--minify", "-o", "json"])
    from_exec: Optional[ClusterRef] = None
    from_server: Optional[ClusterRef] = None
    if view.ok:
        try:
            config = json.loads(view.stdout or "{}")
        except json.JSONDecodeError:
            if from_name is None:
                return None, "kubeconfig was not valid JSON; skipping EKS control-plane checks"
        else:
            from_exec = _from_exec_args(config)
            from_server = _from_server_url(config)
    elif from_name is None:
        return None, "could not read the kubeconfig to identify the EKS cluster"

    profile = from_exec.profile if from_exec else ""
    for candidate in (from_name, from_exec, from_server):
        if candidate is not None:
            return (
                ClusterRef(
                    name=candidate.name,
                    region=candidate.region,
                    account_id=candidate.account_id,
                    profile=profile,
                ),
                "",
            )
    return None, ""


def _from_arn(text: str) -> Optional[ClusterRef]:
    match = _CLUSTER_ARN.match(text.strip())
    if not match:
        return None
    return ClusterRef(
        name=match.group("name"),
        region=match.group("region"),
        account_id=match.group("account"),
    )


def _from_exec_args(config: dict[str, Any]) -> Optional[ClusterRef]:
    """Read cluster name / region from an ``aws eks get-token`` exec block."""
    for user in config.get("users") or []:
        exec_block = ((user or {}).get("user") or {}).get("exec") or {}
        args = [str(a) for a in exec_block.get("args") or []]
        if "get-token" not in args:
            continue
        name = _flag_value(args, "--cluster-name")
        region = _flag_value(args, "--region")
        profile = _flag_value(args, "--profile") or _env_value(exec_block, "AWS_PROFILE")
        if name:
            return ClusterRef(name=name, region=region or "", profile=profile or "")
    return None


def _from_server_url(config: dict[str, Any]) -> Optional[ClusterRef]:
    """Last resort: an EKS API hostname gives the region but not the name."""
    for cluster in config.get("clusters") or []:
        server = ((cluster or {}).get("cluster") or {}).get("server") or ""
        match = _EKS_SERVER.match(str(server))
        if match:
            # Without a cluster name the EKS API cannot be queried; report the
            # region so the caller can say "EKS, but not identifiable".
            return ClusterRef(name="", region=match.group("region"))
    return None


def _flag_value(args: list[str], flag: str) -> str:
    for index, arg in enumerate(args):
        if arg == flag and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return ""


def _env_value(exec_block: dict[str, Any], name: str) -> str:
    for entry in exec_block.get("env") or []:
        if isinstance(entry, dict) and entry.get("name") == name:
            return str(entry.get("value") or "")
    return ""


# --------------------------------------------------------------------------- #
# Reading the control plane
# --------------------------------------------------------------------------- #
def collect(runner: Runner, ref: ClusterRef) -> tuple[Optional[EksAccess], tuple[str, ...]]:
    """Read access configuration for ``ref``, returning ``(access, warnings)``."""
    if shutil.which("aws") is None:
        return None, ("the AWS CLI is not installed — EKS control-plane checks were skipped.",)
    if not ref.name:
        return None, ("could not determine the EKS cluster name from the kubeconfig — "
                      "EKS control-plane checks were skipped.",)

    warnings: list[str] = []
    described = _aws(runner, ref, "describe-cluster", ["--name", ref.name])
    if described is None:
        return None, (
            f"could not describe EKS cluster '{ref.name}' — the report's EKS "
            f"control-plane findings are omitted and aws-auth posture is unverified.",
        )

    cluster = described.get("cluster") or {}
    access_config = cluster.get("accessConfig") or {}
    vpc_config = cluster.get("resourcesVpcConfig") or {}

    entries, entry_warnings = _access_entries(runner, ref)
    warnings.extend(entry_warnings)

    access = EksAccess(
        cluster_arn=str(cluster.get("arn") or ref.arn),
        authentication_mode=str(access_config.get("authenticationMode") or ""),
        access_entries=entries,
        endpoint_public_access=bool(vpc_config.get("endpointPublicAccess")),
        public_access_cidrs=tuple(str(c) for c in vpc_config.get("publicAccessCidrs") or []),
        enabled_log_types=_enabled_log_types(cluster),
        platform_version=str(cluster.get("platformVersion") or ""),
    )
    return access, tuple(warnings)


def _enabled_log_types(cluster: dict[str, Any]) -> tuple[str, ...]:
    enabled: list[str] = []
    for group in ((cluster.get("logging") or {}).get("clusterLogging") or []):
        if isinstance(group, dict) and group.get("enabled"):
            enabled.extend(str(t) for t in group.get("types") or [])
    return tuple(sorted(set(enabled)))


def _access_entries(runner: Runner, ref: ClusterRef) -> tuple[tuple[AccessEntry, ...], tuple[str, ...]]:
    listed = _aws(runner, ref, "list-access-entries", ["--cluster-name", ref.name])
    if listed is None:
        return (), ("could not list EKS access entries (eks:ListAccessEntries denied or "
                    "unsupported) — access-entry findings are omitted.",)

    arns = [str(a) for a in listed.get("accessEntries") or []]
    warnings: list[str] = []
    detailed = sorted(arns)[:MAX_DETAILED_ACCESS_ENTRIES]
    if len(arns) > MAX_DETAILED_ACCESS_ENTRIES:
        warnings.append(
            f"{len(arns)} EKS access entries exist; only the first "
            f"{MAX_DETAILED_ACCESS_ENTRIES} (sorted by ARN) were expanded in detail."
        )

    entries: list[AccessEntry] = []
    for arn in detailed:
        entries.append(_access_entry(runner, ref, arn))
    return tuple(entries), tuple(warnings)


def _access_entry(runner: Runner, ref: ClusterRef, principal_arn: str) -> AccessEntry:
    described = _aws(
        runner, ref, "describe-access-entry",
        ["--cluster-name", ref.name, "--principal-arn", principal_arn],
    ) or {}
    entry = described.get("accessEntry") or {}

    associated = _aws(
        runner, ref, "list-associated-access-policies",
        ["--cluster-name", ref.name, "--principal-arn", principal_arn],
    ) or {}

    policies = tuple(
        AccessPolicy(
            name=str(item.get("policyArn") or "").rsplit("/", 1)[-1],
            scope_type=str((item.get("accessScope") or {}).get("type") or ""),
            namespaces=tuple(str(n) for n in (item.get("accessScope") or {}).get("namespaces") or []),
        )
        for item in associated.get("associatedAccessPolicies") or []
        if isinstance(item, dict)
    )

    return AccessEntry(
        principal_arn=principal_arn,
        entry_type=str(entry.get("type") or "STANDARD"),
        username=str(entry.get("username") or ""),
        kubernetes_groups=tuple(str(g) for g in entry.get("kubernetesGroups") or []),
        policies=policies,
    )


def _aws(
    runner: Runner, ref: ClusterRef, operation: str, args: list[str]
) -> Optional[dict[str, Any]]:
    """Invoke one allowlisted read-only ``aws eks`` operation."""
    if operation not in ALLOWED_AWS_OPERATIONS:
        raise ValueError(f"'aws eks {operation}' is not an allowed read-only operation")

    argv = ["aws", "eks", operation, *args, "--output", "json"]
    if ref.region:
        argv.extend(["--region", ref.region])
    profile = ref.profile or os.environ.get("AWS_PROFILE", "")
    if profile:
        argv.extend(["--profile", profile])

    result = runner.run_external(f"aws-{operation}", argv)
    if not result.ok:
        return None
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def missing_log_types(access: EksAccess) -> tuple[str, ...]:
    """Control-plane log types required for an auth audit that are switched off."""
    return tuple(t for t in REQUIRED_LOG_TYPES if t not in access.enabled_log_types)
