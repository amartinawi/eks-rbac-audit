"""Turn a raw collection into a sorted, summarised :class:`AuditResult`.

This module owns the orchestration only: it builds the inventory, runs every
rule, sorts the findings by severity, and assembles the executive summary. The
rules themselves live in :mod:`eksaudit.rules_rbac` and :mod:`eksaudit.rules_eks`.
"""

from __future__ import annotations

from typing import Optional

from . import awsauth, inventory as inventory_mod, rules_eks, rules_rbac
from .config import (
    ANONYMOUS_SUBJECTS,
    CLUSTER_ADMIN_ROLE,
    DEFAULT_ANONYMOUS_BINDINGS,
    DEFAULT_THRESHOLDS,
    MASTERS_GROUP,
    NODE_USERNAME_TEMPLATE,
    Thresholds,
    severity_rank,
)
from .models import AuditResult, ClusterMeta, CommandRecord, EksAccess, Finding
from .rules_common import RuleContext, count_noun, looks_node_role


def analyze(
    raw,
    eks: Optional[EksAccess] = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    commands: tuple[CommandRecord, ...] = (),
    extra_warnings: tuple[str, ...] = (),
) -> AuditResult:
    """Run every rule against a :class:`eksaudit.collector.RawDump`."""
    mappings = awsauth.parse_aws_auth(raw.aws_auth)
    map_accounts = awsauth.map_accounts(raw.aws_auth)

    inv = inventory_mod.build_inventory(raw)
    roles_by_name = {role.name: role for role in inv.cluster_roles}
    roles_by_name.update({role.name: role for role in inv.roles})
    sa_posture = inventory_mod.build_sa_posture(
        raw, inv.cluster_role_bindings + inv.role_bindings, roles_by_name
    )

    meta = build_meta(raw, mappings, eks)

    ctx = RuleContext(
        meta=meta,
        inventory=inv,
        sa_posture=sa_posture,
        thresholds=thresholds,
        mappings=mappings,
        eks=eks,
        aws_auth_present=raw.aws_auth is not None,
        map_accounts=map_accounts,
        admin_roles=inventory_mod.admin_role_names(inv.cluster_roles),
    )

    findings: list[Finding] = []
    for rule in rules_rbac.ALL_RULES + rules_eks.ALL_RULES:
        findings.extend(rule(ctx))

    ordered = sort_findings(tuple(findings))
    positives = detect_positives(ctx)

    return AuditResult(
        meta=meta,
        mappings=mappings,
        inventory=inv,
        sa_posture=sa_posture,
        eks=eks,
        findings=ordered,
        positives=positives,
        summary=build_summary(ordered, positives, ctx),
        warnings=tuple(raw.warnings) + tuple(extra_warnings),
        commands=commands,
        aws_auth_present=raw.aws_auth is not None,
    )


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
def build_meta(raw, mappings, eks: Optional[EksAccess]) -> ClusterMeta:
    """Assemble the header facts: who was audited, at what version, in what account."""
    versions = parse_versions(raw.version_text)
    account = awsauth.account_id(mappings)
    cluster_name = region = ""

    if eks is not None and eks.cluster_arn:
        parts = eks.cluster_arn.split(":")
        if len(parts) > 5:
            region = parts[3]
            account = account or parts[4]
            cluster_name = parts[5].split("/", 1)[-1]

    rules = tuple(
        line.strip()
        for line in (raw.can_i_text or "").splitlines()[1:]
        if line.strip()
    )

    return ClusterMeta(
        context=raw.context,
        server_version=versions.get("Server Version", ""),
        client_version=versions.get("Client Version", ""),
        cluster_endpoint=first_endpoint(raw.cluster_info_text),
        account_id=account,
        cluster_name=cluster_name,
        region=region,
        caller_can_i=rules,
        can_i_warning=raw.can_i_warning,
    )


def parse_versions(text: str) -> dict[str, str]:
    """Parse ``kubectl version`` output into a mapping of label to version."""
    versions: dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        versions[label.strip()] = value.strip()
    return versions


def first_endpoint(text: str) -> str:
    """The control-plane URL from ``kubectl cluster-info``, stripped of ANSI codes."""
    for line in (text or "").splitlines():
        if "://" in line:
            cleaned = _strip_ansi(line)
            start = cleaned.find("http")
            if start >= 0:
                return cleaned[start:].split()[0]
    return ""


def _strip_ansi(text: str) -> str:
    out: list[str] = []
    skipping = False
    for char in text:
        if char == "\x1b":
            skipping = True
            continue
        if skipping:
            if char.isalpha():
                skipping = False
            continue
        out.append(char)
    return "".join(out)


# --------------------------------------------------------------------------- #
# Ordering and narrative
# --------------------------------------------------------------------------- #
def sort_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Most severe first; stable and deterministic within a severity."""
    return tuple(
        sorted(findings, key=lambda f: (severity_rank(f.severity), f.rule_id, f.title))
    )


def detect_positives(ctx: RuleContext) -> tuple[str, ...]:
    """Controls that are demonstrably in good shape — worth stating explicitly.

    A report that lists only problems gives no signal about what was verified
    and found sound, which is exactly what a reviewer needs to prioritise.
    """
    positives: list[str] = []

    admin_subject_kinds = {kind for _, _, kind in ctx.inventory.cluster_admin_paths}
    if admin_subject_kinds and admin_subject_kinds <= {"Group", "User"}:
        platform_managed = [
            subject for _, subject, _ in ctx.inventory.cluster_admin_paths
            if "eks:" in subject or subject.startswith("system:")
        ]
        group_only = all(
            subject.startswith(f"Group:{MASTERS_GROUP}") or "eks:" in subject
            for _, subject, _ in ctx.inventory.cluster_admin_paths
        )
        if group_only:
            addendum = (
                " and platform-managed add-on identities" if platform_managed else ""
            )
            positives.append(
                f"cluster-admin is reachable only through the {MASTERS_GROUP} group"
                f"{addendum} — there are no ad-hoc admin bindings."
            )

    if not ctx.sa_posture.default_bound:
        positives.append(
            "No default ServiceAccount is bound to any Role or ClusterRole, so pods without "
            "an explicit ServiceAccount inherit no permissions."
        )

    node_mappings = [m for m in ctx.mappings if looks_node_role(m.arn)]
    if node_mappings and all(
        MASTERS_GROUP not in m.groups and m.username == NODE_USERNAME_TEMPLATE
        for m in node_mappings
    ):
        positives.append(
            f"All {len(node_mappings)} node-group roles map correctly to "
            f"system:bootstrappers / system:nodes with per-instance usernames."
        )

    non_default_anonymous = [
        binding
        for binding in ctx.all_bindings
        if binding.name not in DEFAULT_ANONYMOUS_BINDINGS
        and any(s.name in ANONYMOUS_SUBJECTS for s in binding.subjects)
    ]
    if not non_default_anonymous:
        positives.append(
            "Anonymous access is limited to the upstream-default system:public-info-viewer "
            "binding (health, version, and API discovery only)."
        )

    custom_wildcards = [
        role for role in ctx.inventory.cluster_roles
        if role.flags.full_wildcard and not role.builtin and role.name != CLUSTER_ADMIN_ROLE
    ]
    if not custom_wildcards:
        positives.append(
            "No operator-defined wildcard ClusterRole exists outside cluster-admin itself."
        )

    return tuple(positives)


def build_summary(
    findings: tuple[Finding, ...], positives: tuple[str, ...], ctx: RuleContext
) -> str:
    """Assemble the executive summary from what was actually found.

    Deterministic: the same cluster state always produces the same prose.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    actionable = [f for f in findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    sentences: list[str] = []

    if not actionable:
        sentences.append(
            "No critical, high, or medium-severity authentication or RBAC issues were found "
            "in this cluster."
        )
    else:
        headline = actionable[0]
        sentences.append(
            f"The most serious issue is {_lower_first(headline.title)}. {headline.impact}"
        )
        remaining = actionable[1:]
        if remaining:
            shown = remaining[:3]
            others = "; ".join(_lower_first(f.title) for f in shown)
            overflow = len(remaining) - len(shown)
            tail = f", and {overflow} further issue{'s' if overflow > 1 else ''}" if overflow else ""
            sentences.append(f"Also outstanding: {others}{tail}.")

    admins = len(ctx.mappings and [m for m in ctx.mappings if m.is_master] or [])
    if ctx.aws_auth_present:
        sentences.append(
            f"{count_noun(len(ctx.mappings), 'IAM principal')} are mapped into the cluster through "
            f"aws-auth, {admins} of them with cluster-admin."
        )
    if ctx.eks is not None and ctx.eks.authentication_mode:
        sentences.append(
            f"The cluster's authenticationMode is {ctx.eks.authentication_mode}."
        )

    # Positives are rendered as their own list in the report rather than being
    # buried in this paragraph, so they are deliberately not appended here.
    del positives

    tally = ", ".join(
        f"{count} {severity.lower()}"
        for severity, count in counts.items()
        if count
    )
    if tally:
        sentences.append(f"Findings by severity: {tally}.")

    return " ".join(sentences)


def _lower_first(text: str) -> str:
    """Lower the leading character unless the first word is a proper identifier.

    "ClusterRole", "EKS", and "system:masters" must survive intact; "Broad
    standing cluster-admin" should read as lower case mid-sentence.
    """
    if not text:
        return text
    first_word = text.split(" ", 1)[0]
    has_inner_capital = first_word[1:] != first_word[1:].lower()
    if has_inner_capital or any(c in first_word for c in "-:/_"):
        return text
    return text[0].lower() + text[1:]
