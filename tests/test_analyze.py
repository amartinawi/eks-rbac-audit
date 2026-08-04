"""One test per finding rule, plus negative tests against a well-configured cluster."""

import dataclasses

import pytest

from conftest import load_dump
from eksaudit import analyze
from eksaudit.models import AccessEntry, AccessPolicy, EksAccess


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def rule(result, rule_id):
    """Return the finding emitted by ``rule_id``, or None."""
    matches = [f for f in result.findings if f.rule_id == rule_id]
    return matches[0] if matches else None


def cluster_role(name, rules, labels=None):
    metadata = {"name": name}
    if labels:
        metadata["labels"] = labels
    return {"metadata": metadata, "rules": rules}


def binding(name, role_name, subjects, kind="ClusterRole"):
    return {
        "metadata": {"name": name},
        "roleRef": {"kind": kind, "name": role_name},
        "subjects": subjects,
    }


def dump_with(clean_dump, **overrides):
    """Start from the clean cluster and inject exactly one problem."""
    return dataclasses.replace(clean_dump, **overrides)


# --------------------------------------------------------------------------- #
# The real (imperfect) cluster
# --------------------------------------------------------------------------- #
def test_deceptive_read_only_role_is_detected(raw_dump):
    """R1 — a role that promises read-only and delivers Secret read plus exec."""
    result = analyze.analyze(raw_dump)
    finding = rule(result, "R1")
    assert finding is not None
    assert finding.severity == "CRITICAL"
    assert "cluster-reader" in finding.title
    joined = " ".join(finding.evidence)
    assert "pods/exec" in joined and "secrets" in joined


def test_principals_reaching_the_deceptive_role_are_named(raw_dump):
    """The evidence must name who actually holds it, via the aws-auth group."""
    finding = rule(analyze.analyze(raw_dump), "R1")
    joined = " ".join(finding.evidence)
    assert "qa-analyst" in joined and "report-exporter" in joined


def test_automation_cluster_admins_are_detected(raw_dump):
    """R3 — machine identities holding standing cluster-admin."""
    result = analyze.analyze(raw_dump)
    finding = rule(result, "R3")
    assert finding is not None and finding.severity == "HIGH"
    evidence = " ".join(finding.evidence)
    assert "ci-pipeline-role" in evidence and "build-bot" in evidence


@pytest.mark.parametrize(
    "name", ["pod-reader", "secret-viewer", "cluster-reader", "app-read", "ns-readonly"]
)
def test_common_read_only_naming_conventions_are_recognised(name):
    from eksaudit.rules_common import looks_read_only

    assert looks_read_only(name), f"{name!r} advertises read-only access"


@pytest.mark.parametrize("name", ["preview-gateway", "credential-manager", "broadcast-agent"])
def test_lookalike_names_are_not_treated_as_read_only(name):
    from eksaudit.rules_common import looks_read_only

    assert not looks_read_only(name), f"{name!r} only contains a hint as a substring"


def test_real_cluster_detects_static_iam_user_admins(raw_dump):
    finding = rule(analyze.analyze(raw_dump), "R3b")
    assert finding is not None and finding.severity == "HIGH"


def test_real_cluster_reports_token_automount_posture(raw_dump):
    finding = rule(analyze.analyze(raw_dump), "R15")
    assert finding is not None and finding.severity == "LOW"


def test_kubernetes_default_roles_are_not_flagged_as_custom(raw_dump):
    """`admin` and `edit` are upstream defaults labelled rbac-defaults.

    They grant Secret read and pod exec by design; flagging them would produce
    two CRITICAL false positives on literally every cluster.
    """
    result = analyze.analyze(raw_dump)
    titles = " ".join(f.title for f in result.findings)
    assert "“admin”" not in titles
    assert "“edit”" not in titles


# --------------------------------------------------------------------------- #
# The clean cluster — negative tests
# --------------------------------------------------------------------------- #
def test_clean_cluster_has_no_critical_or_high_findings(clean_dump):
    result = analyze.analyze(clean_dump)
    serious = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH")]
    assert serious == [], f"unexpected findings: {[f.title for f in serious]}"


def test_clean_cluster_reports_positives(clean_dump):
    result = analyze.analyze(clean_dump)
    assert result.positives, "a well-configured cluster should have something to show for it"


def test_clean_cluster_still_reports_the_aws_auth_migration(clean_dump):
    """A well-run cluster on aws-auth is still on the legacy path.

    "No CRITICAL or HIGH" is not the same as "nothing to do" — this is the one
    MEDIUM a correctly configured ConfigMap-based cluster is expected to carry.
    """
    finding = rule(analyze.analyze(clean_dump), "R13")
    assert finding is not None and finding.severity == "MEDIUM"


def test_summary_says_so_when_nothing_is_actionable(clean_dump):
    """A clean non-EKS cluster has no actionable findings at all."""
    result = analyze.analyze(dump_with(clean_dump, aws_auth=None))
    assert "No critical, high, or medium-severity" in result.summary


# --------------------------------------------------------------------------- #
# Individual rules, injected into the clean cluster one at a time
# --------------------------------------------------------------------------- #
def test_r2_secret_read_plus_exec_is_critical(clean_dump):
    """R2 — the combination is admin-equivalent regardless of the role's name."""
    roles = clean_dump.cluster_roles + (
        cluster_role("platform-helper", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
        ]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_roles=roles)), "R2")
    assert finding is not None and finding.severity == "CRITICAL"
    assert "platform-helper" in finding.title


def test_r1_fires_on_a_read_named_role_with_only_secrets(clean_dump):
    roles = clean_dump.cluster_roles + (
        cluster_role("metrics-viewer", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]},
        ]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_roles=roles)), "R1")
    assert finding is not None and finding.severity == "CRITICAL"


def test_read_only_naming_does_not_match_substrings(clean_dump):
    """`credential-manager` contains "read" only as a substring of no word."""
    roles = clean_dump.cluster_roles + (
        cluster_role("preview-gateway", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]},
        ]),
    )
    result = analyze.analyze(dump_with(clean_dump, cluster_roles=roles))
    assert rule(result, "R1") is None, "'preview' must not be read as 'view'"


def test_r5_node_role_mapped_to_masters_is_critical(clean_dump):
    configmap = {
        "data": {
            "mapRoles": (
                "- groups:\n  - system:masters\n"
                "  rolearn: arn:aws:iam::111122223333:role/eks-managed-web-node-group-role\n"
                "  username: system:node:{{EC2PrivateDNSName}}\n"
            ),
            "mapUsers": "[]\n",
            "mapAccounts": "[]\n",
        }
    }
    finding = rule(analyze.analyze(dump_with(clean_dump, aws_auth=configmap)), "R5")
    assert finding is not None and finding.severity == "CRITICAL"


def test_r6_non_node_principal_in_system_nodes(clean_dump):
    configmap = {
        "data": {
            "mapRoles": (
                "- groups:\n  - system:nodes\n"
                "  rolearn: arn:aws:iam::111122223333:role/BuildPipeline\n"
                "  username: builder\n"
            ),
            "mapUsers": "[]\n",
            "mapAccounts": "[]\n",
        }
    }
    finding = rule(analyze.analyze(dump_with(clean_dump, aws_auth=configmap)), "R6")
    assert finding is not None and finding.severity == "HIGH"


def test_r6_node_role_with_wrong_username_template(clean_dump):
    configmap = {
        "data": {
            "mapRoles": (
                "- groups:\n  - system:bootstrappers\n  - system:nodes\n"
                "  rolearn: arn:aws:iam::111122223333:role/eks-managed-web-node-group-role\n"
                "  username: shared-node\n"
            ),
            "mapUsers": "[]\n",
            "mapAccounts": "[]\n",
        }
    }
    finding = rule(analyze.analyze(dump_with(clean_dump, aws_auth=configmap)), "R6")
    assert finding is not None
    assert "system:node:{{EC2PrivateDNSName}}" in " ".join(finding.evidence)


def test_r7_non_default_anonymous_binding_is_flagged(clean_dump):
    bindings = clean_dump.cluster_role_bindings + (
        binding("open-door", "cluster-admin", [{"kind": "Group", "name": "system:anonymous"}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_role_bindings=bindings)), "R7")
    assert finding is not None and finding.severity == "CRITICAL"


def test_r7_upstream_default_binding_is_informational(clean_dump):
    finding = rule(analyze.analyze(clean_dump), "R7")
    assert finding is not None and finding.severity == "INFORMATIONAL"


def test_r8_custom_wildcard_cluster_role_is_high(clean_dump):
    roles = clean_dump.cluster_roles + (
        cluster_role("do-everything",
                     [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_roles=roles)), "R8")
    assert finding is not None and finding.severity == "HIGH"
    assert "do-everything" in " ".join(finding.evidence)


def test_r9_default_service_account_binding_is_flagged(clean_dump):
    bindings = clean_dump.cluster_role_bindings + (
        binding("app-default", "app-viewer",
                [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_role_bindings=bindings)), "R9")
    assert finding is not None and finding.severity == "HIGH"


def test_r9_default_sa_bound_to_admin_is_critical(clean_dump):
    bindings = clean_dump.cluster_role_bindings + (
        binding("app-default", "cluster-admin",
                [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_role_bindings=bindings)), "R9")
    assert finding is not None and finding.severity == "CRITICAL"


@pytest.mark.parametrize(
    "verb,resources",
    [
        ("escalate", ["clusterroles"]),
        ("bind", ["clusterroles"]),
        ("impersonate", ["users"]),
    ],
)
def test_r10_escalation_verbs_are_high(clean_dump, verb, resources):
    roles = clean_dump.cluster_roles + (
        cluster_role("sneaky",
                     [{"apiGroups": ["rbac.authorization.k8s.io"],
                       "resources": resources, "verbs": [verb]}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_roles=roles)), "R10")
    assert finding is not None and finding.severity == "HIGH"
    assert verb in " ".join(finding.evidence)


@pytest.mark.parametrize(
    "resource", ["serviceaccounts/token", "certificatesigningrequests"]
)
def test_r11_credential_minting_is_high(clean_dump, resource):
    roles = clean_dump.cluster_roles + (
        cluster_role("minter", [{"apiGroups": ["*"], "resources": [resource],
                                 "verbs": ["create"]}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_roles=roles)), "R11")
    assert finding is not None and finding.severity == "HIGH"


def test_r12_broad_standing_admin_respects_the_threshold(raw_dump):
    from eksaudit.config import Thresholds

    lenient = analyze.analyze(raw_dump, thresholds=Thresholds(admin_threshold=100))
    assert rule(lenient, "R12") is None

    strict = analyze.analyze(raw_dump, thresholds=Thresholds(admin_threshold=1))
    assert rule(strict, "R12") is not None


def test_r13_config_map_mode_recommends_access_entries(raw_dump):
    finding = rule(analyze.analyze(raw_dump), "R13")
    assert finding is not None and finding.severity == "MEDIUM"
    assert finding.unverified, "without EKS API data the auth mode is unverified"


def test_r13_dual_source_mode_is_flagged(raw_dump):
    eks = EksAccess(cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
                    authentication_mode="API_AND_CONFIG_MAP")
    finding = rule(analyze.analyze(raw_dump, eks=eks), "R13")
    assert finding is not None and finding.severity == "MEDIUM"
    assert "two places" in finding.title
    assert not finding.unverified


def test_r13_api_mode_with_stale_configmap_is_low(raw_dump):
    eks = EksAccess(cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
                    authentication_mode="API")
    finding = rule(analyze.analyze(raw_dump, eks=eks), "R13")
    assert finding is not None and finding.severity == "LOW"
    assert "stale" in finding.title


def test_r4_access_entry_cluster_admin_is_high(clean_dump):
    eks = EksAccess(
        cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
        authentication_mode="API",
        access_entries=(
            AccessEntry(
                principal_arn="arn:aws:iam::111122223333:role/Deployer",
                policies=(AccessPolicy(name="AmazonEKSClusterAdminPolicy",
                                       scope_type="cluster"),),
            ),
        ),
        enabled_log_types=("audit", "authenticator"),
    )
    finding = rule(analyze.analyze(clean_dump, eks=eks), "R4")
    assert finding is not None and finding.severity == "HIGH"
    assert "Deployer" in " ".join(finding.evidence)


def test_r4_namespace_scoped_access_entry_is_not_flagged(clean_dump):
    eks = EksAccess(
        cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
        authentication_mode="API",
        access_entries=(
            AccessEntry(
                principal_arn="arn:aws:iam::111122223333:role/Dev",
                policies=(AccessPolicy(name="AmazonEKSEditPolicy",
                                       scope_type="namespace",
                                       namespaces=("dev",)),),
            ),
        ),
        enabled_log_types=("audit", "authenticator"),
    )
    assert rule(analyze.analyze(clean_dump, eks=eks), "R4") is None


def test_r14_public_endpoint_and_missing_logs(clean_dump):
    eks = EksAccess(
        cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
        authentication_mode="API",
        endpoint_public_access=True,
        public_access_cidrs=("0.0.0.0/0",),
        enabled_log_types=("api",),
    )
    result = analyze.analyze(clean_dump, eks=eks)
    titles = [f.title for f in result.findings if f.rule_id == "R14"]
    assert any("internet" in t for t in titles)
    assert any("logging" in t for t in titles)


def test_r14_silent_when_control_plane_is_configured_well(clean_dump):
    eks = EksAccess(
        cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
        authentication_mode="API",
        endpoint_public_access=True,
        public_access_cidrs=("203.0.113.0/24",),
        enabled_log_types=("api", "audit", "authenticator"),
    )
    assert rule(analyze.analyze(clean_dump, eks=eks), "R14") is None


def test_r17_surfaces_the_webhook_authorizer_caveat(clean_dump):
    warning = "the list may be incomplete: webhook authorizer does not support user rule resolution"
    result = analyze.analyze(dump_with(clean_dump, can_i_warning=warning))
    finding = rule(result, "R17")
    assert finding is not None
    assert warning in " ".join(finding.evidence)


# --------------------------------------------------------------------------- #
# Non-EKS clusters
# --------------------------------------------------------------------------- #
def test_non_eks_cluster_skips_eks_rules_but_still_audits_rbac(clean_dump):
    """OpenShift and plain Kubernetes have no aws-auth ConfigMap."""
    roles = clean_dump.cluster_roles + (
        cluster_role("do-everything",
                     [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
    )
    result = analyze.analyze(
        dump_with(clean_dump, aws_auth=None, cluster_roles=roles)
    )
    assert not result.aws_auth_present
    assert result.mappings == ()
    assert rule(result, "R13") is None, "no aws-auth means no aws-auth posture finding"
    assert rule(result, "R8") is not None, "RBAC rules must still run"


# --------------------------------------------------------------------------- #
# Ordering and determinism
# --------------------------------------------------------------------------- #
def test_findings_are_sorted_most_severe_first(raw_dump):
    from eksaudit.config import severity_rank

    ranks = [severity_rank(f.severity) for f in analyze.analyze(raw_dump).findings]
    assert ranks == sorted(ranks)


def test_analysis_is_deterministic(raw_dump):
    first = analyze.analyze(raw_dump)
    second = analyze.analyze(raw_dump)
    assert first.findings == second.findings
    assert first.summary == second.summary
    assert first.positives == second.positives


def test_metadata_is_parsed_from_version_output(raw_dump):
    result = analyze.analyze(raw_dump)
    assert result.meta.server_version == "v1.33.13-eks-8f14419"
    assert result.meta.client_version == "v1.32.2"
    assert result.meta.account_id == "111122223333"


def test_cluster_identity_comes_from_the_eks_arn(clean_dump):
    eks = EksAccess(cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo-prod",
                    authentication_mode="API")
    meta = analyze.analyze(clean_dump, eks=eks).meta
    assert meta.cluster_name == "demo-prod"
    assert meta.region == "eu-west-1"
    assert meta.is_eks


def test_empty_cluster_does_not_crash():
    """A caller with no list permissions gets empty dumps, not a traceback."""
    result = analyze.analyze(load_dump("/nonexistent-fixture-dir"))
    assert result.findings, "informational findings should still be produced"
    assert result.severity_counts["CRITICAL"] == 0
