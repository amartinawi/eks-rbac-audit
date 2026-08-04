"""EKS cluster resolution and the AWS-side read-only allowlist."""

import pytest

from eksaudit import eksapi
from eksaudit.kubectl import Runner
from eksaudit.models import EksAccess


# --------------------------------------------------------------------------- #
# Resolving a context to a cluster
# --------------------------------------------------------------------------- #
def test_context_named_after_the_cluster_arn_resolves():
    ref = eksapi._from_arn("arn:aws:eks:eu-west-1:111122223333:cluster/demo-prod")
    assert ref is not None
    assert ref.name == "demo-prod"
    assert ref.region == "eu-west-1"
    assert ref.account_id == "111122223333"


@pytest.mark.parametrize(
    "context",
    [
        "demo-staging-ssm-tunnel",              # a tunnel alias, not an ARN
        "/api-example-com:443/devops",          # OpenShift-style context
        "minikube",
        "kind-local",
        "",
    ],
)
def test_non_arn_contexts_do_not_resolve_by_name(context):
    assert eksapi._from_arn(context) is None


def test_exec_args_supply_the_cluster_name_region_and_profile():
    config = {
        "users": [
            {
                "user": {
                    "exec": {
                        "args": ["--region", "eu-west-1", "eks", "get-token",
                                 "--cluster-name", "demo-staging"],
                        "env": [{"name": "AWS_PROFILE", "value": "demo-stage"}],
                    }
                }
            }
        ]
    }
    ref = eksapi._from_exec_args(config)
    assert ref is not None
    assert (ref.name, ref.region, ref.profile) == ("demo-staging", "eu-west-1", "demo-stage")


def test_exec_args_accept_equals_form_flags():
    config = {
        "users": [
            {"user": {"exec": {"args": ["eks", "get-token", "--cluster-name=demo",
                                        "--region=us-east-1", "--profile=prod"]}}}
        ]
    }
    ref = eksapi._from_exec_args(config)
    assert ref is not None
    assert (ref.name, ref.region, ref.profile) == ("demo", "us-east-1", "prod")


def test_non_eks_exec_block_is_ignored():
    config = {"users": [{"user": {"exec": {"args": ["oidc-login", "get-token"]}}}]}
    assert eksapi._from_exec_args(config) is None


def test_server_url_supplies_the_region_only():
    config = {"clusters": [{"cluster": {"server": "https://ABC123.gr7.eu-west-1.eks.amazonaws.com"}}]}
    ref = eksapi._from_server_url(config)
    assert ref is not None
    assert ref.region == "eu-west-1"
    assert ref.name == "", "the API hostname does not carry the cluster name"


def test_non_eks_server_url_does_not_resolve():
    config = {"clusters": [{"cluster": {"server": "https://api.openshift.example.com:6443"}}]}
    assert eksapi._from_server_url(config) is None


# --------------------------------------------------------------------------- #
# The AWS read-only allowlist
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "operation",
    [
        "create-access-entry",
        "delete-access-entry",
        "update-cluster-config",
        "associate-access-policy",
        "delete-cluster",
    ],
)
def test_mutating_aws_operations_are_refused(operation):
    runner = Runner(binary="true")
    ref = eksapi.ClusterRef(name="demo", region="eu-west-1")
    with pytest.raises(ValueError):
        eksapi._aws(runner, ref, operation, [])


@pytest.mark.parametrize(
    "operation",
    [
        "describe-cluster",
        "list-access-entries",
        "describe-access-entry",
        "list-associated-access-policies",
    ],
)
def test_read_only_aws_operations_are_allowed(operation):
    assert operation in eksapi.ALLOWED_AWS_OPERATIONS


def test_collect_degrades_gracefully_without_a_cluster_name():
    """A region-only resolution cannot query the API; it must warn, not crash."""
    runner = Runner(binary="true")
    access, warnings = eksapi.collect(runner, eksapi.ClusterRef(name="", region="eu-west-1"))
    assert access is None
    assert warnings and "skipped" in warnings[0]


# --------------------------------------------------------------------------- #
# Log-type evaluation
# --------------------------------------------------------------------------- #
def test_missing_log_types_are_identified():
    access = EksAccess(cluster_arn="arn", enabled_log_types=("api", "audit"))
    assert eksapi.missing_log_types(access) == ("authenticator",)


def test_no_missing_log_types_when_both_are_enabled():
    access = EksAccess(cluster_arn="arn",
                       enabled_log_types=("api", "audit", "authenticator", "scheduler"))
    assert eksapi.missing_log_types(access) == ()


def test_enabled_log_types_are_read_from_the_describe_payload():
    cluster = {
        "logging": {
            "clusterLogging": [
                {"types": ["api", "audit"], "enabled": True},
                {"types": ["authenticator", "scheduler"], "enabled": False},
            ]
        }
    }
    assert eksapi._enabled_log_types(cluster) == ("api", "audit")
