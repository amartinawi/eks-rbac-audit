"""aws-auth ConfigMap parsing, including the YAML-style inconsistencies seen in the wild."""

import json
import os

import pytest

from eksaudit import awsauth

# Unquoted style, as written by eksctl / Terraform.
UNQUOTED = """\
- groups:
  - system:bootstrappers
  - system:nodes
  rolearn: arn:aws:iam::111122223333:role/node-role
  username: system:node:{{EC2PrivateDNSName}}
- groups:
  - system:masters
  rolearn: arn:aws:iam::111122223333:role/Admin
  username: admin
"""

# Fully quoted style, as written by the EKS console and some CI tooling.
QUOTED = """\
- "groups":
  - "system:masters"
  "userarn": "arn:aws:iam::111122223333:user/ci-deploy-user"
  "username": "cluster-admin"
- "groups":
  - "cluster-reader"
  "userarn": "arn:aws:iam::111122223333:user/qa"
  "username": "qa"
"""


def _configmap(map_roles="", map_users="", map_accounts="[]\n"):
    return {
        "kind": "ConfigMap",
        "metadata": {"name": "aws-auth", "namespace": "kube-system"},
        "data": {"mapRoles": map_roles, "mapUsers": map_users, "mapAccounts": map_accounts},
    }


def test_unquoted_map_roles_parses():
    mappings = awsauth.parse_aws_auth(_configmap(map_roles=UNQUOTED))
    assert len(mappings) == 2
    node, admin = mappings
    assert node.arn.endswith("role/node-role")
    assert node.kind == "IAM role"
    assert node.groups == ("system:bootstrappers", "system:nodes")
    assert node.username == "system:node:{{EC2PrivateDNSName}}"
    assert admin.is_master


def test_quoted_map_users_parses():
    mappings = awsauth.parse_aws_auth(_configmap(map_users=QUOTED))
    assert len(mappings) == 2
    repo, qa = mappings
    assert repo.arn == "arn:aws:iam::111122223333:user/ci-deploy-user"
    assert repo.kind == "IAM user"
    assert repo.username == "cluster-admin"
    assert repo.is_master
    assert qa.groups == ("cluster-reader",)
    assert not qa.is_master


def test_userarn_and_rolearn_normalise_to_one_field():
    mappings = awsauth.parse_aws_auth(_configmap(map_roles=UNQUOTED, map_users=QUOTED))
    assert all(m.arn.startswith("arn:aws:iam::") for m in mappings)


def test_kind_follows_the_arn_not_the_block():
    """Operators do put roles in mapUsers; the ARN is authoritative."""
    misplaced = '- "groups": ["system:masters"]\n  "userarn": "arn:aws:iam::111122223333:role/Oops"\n'
    mappings = awsauth.parse_aws_auth(_configmap(map_users=misplaced))
    assert mappings and mappings[0].kind == "IAM role"


def test_empty_map_accounts_yields_nothing():
    assert awsauth.map_accounts(_configmap()) == ()


def test_populated_map_accounts_is_read():
    cm = _configmap(map_accounts='- "444455556666"\n')
    assert awsauth.map_accounts(cm) == ("444455556666",)


def test_map_accounts_is_read_without_pyyaml(monkeypatch):
    """mapAccounts is a sequence of bare scalars, not of mappings.

    The fallback parser originally assumed every top-level element opened a
    mapping and produced the string '{}' for each account.
    """
    monkeypatch.setattr(awsauth, "yaml", None)
    cm = _configmap(map_accounts='- "444455556666"\n- 999988887777\n')
    assert awsauth.map_accounts(cm) == ("444455556666", "999988887777")


@pytest.mark.parametrize(
    "block",
    [
        '- "444455556666"\n',
        "- 444455556666\n- 999988887777\n",
        "[]\n",
        "",
    ],
    ids=["quoted", "multiple-unquoted", "empty-inline", "blank"],
)
def test_fallback_map_accounts_agrees_with_pyyaml(block, monkeypatch):
    with_yaml = awsauth.map_accounts(_configmap(map_accounts=block))
    monkeypatch.setattr(awsauth, "yaml", None)
    assert awsauth.map_accounts(_configmap(map_accounts=block)) == with_yaml


def test_inline_flow_sequence_for_groups(monkeypatch):
    """`groups: [system:masters]` is valid YAML and appears in real ConfigMaps."""
    block = (
        "- groups: [system:masters, system:nodes]\n"
        "  rolearn: arn:aws:iam::111122223333:role/Multi\n"
    )
    with_yaml = awsauth.parse_aws_auth(_configmap(map_roles=block))
    assert with_yaml[0].groups == ("system:masters", "system:nodes")

    monkeypatch.setattr(awsauth, "yaml", None)
    assert awsauth.parse_aws_auth(_configmap(map_roles=block)) == with_yaml


def test_colon_inside_a_value_is_not_read_as_a_key(monkeypatch):
    """ARNs and group names are full of colons; only `key: value` is a mapping."""
    monkeypatch.setattr(awsauth, "yaml", None)
    mappings = awsauth.parse_aws_auth(_configmap(map_roles=UNQUOTED))
    assert mappings[0].arn == "arn:aws:iam::111122223333:role/node-role"
    assert mappings[0].username == "system:node:{{EC2PrivateDNSName}}"


def test_missing_configmap_yields_no_mappings():
    assert awsauth.parse_aws_auth(None) == ()
    assert awsauth.parse_aws_auth({}) == ()
    assert awsauth.parse_aws_auth({"data": "not-a-dict"}) == ()


def test_account_id_is_derived_from_the_mappings():
    mappings = awsauth.parse_aws_auth(_configmap(map_roles=UNQUOTED))
    assert awsauth.account_id(mappings) == "111122223333"


def test_account_id_prefers_the_most_common_account():
    """Cross-account mappings are legal; the cluster's own account should win."""
    mixed = (
        "- groups: [system:masters]\n  rolearn: arn:aws:iam::111122223333:role/A\n"
        "- groups: [system:masters]\n  rolearn: arn:aws:iam::111122223333:role/B\n"
        "- groups: [system:masters]\n  rolearn: arn:aws:iam::999988887777:role/C\n"
    )
    mappings = awsauth.parse_aws_auth(_configmap(map_roles=mixed))
    assert awsauth.account_id(mappings) == "111122223333"


def test_principal_name_is_the_arn_tail():
    mappings = awsauth.parse_aws_auth(_configmap(map_users=QUOTED))
    assert mappings[0].principal_name == "ci-deploy-user"


@pytest.mark.parametrize("block", [UNQUOTED, QUOTED])
def test_fallback_parser_agrees_with_pyyaml(block, monkeypatch):
    """The stdlib fallback must produce identical results to PyYAML.

    Without this the tool would behave differently on a machine that happens to
    lack PyYAML — the worst kind of environment-dependent bug for an audit tool.
    """
    with_yaml = awsauth.parse_aws_auth(_configmap(map_roles=block))
    monkeypatch.setattr(awsauth, "yaml", None)
    without_yaml = awsauth.parse_aws_auth(_configmap(map_roles=block))
    assert with_yaml == without_yaml


def test_fallback_parser_agrees_on_the_real_fixture(fixtures_dir, monkeypatch):
    with open(os.path.join(fixtures_dir, "aws-auth.json"), encoding="utf-8") as handle:
        configmap = json.load(handle)

    with_yaml = awsauth.parse_aws_auth(configmap)
    monkeypatch.setattr(awsauth, "yaml", None)
    without_yaml = awsauth.parse_aws_auth(configmap)

    assert with_yaml == without_yaml
    assert len(with_yaml) > 5, "fixture should exercise a realistic number of mappings"
