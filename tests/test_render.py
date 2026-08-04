"""HTML rendering: self-containment, escaping, determinism, and completeness."""

import dataclasses
import os
import re
from datetime import datetime, timezone

import pytest

from eksaudit import analyze, render
from eksaudit.models import AccessEntry, AccessPolicy, EksAccess

GENERATED_AT = datetime(2026, 8, 4, 10, 18, tzinfo=timezone.utc)

# Any of these in the output means the report needs the network to render fully.
EXTERNAL_REFERENCE = re.compile(r"""(?:src|href)\s*=\s*["'](?!#)([^"']+)""", re.I)


@pytest.fixture
def html(raw_dump):
    return render.render_html(analyze.analyze(raw_dump), GENERATED_AT)


# --------------------------------------------------------------------------- #
# Self-containment
# --------------------------------------------------------------------------- #
def test_report_has_no_external_references(html):
    external = EXTERNAL_REFERENCE.findall(html)
    assert external == [], f"report must open offline; found {external}"


def test_report_contains_no_remote_urls(html):
    """Catches CDN imports inside CSS (@import, url()) that the regex above misses."""
    for marker in ("http://", "https://", "//cdn", "@import"):
        assert marker not in html, f"unexpected remote reference: {marker}"


def test_stylesheet_is_inlined_intact(html):
    """Autoescaping the CSS would silently break font and selector declarations."""
    assert "<style>" in html
    assert "'Segoe UI'" in html, "quoted font names must survive"
    assert "details.collapsible > summary" in html, "child combinators must survive"
    assert "&#39;" not in html.split("</style>")[0], "CSS must not be HTML-escaped"


# --------------------------------------------------------------------------- #
# Escaping
# --------------------------------------------------------------------------- #
def test_hostile_cluster_names_are_escaped(clean_dump):
    """Object names come from the cluster and must never be treated as markup."""
    payload = "<script>alert(1)</script>"
    roles = clean_dump.cluster_roles + (
        {
            "metadata": {"name": payload},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        },
    )
    result = analyze.analyze(dataclasses.replace(clean_dump, cluster_roles=roles))
    output = render.render_html(result, GENERATED_AT)

    assert payload not in output
    assert "&lt;script&gt;" in output


def test_hostile_arns_are_escaped(clean_dump):
    configmap = {
        "data": {
            "mapRoles": (
                '- groups:\n  - system:masters\n'
                '  rolearn: "arn:aws:iam::111122223333:role/<img src=x onerror=alert(1)>"\n'
                "  username: evil\n"
            ),
            "mapUsers": "[]\n",
            "mapAccounts": "[]\n",
        }
    }
    result = analyze.analyze(dataclasses.replace(clean_dump, aws_auth=configmap))
    output = render.render_html(result, GENERATED_AT)

    assert "<img src=x" not in output
    assert "&lt;img" in output


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #
def test_rendering_is_byte_identical_across_runs(raw_dump):
    result = analyze.analyze(raw_dump)
    assert render.render_html(result, GENERATED_AT) == render.render_html(result, GENERATED_AT)


def test_only_the_timestamp_varies_between_runs(raw_dump):
    """Re-running against unchanged cluster state must produce the same report."""
    result = analyze.analyze(raw_dump)
    later = datetime(2026, 8, 5, 9, 0, tzinfo=timezone.utc)

    first = render.render_html(result, GENERATED_AT)
    second = render.render_html(result, later)

    normalise = lambda text: text.replace(  # noqa: E731
        GENERATED_AT.strftime("%Y-%m-%d %H:%M UTC"), "<TS>"
    ).replace(later.strftime("%Y-%m-%d %H:%M UTC"), "<TS>")
    assert normalise(first) == normalise(second)


# --------------------------------------------------------------------------- #
# Completeness
# --------------------------------------------------------------------------- #
def test_every_finding_title_appears(raw_dump, html):
    import html as html_mod

    for finding in analyze.analyze(raw_dump).findings:
        assert html_mod.escape(finding.title, quote=False) in html, finding.title


def test_every_mapped_principal_appears(raw_dump, html):
    for mapping in analyze.analyze(raw_dump).mappings:
        assert mapping.principal_name in html


def test_methodology_lists_the_commands_that_ran(raw_dump):
    from eksaudit.models import CommandRecord

    commands = (
        CommandRecord(label="version", command="kubectl version", exit_code=0),
        CommandRecord(label="crb", command="kubectl get clusterrolebindings -o json", exit_code=0),
    )
    result = analyze.analyze(raw_dump, commands=commands)
    output = render.render_html(result, GENERATED_AT)

    assert "kubectl get clusterrolebindings -o json" in output


def test_cluster_name_is_shown_when_known(clean_dump):
    eks = EksAccess(cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo-prod",
                    authentication_mode="API")
    output = render.render_html(analyze.analyze(clean_dump, eks=eks), GENERATED_AT)

    assert "<title>EKS RBAC &amp; API Authentication Audit — demo-prod</title>" in output
    assert 'class="cluster">demo-prod' in output


def test_context_stands_in_when_the_cluster_name_is_unknown(html):
    assert 'class="cluster">fixture-context' in html


def test_access_entry_section_renders(clean_dump):
    eks = EksAccess(
        cluster_arn="arn:aws:eks:eu-west-1:111122223333:cluster/demo",
        authentication_mode="API",
        access_entries=(
            AccessEntry(
                principal_arn="arn:aws:iam::111122223333:role/Deployer",
                username="deployer",
                policies=(AccessPolicy(name="AmazonEKSClusterAdminPolicy", scope_type="cluster"),),
            ),
        ),
        enabled_log_types=("audit", "authenticator"),
    )
    output = render.render_html(analyze.analyze(clean_dump, eks=eks), GENERATED_AT)

    assert 'id="entries"' in output
    assert "AmazonEKSClusterAdminPolicy" in output


def test_eks_sections_are_omitted_for_non_eks_clusters(clean_dump):
    result = analyze.analyze(dataclasses.replace(clean_dump, aws_auth=None))
    output = render.render_html(result, GENERATED_AT)

    assert 'id="auth"' not in output, "no aws-auth section without an aws-auth ConfigMap"
    assert 'id="entries"' not in output
    assert 'id="rbac"' in output, "the RBAC audit must still be reported"


def test_non_eks_report_drops_the_eks_framing(clean_dump):
    """On a cluster with no EKS identity layer, EKS wording is simply wrong."""
    result = analyze.analyze(dataclasses.replace(clean_dump, aws_auth=None))
    output = render.render_html(result, GENERATED_AT)

    assert "Kubernetes RBAC &amp; API Authentication Audit" in output
    assert "EKS RBAC &amp; API Authentication Audit" not in output
    assert "IAM principals mapped" not in output, "a 0 IAM tile reads as a finding, not an absence"
    assert "ClusterRoleBindings" in output


def test_eks_report_keeps_the_eks_framing(html):
    assert "EKS RBAC &amp; API Authentication Audit" in html
    assert "IAM principals mapped" in html


def test_warnings_are_surfaced(clean_dump):
    result = analyze.analyze(clean_dump, extra_warnings=("who-can was unavailable",))
    output = render.render_html(result, GENERATED_AT)
    assert "who-can was unavailable" in output


# --------------------------------------------------------------------------- #
# Writing to disk
# --------------------------------------------------------------------------- #
def test_render_report_writes_the_file(raw_dump, tmp_path):
    destination = tmp_path / "nested" / "report.html"
    written = render.render_report(analyze.analyze(raw_dump), GENERATED_AT, str(destination))

    assert os.path.isfile(written)
    with open(written, encoding="utf-8") as handle:
        assert handle.read().startswith("<!doctype html>")
