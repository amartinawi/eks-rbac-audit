"""Collection and graceful degradation, driven by a fake Runner (no cluster needed).

These are the paths that decide whether the tool is genuinely reusable: a missing
aws-auth ConfigMap, an API group the caller cannot list, a plugin that is absent,
a webhook authorizer that refuses to enumerate rules. Every one must produce a
warning and a partial report rather than a traceback.
"""

import json
import os

import pytest

from eksaudit import collector
from eksaudit.kubectl import ClusterUnreachable, CommandResult
from eksaudit.tooling import ToolingStatus

VERSION_OUT = "Client Version: v1.32.2\nServer Version: v1.33.13-eks-8f14419\n"


class FakeRunner:
    """Returns canned output keyed by label, recording what was asked for."""

    def __init__(self, responses=None, context="fixture-context"):
        self._responses = responses or {}
        self.context = context
        self.labels = []

    def _result(self, label, argv=("kubectl",)):
        self.labels.append(label)
        canned = self._responses.get(label, ("", "", 0))
        stdout, stderr, code = canned
        return CommandResult(label=label, argv=tuple(argv), returncode=code,
                             stdout=stdout, stderr=stderr)

    def run(self, label, args, with_context=True, note=""):
        return self._result(label, ("kubectl", *args))

    def run_local(self, label, args, note=""):
        return self._result(label, ("kubectl", *args))

    def run_external(self, label, argv, note=""):
        return self._result(label, argv)

    def commands(self):
        return ()


def _json_items(*names):
    return json.dumps({"items": [{"metadata": {"name": n}} for n in names]})


ALL_PLUGINS = ToolingStatus(krew=True, plugins=("rbac-lookup", "who-can"))
NO_PLUGINS = ToolingStatus(krew=False, plugins=(), warnings=("krew is not installed",))


# --------------------------------------------------------------------------- #
# Reachability
# --------------------------------------------------------------------------- #
def test_unreachable_cluster_raises(tmp_path):
    runner = FakeRunner({"version": ("", "Unable to connect to the server", 1)})
    with pytest.raises(ClusterUnreachable):
        collector.verify_reachable(runner, str(tmp_path))


def test_client_version_alone_is_treated_as_unreachable(tmp_path):
    """kubectl prints the client version to stdout even when the server is down.

    Treating that as success makes every later command block until it times out,
    so an unreachable cluster becomes a multi-minute hang instead of a fast,
    clear failure.
    """
    client_only = "Client Version: v1.32.2\nKustomize Version: v5.5.0\n"
    error = "Unable to connect to the server: dial tcp 10.0.0.1:443: i/o timeout"
    runner = FakeRunner({"version": (client_only, error, 1)})

    with pytest.raises(ClusterUnreachable) as excinfo:
        collector.verify_reachable(runner, str(tmp_path))
    assert "i/o timeout" in str(excinfo.value), "the real cause must reach the operator"
    assert runner.labels == ["version"], "no further commands may be attempted"


def test_server_version_present_means_reachable(tmp_path):
    runner = FakeRunner({"version": (VERSION_OUT, "", 0)})
    version_text, _ = collector.verify_reachable(runner, str(tmp_path))
    assert "Server Version" in version_text


# --------------------------------------------------------------------------- #
# Context discovery
# --------------------------------------------------------------------------- #
def test_contexts_are_listed():
    runner = FakeRunner({"contexts": ("ctx-a\nctx-b\n\n", "", 0)})
    assert collector.list_contexts(runner) == ("ctx-a", "ctx-b")


def test_context_listing_failure_returns_empty():
    runner = FakeRunner({"contexts": ("", "error", 1)})
    assert collector.list_contexts(runner) == ()


def test_current_context_is_read():
    runner = FakeRunner({"current-context": ("my-cluster\n", "", 0)})
    assert collector.current_context(runner) == "my-cluster"


# --------------------------------------------------------------------------- #
# Gathering
# --------------------------------------------------------------------------- #
def test_gather_collects_every_resource(tmp_path):
    runner = FakeRunner({
        "version": (VERSION_OUT, "", 0),
        "aws-auth": (json.dumps({"data": {"mapRoles": "[]\n"}}), "", 0),
        "cr": (_json_items("cluster-admin"), "", 0),
        "crb": (_json_items("cluster-admin"), "", 0),
        "r": (_json_items("reader"), "", 0),
        "rb": (_json_items("reader-binding"), "", 0),
        "sa": (_json_items("default"), "", 0),
        "ns": (_json_items("default", "kube-system"), "", 0),
    })
    raw = collector.gather(runner, str(tmp_path), ALL_PLUGINS)

    assert raw.aws_auth is not None
    assert len(raw.cluster_roles) == 1
    assert len(raw.namespaces) == 2
    assert raw.warnings == ()


def test_missing_aws_auth_warns_but_does_not_fail(tmp_path):
    """OpenShift and plain Kubernetes have no aws-auth ConfigMap."""
    runner = FakeRunner({
        "version": (VERSION_OUT, "", 0),
        "aws-auth": ("", 'Error from server (NotFound): configmaps "aws-auth" not found', 1),
        "cr": (_json_items("cluster-admin"), "", 0),
    })
    raw = collector.gather(runner, str(tmp_path), NO_PLUGINS)

    assert raw.aws_auth is None
    assert any("aws-auth" in w for w in raw.warnings)
    assert len(raw.cluster_roles) == 1, "the RBAC audit must continue"


def test_failed_resource_dump_warns_and_continues(tmp_path):
    runner = FakeRunner({
        "version": (VERSION_OUT, "", 0),
        "cr": ("", 'Error from server (Forbidden): clusterroles is forbidden', 1),
        "ns": (_json_items("default"), "", 0),
    })
    raw = collector.gather(runner, str(tmp_path), NO_PLUGINS)

    assert raw.cluster_roles == ()
    assert any("forbidden" in w.lower() for w in raw.warnings)
    assert len(raw.namespaces) == 1


def test_unparseable_json_warns(tmp_path):
    runner = FakeRunner({"version": (VERSION_OUT, "", 0), "cr": ("not json at all", "", 0)})
    raw = collector.gather(runner, str(tmp_path), NO_PLUGINS)

    assert raw.cluster_roles == ()
    assert any("unparseable" in w for w in raw.warnings)


def test_webhook_authorizer_caveat_is_captured(tmp_path):
    warning = ("Warning: the list may be incomplete: webhook authorizer does not "
               "support user rule resolution")
    runner = FakeRunner({
        "version": (VERSION_OUT, "", 0),
        "can-i-list": ("Resources  Verbs\n*.*  [*]\n", warning, 0),
    })
    raw = collector.gather(runner, str(tmp_path), NO_PLUGINS)
    assert raw.can_i_warning == warning


def test_plugins_are_skipped_when_unavailable(tmp_path):
    runner = FakeRunner({"version": (VERSION_OUT, "", 0)})
    raw = collector.gather(runner, str(tmp_path), NO_PLUGINS)

    assert raw.rbac_lookup_text == ""
    assert raw.who_can == ()
    assert "rbac-lookup" not in runner.labels
    assert "whocan-all" not in runner.labels


def test_plugin_failure_warns_without_aborting(tmp_path):
    runner = FakeRunner({
        "version": (VERSION_OUT, "", 0),
        "whocan-exec": ("", 'Error: the server doesn\'t have a resource type "pods/exec"', 1),
        "whocan-secrets": ("CLUSTERROLEBINDING  SUBJECT\nfoo  bar\n", "", 0),
    })
    raw = collector.gather(runner, str(tmp_path), ALL_PLUGINS)

    assert raw.who_can_text("whocan-secrets") != ""
    assert raw.who_can_text("whocan-exec") == ""
    assert any("pods/exec" in w for w in raw.warnings)


def test_tooling_warnings_are_carried_into_the_dump(tmp_path):
    runner = FakeRunner({"version": (VERSION_OUT, "", 0)})
    raw = collector.gather(runner, str(tmp_path), NO_PLUGINS)
    assert "krew is not installed" in raw.warnings


# --------------------------------------------------------------------------- #
# Work-directory dumps
# --------------------------------------------------------------------------- #
def test_raw_dumps_are_written_for_forensics(tmp_path):
    runner = FakeRunner({
        "version": (VERSION_OUT, "", 0),
        "cr": (_json_items("cluster-admin"), "", 0),
    })
    work_dir = tmp_path / "work"
    collector.gather(runner, str(work_dir), NO_PLUGINS)

    assert (work_dir / "version.out").read_text() == VERSION_OUT
    assert "cluster-admin" in (work_dir / "cr.out").read_text()
    assert (work_dir / "cr.err").exists(), "stderr is captured even when empty"


def test_dump_layout_matches_the_reference_scripts(tmp_path):
    """`<label>.out` / `<label>.err` keeps older forensic directories readable."""
    runner = FakeRunner({"version": (VERSION_OUT, "", 0)})
    collector.gather(runner, str(tmp_path), NO_PLUGINS)

    written = {name for name in os.listdir(tmp_path)}
    for expected in ("version.out", "aws-auth.out", "crb.out", "cr.out", "ns.out",
                     "can-i-list.out"):
        assert expected in written
