"""The read-only guarantee, as an executable test.

If any of these ever fails, the tool can mutate a production cluster. That is
the single most important property of this project, so it is asserted here
rather than only documented in the README.
"""

import pytest

from eksaudit.kubectl import ReadOnlyViolation, Runner, assert_read_only

MUTATING_COMMANDS = [
    ["delete", "pods", "--all"],
    ["apply", "-f", "manifest.yaml"],
    ["patch", "clusterrole", "cluster-reader", "-p", "{}"],
    ["create", "namespace", "evil"],
    ["edit", "configmap", "aws-auth", "-n", "kube-system"],
    ["replace", "-f", "aws-auth.yaml"],
    ["scale", "deployment/api", "--replicas=0"],
    ["drain", "node-1"],
    ["cordon", "node-1"],
    ["taint", "nodes", "node-1", "key=value:NoSchedule"],
    ["annotate", "pod", "x", "k=v"],
    ["label", "node", "n", "k=v"],
    ["exec", "-it", "pod", "--", "sh"],
    ["run", "shell", "--image=busybox"],
    ["cp", "pod:/etc/passwd", "./passwd"],
    ["proxy"],
    ["port-forward", "pod/x", "8080:80"],
    ["rollout", "restart", "deployment/api"],
    ["set", "image", "deployment/api", "api=evil"],
    ["auth", "reconcile", "-f", "rbac.yaml"],
    ["config", "use-context", "prod"],
    ["config", "set-credentials", "me", "--token=abc"],
    ["config", "delete-context", "prod"],
]

READ_ONLY_COMMANDS = [
    ["get", "clusterroles", "-o", "json"],
    ["get", "cm", "aws-auth", "-n", "kube-system", "-o", "json"],
    ["version"],
    ["cluster-info"],
    ["api-resources"],
    ["auth", "can-i", "--list"],
    # `auth can-i create pods` asks a question; it does not create a pod.
    ["auth", "can-i", "create", "pods"],
    ["config", "view", "--minify", "-o", "json"],
    ["config", "current-context"],
    ["config", "get-contexts", "-o", "name"],
    ["rbac-lookup"],
    ["who-can", "get", "secrets", "--all-namespaces"],
    ["who-can", "create", "pods/exec", "--all-namespaces"],
]


@pytest.mark.parametrize("command", MUTATING_COMMANDS, ids=lambda c: " ".join(c[:2]))
def test_mutating_commands_are_refused(command):
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(command)


@pytest.mark.parametrize("command", READ_ONLY_COMMANDS, ids=lambda c: " ".join(c[:3]))
def test_read_only_commands_are_permitted(command):
    assert_read_only(command)  # must not raise


def test_empty_command_is_refused():
    with pytest.raises(ReadOnlyViolation):
        assert_read_only([])


def test_runner_refuses_to_execute_a_mutating_command():
    """The guard must fire in Runner.run, not only in the standalone helper."""
    runner = Runner(context="fixture-context")
    with pytest.raises(ReadOnlyViolation):
        runner.run("delete", ["delete", "clusterrole", "cluster-reader"])
    assert runner.commands() == (), "a refused command must not be recorded as run"


def test_local_writes_are_disabled_by_default():
    runner = Runner(context="fixture-context")
    with pytest.raises(ReadOnlyViolation):
        runner.run_local("switch", ["config", "use-context", "prod"])


def test_run_local_refuses_non_local_verbs_even_when_enabled():
    runner = Runner(context="fixture-context", allow_local_writes=True)
    with pytest.raises(ReadOnlyViolation):
        runner.run_local("delete", ["delete", "pods"])


def test_command_log_records_executed_commands():
    """The methodology section is built from this log, so it must be accurate."""
    runner = Runner(context="fixture-context", binary="true")
    runner.run("version", ["version"])
    records = runner.commands()
    assert len(records) == 1
    assert records[0].label == "version"
    assert records[0].command.startswith("true version")
    assert "--context fixture-context" in records[0].command


def test_context_is_passed_per_command_not_switched():
    """The audit must never depend on mutating the operator's kubeconfig."""
    runner = Runner(context="my-ctx", binary="true")
    runner.run("get", ["get", "clusterroles", "-o", "json"])
    assert runner.commands()[0].command.endswith("--context my-ctx")
