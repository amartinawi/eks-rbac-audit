"""krew plugin detection and the --no-install contract."""

from test_collector import FakeRunner

from eksaudit import tooling


def _patch(monkeypatch, krew=True, installed=()):
    monkeypatch.setattr(tooling, "_krew_installed", lambda: krew)
    monkeypatch.setattr(tooling, "_plugin_installed", lambda name: name in installed)


def test_missing_krew_degrades_with_a_warning(monkeypatch):
    _patch(monkeypatch, krew=False)
    status = tooling.detect(FakeRunner(), allow_install=True)

    assert status.krew is False
    assert status.plugins == ()
    assert any("krew" in w for w in status.warnings)


def test_already_installed_plugins_are_detected(monkeypatch):
    _patch(monkeypatch, installed=("rbac-lookup", "who-can"))
    runner = FakeRunner()
    status = tooling.detect(runner, allow_install=True)

    assert status.has("rbac-lookup") and status.has("who-can")
    assert status.warnings == ()
    assert runner.labels == [], "nothing should be installed when both are present"


def test_no_install_skips_missing_plugins(monkeypatch):
    """--no-install must never write to the local machine."""
    _patch(monkeypatch, installed=("rbac-lookup",))
    runner = FakeRunner()
    status = tooling.detect(runner, allow_install=False)

    assert status.has("rbac-lookup")
    assert not status.has("who-can")
    assert runner.labels == [], "no install command may run under --no-install"
    assert any("who-can" in w and "--no-install" in w for w in status.warnings)


def test_missing_plugin_is_installed_when_permitted(monkeypatch):
    state = {"installed": {"rbac-lookup"}}
    monkeypatch.setattr(tooling, "_krew_installed", lambda: True)
    monkeypatch.setattr(tooling, "_plugin_installed", lambda n: n in state["installed"])

    class InstallingRunner(FakeRunner):
        def run_local(self, label, args, note=""):
            state["installed"].add(args[-1])
            return super().run_local(label, args, note)

    runner = InstallingRunner()
    status = tooling.detect(runner, allow_install=True)

    assert status.has("who-can")
    assert "krew-install-who-can" in runner.labels


def test_failed_install_warns_and_skips_the_section(monkeypatch):
    _patch(monkeypatch, installed=())
    runner = FakeRunner({
        "krew-install-rbac-lookup": ("", "network unreachable", 1),
        "krew-install-who-can": ("", "network unreachable", 1),
    })
    status = tooling.detect(runner, allow_install=True)

    assert status.plugins == ()
    assert len(status.warnings) == 2
    assert all("network unreachable" in w for w in status.warnings)


def test_status_reports_unknown_plugins_as_absent(monkeypatch):
    _patch(monkeypatch, installed=("who-can",))
    status = tooling.detect(FakeRunner(), allow_install=False)
    assert not status.has("something-else")
