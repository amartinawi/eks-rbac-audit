"""Detect (and optionally install) the krew plugins the audit can use.

``rbac-lookup`` and ``who-can`` make the effective-permission sections far
richer, but neither is required: when a plugin is unavailable the corresponding
report section is skipped and a warning is recorded. Installing a plugin writes
only to ``~/.krew`` on the local machine — it never touches the cluster.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from .config import KREW_PLUGINS
from .kubectl import Runner, _krew_bin

# krew installs plugins as `kubectl-<name with dashes replaced by underscores>`.
_PLUGIN_BINARIES = {
    "rbac-lookup": "kubectl-rbac_lookup",
    "who-can": "kubectl-who_can",
}


@dataclass(frozen=True)
class ToolingStatus:
    """Which optional plugins are usable for this run."""

    krew: bool = False
    plugins: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def has(self, plugin: str) -> bool:
        return plugin in self.plugins


def _plugin_installed(plugin: str) -> bool:
    binary = _PLUGIN_BINARIES.get(plugin, f"kubectl-{plugin.replace('-', '_')}")
    search_path = os.pathsep.join([_krew_bin(), os.environ.get("PATH", "")])
    return shutil.which(binary, path=search_path) is not None


def _krew_installed() -> bool:
    search_path = os.pathsep.join([_krew_bin(), os.environ.get("PATH", "")])
    return shutil.which("kubectl-krew", path=search_path) is not None


def detect(runner: Runner, allow_install: bool = True) -> ToolingStatus:
    """Return which plugins are available, installing the missing ones if permitted.

    Never raises: a machine without krew simply yields a status with empty
    ``plugins`` and an explanatory warning.
    """
    warnings: list[str] = []
    krew = _krew_installed()

    if not krew:
        warnings.append(
            "kubectl krew is not installed — the rbac-lookup and who-can sections "
            "are skipped. See https://krew.sigs.k8s.io/docs/user-guide/setup/install/"
        )
        return ToolingStatus(krew=False, plugins=(), warnings=tuple(warnings))

    available: list[str] = []
    for plugin in KREW_PLUGINS:
        if _plugin_installed(plugin):
            available.append(plugin)
            continue
        if not allow_install:
            warnings.append(
                f"krew plugin '{plugin}' is not installed and --no-install was given "
                f"— its report section is skipped."
            )
            continue
        result = runner.run_local(
            f"krew-install-{plugin}",
            ["krew", "install", plugin],
            note="installs a kubectl plugin under ~/.krew (local machine only)",
        )
        if result.ok and _plugin_installed(plugin):
            available.append(plugin)
        else:
            detail = (result.stderr or result.stdout or "unknown error").strip().splitlines()
            warnings.append(
                f"could not install krew plugin '{plugin}': "
                f"{detail[-1] if detail else 'unknown error'} — its section is skipped."
            )

    return ToolingStatus(krew=True, plugins=tuple(available), warnings=tuple(warnings))
