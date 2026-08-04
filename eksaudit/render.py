"""Render one self-contained HTML report.

Loads the Jinja template plus the CSS asset, inlines the asset, and writes a
single offline file. Autoescaping is on for every value: role names, usernames,
and ARNs come from the cluster and must never be trusted as markup.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

from . import __version__
from .config import (
    MASTERS_GROUP,
    NODE_GROUPS,
    SEVERITY_ALWAYS_SHOWN,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    Thresholds,
    DEFAULT_THRESHOLDS,
)
from .models import AuditResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES = os.path.join(_HERE, "templates")
_ASSETS = os.path.join(_HERE, "assets")

_ACCOUNT_IN_ARN = re.compile(r"^(arn:aws[\w-]*:[\w-]+::?)(\d{12})(:.*)$")


def _read_asset(name: str) -> Markup:
    """Read a first-party asset for inlining.

    Marked safe deliberately: this is our own stylesheet, never cluster data.
    Escaping it would corrupt the CSS — quoted font names become ``&#39;`` and
    child combinators become ``&gt;``, silently breaking the declarations.
    """
    with open(os.path.join(_ASSETS, name), encoding="utf-8") as handle:
        return Markup(handle.read())


# --------------------------------------------------------------------------- #
# Filters
# --------------------------------------------------------------------------- #
def _severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, "#5b6470")


def _arn(value: str) -> Markup:
    """Render an ARN with the account id de-emphasised and the name bolded.

    Every row in the principal table repeats the same 12-digit account, so
    dimming it lets the eye land on the part that actually differs.
    """
    text = str(value)
    match = _ACCOUNT_IN_ARN.match(text)
    if not match:
        return Markup(f'<span class="mono arn">{escape(text)}</span>')

    prefix, account, rest = match.groups()
    if "/" in rest:
        path, _, name = rest.rpartition("/")
        tail = Markup(
            f'<span class="dim">{escape(path)}/</span><span class="name">{escape(name)}</span>'
        )
    else:
        tail = Markup(f'<span class="dim">{escape(rest)}</span>')

    return Markup(
        f'<span class="mono arn"><span class="dim">{escape(prefix)}'
        f'{escape(account)}</span>{tail}</span>'
    )


def _group_chip(group: str) -> Markup:
    """A group name as a coloured chip; masters and node groups stand out."""
    text = str(group)
    if text == MASTERS_GROUP:
        css = "grp master"
    elif text in NODE_GROUPS:
        css = "grp node"
    else:
        css = "grp"
    return Markup(f'<span class="{css}">{escape(text)}</span>')


def _build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES),
        autoescape=select_autoescape(["html", "j2", "html.j2"], default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["sev_color"] = _severity_color
    env.filters["arn"] = _arn
    env.filters["group_chip"] = _group_chip
    return env


# --------------------------------------------------------------------------- #
# View model
# --------------------------------------------------------------------------- #
def build_view(
    result: AuditResult,
    generated_at: datetime,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    """Flatten the audit result into exactly what the template renders.

    Keeping the shaping here means the template stays declarative and the
    numbers shown in the report can be asserted directly in tests.
    """
    counts = result.severity_counts
    posture = result.sa_posture
    inv = result.inventory

    severity_bar = tuple(
        {"name": name, "count": counts.get(name, 0), "color": SEVERITY_COLORS[name]}
        for name in SEVERITY_ORDER
        if counts.get(name, 0) > 0 or name in SEVERITY_ALWAYS_SHOWN
    )

    admin_count = len(result.masters)
    if result.eks is not None:
        admin_count += sum(1 for e in result.eks.access_entries if e.grants_cluster_admin)

    # On a cluster with no EKS identity layer the IAM tiles would read "0 / 0",
    # which looks like a finding rather than an absence. Swap in the RBAC facts
    # that do mean something there.
    is_eks_report = result.aws_auth_present or result.eks is not None
    if is_eks_report:
        identity_tiles = (
            {"n": len(result.mappings), "label": "IAM principals mapped", "color": None},
            {"n": admin_count, "label": "cluster-admin principals",
             "color": SEVERITY_COLORS["CRITICAL"] if admin_count else None},
        )
    else:
        admin_subjects = len({subject for _, subject, _ in inv.cluster_admin_paths})
        identity_tiles = (
            {"n": len(inv.cluster_role_bindings), "label": "ClusterRoleBindings", "color": None},
            {"n": admin_subjects, "label": "cluster-admin subjects",
             "color": SEVERITY_COLORS["CRITICAL"] if admin_subjects else None},
        )

    return {
        "is_eks_report": is_eks_report,
        "version": __version__,
        "generated_at": generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        "meta": result.meta,
        "result": result,
        "summary": result.summary,
        "positives": result.positives,
        "warnings": result.warnings,
        "findings": result.findings,
        "severity_bar": severity_bar,
        "mappings": result.mappings,
        "eks": result.eks,
        "inventory": inv,
        "posture": posture,
        "commands": result.commands,
        "collapse_after": thresholds.large_table_rows,
        "tiles": identity_tiles + (
            {"n": len(inv.custom_cluster_roles), "label": "custom ClusterRoles", "color": None},
            {"n": len(result.findings), "label": "total findings", "color": None},
            {"n": len(inv.namespaces), "label": "namespaces", "color": None},
            {"n": posture.total, "label": "service accounts", "color": None},
        ),
        "inventory_rows": (
            ("Namespaces", str(len(inv.namespaces))),
            ("ClusterRoles / ClusterRoleBindings",
             f"{len(inv.cluster_roles)} / {len(inv.cluster_role_bindings)}"),
            ("Roles / RoleBindings (namespaced)",
             f"{len(inv.roles)} / {len(inv.role_bindings)}"),
            ("ServiceAccounts", str(posture.total)),
            ("Custom (operator-defined) ClusterRoles / ClusterRoleBindings",
             f"{len(inv.custom_cluster_roles)} / {len(inv.custom_cluster_role_bindings)}"),
        ),
        "sa_rows": (
            ("Total ServiceAccounts", str(posture.total), False),
            ("Explicitly disable token automount", str(posture.automount_disabled), False),
            ("Implicitly mount a token (Kubernetes default)",
             str(posture.implicitly_mounting), False),
            ("Per-namespace default ServiceAccounts", str(posture.default_count), False),
            ("default ServiceAccounts bound to a Role or ClusterRole",
             str(len(posture.default_bound)), not posture.default_bound),
        ),
    }


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def render_html(
    result: AuditResult,
    generated_at: datetime,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> str:
    """Return the complete HTML document as a string."""
    env = _build_env()
    template = env.get_template("report.html.j2")
    view = build_view(result, generated_at, thresholds)
    view["styles"] = _read_asset("styles.css")
    return template.render(**view)


def render_report(
    result: AuditResult,
    generated_at: datetime,
    output_path: str,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> str:
    """Write the report to ``output_path`` and return the absolute path."""
    html = render_html(result, generated_at, thresholds)
    directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return os.path.abspath(output_path)
