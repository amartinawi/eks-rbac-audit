#!/usr/bin/env python3
"""EKS RBAC & API Authentication Audit — read-only Kubernetes RBAC scanner and HTML reporter.

Audits any kubectl context for Kubernetes RBAC and EKS authentication weaknesses
and produces one self-contained HTML report that opens offline.

READ-ONLY GUARANTEE
    Against the cluster this tool issues only `get`, `auth can-i`, `version`,
    `cluster-info`, and the read-only krew plugins `rbac-lookup` and `who-can`.
    It never creates, updates, patches, deletes, or applies anything, and the
    allowlist that enforces this is checked in code before any command runs.
    On AWS it calls only `eks describe-cluster`, `eks list-access-entries`,
    `eks describe-access-entry`, and `eks list-associated-access-policies`.

    Two optional actions write to the local machine, never to the cluster:
    installing krew plugins under ~/.krew (disable with --no-install) and
    switching the kubeconfig context (only with --use-context; by default the
    context is passed per command, leaving ~/.kube/config untouched).

Examples:
    python3 eks_rbac_audit.py                                 # current context
    python3 eks_rbac_audit.py --context my-cluster --open
    python3 eks_rbac_audit.py --context my-cluster --keep-data --work-dir ./audit
    python3 eks_rbac_audit.py --no-aws --no-install -q
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import webbrowser
from dataclasses import asdict, replace
from datetime import datetime, timezone

# Allow running as a plain script from the project directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eksaudit import __version__, analyze, collector, eksapi, render, tooling
from eksaudit.config import DEFAULT_THRESHOLDS, DEFAULT_TIMEOUT_SECONDS
from eksaudit.kubectl import ClusterUnreachable, ReadOnlyViolation, Runner, ToolMissing
from eksaudit.models import AuditResult

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eks_rbac_audit",
        description=(
            "Read-only Kubernetes RBAC + EKS API authentication audit -> self-contained "
            "HTML report."
        ),
        epilog=(
            "Read-only guarantee: only get / auth can-i / version / cluster-info and the "
            "read-only rbac-lookup and who-can plugins are ever run against the cluster; "
            "AWS calls are limited to eks describe-cluster and the access-entry list/describe "
            "operations. Nothing is created, updated, patched, or deleted. The only optional "
            "local writes are krew plugin installation (--no-install to skip) and the "
            "kubeconfig context switch (--use-context, off by default)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--context", metavar="NAME",
                        help="kubectl context to audit (default: the current context).")
    parser.add_argument("--output", metavar="PATH",
                        help="HTML output path "
                             "(default: eks_rbac_auth_audit_<context>_<date>.html).")
    parser.add_argument("--work-dir", metavar="DIR",
                        help="Directory for raw JSON/text dumps (default: a temp dir).")
    parser.add_argument("--keep-data", action="store_true",
                        help="Retain the raw dumps for forensics instead of deleting them.")
    parser.add_argument("--json", metavar="PATH", dest="json_path",
                        help="Also write the structured findings as JSON.")
    parser.add_argument("--open", action="store_true", dest="open_report",
                        help="Open the finished report in the default browser.")
    parser.add_argument("--no-install", action="store_true",
                        help="Never install krew plugins; skip those sections instead.")
    parser.add_argument("--no-aws", action="store_true",
                        help="Skip the read-only EKS control-plane enrichment.")
    parser.add_argument("--use-context", action="store_true",
                        help="Switch the kubeconfig context instead of passing --context "
                             "per command (writes ~/.kube/config).")
    parser.add_argument("--admin-threshold", type=int,
                        default=DEFAULT_THRESHOLDS.admin_threshold,
                        help="Standing cluster-admin count above which a finding is raised "
                             f"(default: {DEFAULT_THRESHOLDS.admin_threshold}).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        help=f"Per-command timeout in seconds "
                             f"(default: {DEFAULT_TIMEOUT_SECONDS}).")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only print the final summary.")
    parser.add_argument("--version", action="version",
                        version=f"eks_rbac_audit {__version__}")
    return parser


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def slugify(text: str) -> str:
    """Turn a context name into a filename-safe slug.

    Contexts are often full cluster ARNs, so the trailing cluster name is used
    in preference to the whole ARN.
    """
    candidate = text.rsplit("/", 1)[-1] if "/" in text else text
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", candidate).strip("-.")
    return slug or "cluster"


def default_output(context: str, generated_at: datetime) -> str:
    return (
        f"eks_rbac_auth_audit_{slugify(context)}_"
        f"{generated_at.strftime('%Y-%m-%d')}.html"
    )


def resolve_context(runner: Runner, requested: str | None) -> str:
    """Pick the context to audit and confirm the kubeconfig knows it."""
    contexts = collector.list_contexts(runner)
    if requested:
        if contexts and requested not in contexts:
            raise ValueError(
                f"context {requested!r} is not in the kubeconfig. "
                f"Available: {', '.join(sorted(contexts)) or '(none)'}"
            )
        return requested

    current = collector.current_context(runner)
    if not current:
        raise ValueError(
            "no current kubectl context is set; pass --context NAME to choose one."
        )
    return current


def findings_json(result: AuditResult, generated_at: datetime) -> str:
    """Serialise the findings and key counts for downstream tooling."""
    payload = {
        "generated_at": generated_at.isoformat(),
        "tool_version": __version__,
        "context": result.meta.context,
        "cluster": result.meta.cluster_name,
        "account_id": result.meta.account_id,
        "region": result.meta.region,
        "server_version": result.meta.server_version,
        "authentication_mode": result.eks.authentication_mode if result.eks else None,
        "severity_counts": result.severity_counts,
        "findings": [asdict(f) for f in result.findings],
        "positives": list(result.positives),
        "warnings": list(result.warnings),
        "mapped_principals": [asdict(m) for m in result.mappings],
        "commands": [asdict(c) for c in result.commands],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _log(quiet: bool, message: str) -> None:
    if not quiet:
        print(message, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    generated_at = datetime.now(timezone.utc)
    thresholds = replace(DEFAULT_THRESHOLDS, admin_threshold=args.admin_threshold)

    probe = Runner(timeout=args.timeout, allow_local_writes=args.use_context)
    try:
        probe.resolve_binary()
        context = resolve_context(probe, args.context)
    except ToolMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    runner = Runner(
        context=context,
        timeout=args.timeout,
        allow_local_writes=not args.no_install or args.use_context,
    )

    if args.use_context:
        switched = collector.switch_context(runner, context)
        if not switched.ok:
            print(f"error: could not switch context: {switched.stderr.strip()}", file=sys.stderr)
            return EXIT_USAGE

    _log(args.quiet, f"Auditing context '{context}' (read-only)…")

    work_dir, cleanup = _prepare_work_dir(args)
    exit_code = EXIT_OK
    try:
        status = tooling.detect(runner, allow_install=not args.no_install)
        if status.plugins:
            _log(args.quiet, f"krew plugins available: {', '.join(status.plugins)}")

        try:
            raw = collector.gather(runner, work_dir, status)
        except ClusterUnreachable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_UNREACHABLE

        eks_access, aws_warnings = _collect_eks(runner, context, args)

        result = analyze.analyze(
            raw,
            eks=eks_access,
            thresholds=thresholds,
            commands=runner.commands(),
            extra_warnings=aws_warnings,
        )

        output = args.output or default_output(context, generated_at)
        path = render.render_report(result, generated_at, output, thresholds)

        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as handle:
                handle.write(findings_json(result, generated_at))

        _print_summary(result, path, work_dir if args.keep_data else "", args)

        if args.open_report:
            webbrowser.open(f"file://{path}")
    except ReadOnlyViolation as exc:
        # Should be unreachable: every command is built from the allowlist. If it
        # ever fires, the audit is aborted rather than continued.
        print(f"error: read-only guarantee would be violated: {exc}", file=sys.stderr)
        exit_code = EXIT_USAGE
    finally:
        cleanup()

    return exit_code


def _prepare_work_dir(args):
    """Return ``(path, cleanup)``; cleanup is a no-op when the data is kept."""
    if args.work_dir:
        os.makedirs(args.work_dir, exist_ok=True)
        return os.path.abspath(args.work_dir), lambda: None

    path = tempfile.mkdtemp(prefix="eks-rbac-audit-")
    if args.keep_data:
        return path, lambda: None
    return path, lambda: shutil.rmtree(path, ignore_errors=True)


def _collect_eks(runner: Runner, context: str, args):
    """Best-effort EKS control-plane enrichment; never fatal."""
    if args.no_aws:
        return None, ()

    ref, warning = eksapi.resolve_cluster(runner, context)
    if ref is None:
        return None, ((warning,) if warning else ())

    access, warnings = eksapi.collect(runner, ref)
    if warning:
        warnings = (warning,) + tuple(warnings)
    return access, tuple(warnings)


def _print_summary(result: AuditResult, path: str, work_dir: str, args) -> None:
    counts = result.severity_counts
    print("", file=sys.stderr)
    print(
        f"Done. {len(result.findings)} finding(s): "
        f"{counts.get('CRITICAL', 0)} critical, {counts.get('HIGH', 0)} high, "
        f"{counts.get('MEDIUM', 0)} medium, {counts.get('LOW', 0)} low, "
        f"{counts.get('INFORMATIONAL', 0)} informational.",
        file=sys.stderr,
    )
    if result.warnings and not args.quiet:
        print(f"Caveats: {len(result.warnings)} (listed in the report).", file=sys.stderr)
    print(f"Report:  {path}", file=sys.stderr)
    if args.json_path:
        print(f"JSON:    {os.path.abspath(args.json_path)}", file=sys.stderr)
    if work_dir:
        print(f"Data:    {work_dir}/", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
