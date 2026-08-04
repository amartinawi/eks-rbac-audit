# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08-04

First release.

### Added

- **Read-only RBAC and EKS authentication audit** for any kubectl context,
  producing one self-contained HTML report that opens offline.
- **17 finding rules** covering deceptively-named roles, machine identities with
  standing cluster-admin, EKS access entries, node-role mapping, anonymous
  access, wildcard roles, `default` ServiceAccount exposure, privilege-escalation
  verbs, credential minting, `aws-auth` posture, control-plane exposure, and
  ServiceAccount token posture. See [docs/findings.md](docs/findings.md).
- **Optional EKS control-plane enrichment** reading `authenticationMode`, access
  entries, endpoint exposure, and control-plane logging. Access entries are
  evaluated before the `aws-auth` ConfigMap and are invisible to Kubernetes RBAC
  alone, so this surfaces admins no kubectl-only audit can see.
- **Non-EKS support.** OpenShift, kind, and plain Kubernetes get the full RBAC
  audit with EKS sections and framing dropped.
- **JSON export** (`--json`) with stable rule IDs for downstream tooling.
- **Forensic dumps** (`--keep-data`) laid out as `<label>.out` / `<label>.err`.

### Security

- The read-only guarantee is enforced in code. Every command passes through a
  single chokepoint that validates the verb against an allowlist before spawning
  a process; the AWS side is restricted to four describe/list operations. CI
  asserts that no mutating verb is reachable.
- The context is passed as `--context` per command rather than switching the
  kubeconfig, so `~/.kube/config` is never written and concurrent audits do not
  interfere. `--use-context` opts into the older behaviour.
- Reports are self-contained — no CDN, font, script, or remote image — so opening
  one cannot phone home. Asserted in tests.
- Cluster-supplied names are treated as untrusted and escaped throughout.

### Notes

- Roles labelled `kubernetes.io/bootstrapping: rbac-defaults` are excluded from
  operator-defined rules. Without this, the upstream `admin` and `edit`
  ClusterRoles would raise two false CRITICAL findings on every cluster.
- Output is deterministic: the same cluster state produces a report differing
  only in its timestamp.
- `kubectl who-can` cannot evaluate pod subresources, so `pods/exec` rights are
  read directly from the role rules rather than from its output.

[1.0.0]: https://github.com/amartinawi/eks-rbac-audit/releases/tag/v1.0.0
