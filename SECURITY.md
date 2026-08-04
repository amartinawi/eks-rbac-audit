# Security policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/amartinawi/eks-rbac-audit/security/advisories/new).
Do not open a public issue.

Please include what the issue allows, how to reproduce it, and the version
affected. Expect an initial response within 7 days.

**Redact before you send.** Reports, work-directory dumps, and `aws-auth`
ConfigMaps contain IAM ARNs, AWS account IDs, and internal namespace names.
Replace account IDs with `111122223333` and rename real principals before
attaching anything.

## What counts as a vulnerability here

This tool reads security-sensitive configuration from clusters people care
about. The following are treated as security issues, not ordinary bugs:

| Class | Example |
|---|---|
| **Breaking the read-only guarantee** | Any path that reaches a mutating `kubectl` or AWS operation |
| **Command injection** | Cluster-controlled data (a role name, an ARN) reaching a shell |
| **Report injection** | A crafted object name executing script in a rendered report |
| **Data exfiltration** | The report or tool sending cluster data anywhere off the machine |
| **Credential exposure** | Tokens, kubeconfig contents, or Secret values written to the report or dumps |
| **A silently missed finding** | A rule that fails to fire on a cluster state it claims to cover, giving false assurance |

That last one matters as much as the others. An audit tool that quietly returns
"no findings" on a compromised cluster is worse than no tool, because it
manufactures confidence.

## Design invariants

These properties are enforced in code and asserted in CI. A change that breaks
one is a security regression regardless of intent.

### 1. Read-only against the cluster

Every command passes through `Runner` in `eksaudit/kubectl.py`, which validates
the verb against an allowlist **before** spawning a process. Anything not on the
list raises `ReadOnlyViolation`.

The permitted set is: `get`, `version`, `cluster-info`, `api-resources`,
`api-versions`, `explain`, `auth can-i`, `config view|current-context|get-contexts`,
and the read-only krew plugins `rbac-lookup` and `who-can`.

`auth can-i create pods` is permitted — it asks the API server a question and
creates nothing. `auth reconcile` is refused because it writes RBAC objects.

On AWS only four operations are ever invoked, enforced in `eksaudit/eksapi.py`:
`describe-cluster`, `list-access-entries`, `describe-access-entry`, and
`list-associated-access-policies`.

CI asserts both: `tests/test_kubectl.py` proves 23 mutating commands are refused,
and a dedicated job asserts no mutating verb is reachable in the allowlist at all.

### 2. Local writes are opt-out or opt-in, and never touch the cluster

| Action | Writes | Control |
|---|---|---|
| Installing krew plugins | `~/.krew` | `--no-install` disables |
| Switching kubeconfig context | `~/.kube/config` | off by default; `--use-context` enables |

By default the context is passed as `--context` per command, so the kubeconfig is
never modified.

### 3. No network egress beyond the cluster and AWS

The tool contacts the Kubernetes API server and the AWS EKS API. Nothing else.
Reports are self-contained: no CDN, external stylesheet, font, script, or remote
image. `tests/test_render.py` asserts the rendered HTML contains no external
reference, so a report cannot phone home when opened.

### 4. Cluster data is untrusted input

Role names, usernames, and ARNs come from the cluster and are treated as hostile.
Rendering is autoescaped throughout; `tests/test_render.py` asserts that a
ClusterRole named `<script>alert(1)</script>` and an ARN containing an `<img
onerror=...>` payload are both escaped.

Subprocess arguments are passed as an argument vector, never through a shell, so
a crafted object name cannot become a command.

### 5. Secret values are never read

The tool reports that a role *can* read Secrets. It never runs `get secrets`, so
Secret contents cannot reach the report, the work directory, or your terminal.

## Scope

Out of scope: vulnerabilities in `kubectl`, the krew plugins, the AWS CLI, or
Kubernetes itself. Report those upstream.

## Supported versions

The latest release on `main` receives security fixes.
