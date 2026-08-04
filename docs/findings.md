# Finding reference

Every rule, what it detects, why it is rated where it is, and the legitimate
configuration that looks similar. Rule IDs are stable and appear in the JSON
export, so they can be referenced in tickets and suppression lists.

Rules that find nothing emit an INFORMATIONAL finding stating what was checked.
A clean result and an unchecked one must never look the same.

---

## R1 — A role named read-only that is not · CRITICAL

**Detects** an operator-defined Role or ClusterRole whose *name* advertises
read-only access (`read`, `reader`, `view`, `viewer`, `readonly`, `ro`, `get`,
`list`, `watch`, `observer`) while its rules grant Secret read or pod exec.

**Why CRITICAL.** The danger is not only the permission but the mismatch. A role
called `cluster-reader` gets handed to QA, contractors, and dashboards by people
who reasonably believe it is harmless. Reading Secrets yields ServiceAccount
tokens, database credentials, and TLS keys; `pods/exec` turns any of those into
code execution inside the cluster.

**Matching is token-based, not substring.** `preview-gateway` is not `view`,
`credential-manager` is not `read`. `pod-reader` — the canonical example Role in
the Kubernetes documentation — does match, which is why `reader` has its own
entry.

**Looks similar but is fine:** nothing. If a role legitimately needs Secret
access, its name should say so. Renaming it resolves this finding, which is the
point.

## R2 — Secret read combined with pod exec · CRITICAL

**Detects** any operator-defined role granting both, regardless of name.

**Why CRITICAL.** The combination is admin-equivalent. Read a ServiceAccount
token from a Secret, exec into a pod running as that account, and RBAC has been
routed around entirely.

Emitted only when R1 has not already fired for the role — one problem, one
finding.

**Looks similar but is fine:** the upstream `admin` and `edit` ClusterRoles grant
exactly this by design. They carry `kubernetes.io/bootstrapping: rbac-defaults`
and are excluded. Without that exclusion this rule would raise two false
CRITICALs on every Kubernetes cluster in existence.

## R3 — Automation principals with permanent cluster-admin · HIGH

**Detects** `aws-auth` principals in `system:masters` whose names suggest a
machine identity (`ci`, `cd`, `pipeline`, `repo`, `bot`, `jenkins`, `gitlab`,
`github`, `terraform`, `lambda`, `deploy`, `runner`, `argo`, `flux`, ...).

**Why HIGH.** CI credentials live in pipeline variables readable by everyone who
can edit a build, are rarely rotated, and are exposed by any build-script
compromise. Standing `system:masters` turns that into full cluster takeover.

**Fix direction:** IRSA for in-cluster workloads, OIDC-federated role assumption
for pipelines, and a namespace-scoped Role rather than `system:masters`.

**Looks similar but is fine:** a break-glass automation identity that is
monitored and short-lived. Rare — verify rather than assume.

## R3b — IAM users with cluster-admin · HIGH

**Detects** IAM *users* (as opposed to roles) in `system:masters` that R3 has not
already covered.

**Why separate from R3.** The remediation differs. A pipeline needs workload
identity; a named engineer needs federated role assumption through SSO. Merging
them produced a finding titled "non-human principals" that listed real people —
accurate about the credential, wrong about the human.

**Why HIGH.** An IAM user authenticates with a static access-key pair. No session
lifetime, no MFA challenge at the point of use. A key committed to a repository
grants permanent, unconditional cluster-admin.

## R4 — EKS access entries granting cluster-admin · HIGH

**Detects** access entries carrying `AmazonEKSClusterAdminPolicy` or
`AmazonEKSAdminPolicy` at cluster scope, or listing `system:masters` in their
Kubernetes groups.

**Why it matters disproportionately.** Access entries are evaluated by the EKS
control plane *before* the `aws-auth` ConfigMap. They are invisible to anyone
auditing Kubernetes RBAC or the ConfigMap alone — which is most audits. A cluster
can look clean from inside and have a dozen admins granted through the AWS API.

Requires AWS credentials. Omitted entirely with `--no-aws`.

**Looks similar but is fine:** namespace-scoped entries with
`AmazonEKSEditPolicy` or `AmazonEKSViewPolicy` are not flagged.

## R5 — Node-group role mapped to system:masters · CRITICAL

**Detects** an `aws-auth` entry whose ARN looks like an EKS node-group role and
whose groups include `system:masters`.

**Why CRITICAL.** Every EC2 instance in the node group can fetch that role's
credentials from the instance metadata service. Any pod that can reach IMDS — and
by default, every pod can — becomes cluster-admin. This converts a single
container escape, or even a plain SSRF, into total cluster compromise.

**Fix direction:** map node roles to `system:bootstrappers` and `system:nodes`
only, and restrict pod access to IMDS (hop limit 1, or a network policy).

## R6 — Node mappings deviating from the EKS pattern · HIGH

**Detects** two deviations: a non-node principal placed in `system:nodes`, and a
node role whose username is not the `system:node:{{EC2PrivateDNSName}}` template.

**Why HIGH.** `system:nodes` carries the Node authorizer's privileges — a
non-node principal there holds permissions designed for kubelets. And a node
without the templated username cannot be attributed to a specific instance in the
audit log, so "which node read that Secret?" becomes unanswerable.

## R7 — Anonymous or unauthenticated access · CRITICAL / HIGH

**Detects** bindings granting `system:anonymous` or `system:unauthenticated`
beyond the upstream default. CRITICAL when the bound role is admin or wildcard.

**Why it matters.** These permissions are held by anyone who can reach the API
endpoint, with no credential at all. On a cluster with a public endpoint that
means the internet.

**Looks similar but is fine:** `system:public-info-viewer` bound to
`system:unauthenticated` is the Kubernetes default and grants only `/healthz`,
`/version`, and API discovery. Reported as INFORMATIONAL, never as a finding.

## R8 — Custom wildcard ClusterRoles · HIGH

**Detects** operator-defined ClusterRoles granting `*` verbs on `*` resources in
`*` API groups, excluding `cluster-admin` itself.

**Why HIGH.** A wildcard role is cluster-admin under a name that does not say so,
and it silently absorbs every API resource added by a future CRD or upgrade — the
grant widens without anyone changing it.

**Looks similar but is fine:** system and EKS-managed wildcard roles are required
for platform operation and are excluded.

## R9 — The default ServiceAccount is bound · HIGH / CRITICAL

**Detects** `ServiceAccount:default` appearing as a subject in any binding.
CRITICAL when the role is admin or wildcard.

**Why HIGH.** Pods that do not name a ServiceAccount silently fall back to
`default`. Binding permissions to it grants them to every such pod in the
namespace — including pods deployed later by anyone with namespace write access.
Nobody reviewing that deployment will see the grant.

## R10 — Privilege-escalation verbs · HIGH

**Detects** `escalate` or `bind` on roles, or `impersonate` on users, groups, or
ServiceAccounts, in operator-defined roles.

**Why HIGH.** `escalate` and `bind` let a principal award itself permissions it
does not hold, removing the RBAC ceiling entirely. `impersonate` lets it act as
any other identity — and the audit log records the *impersonated* identity, so
the action is attributed to the victim.

**Looks similar but is fine:** a controller that reconciles RBAC genuinely needs
`bind`. Scope it with `resourceNames` to the specific roles it manages.

## R11 — Credential minting · HIGH

**Detects** `create` on `serviceaccounts/token` or `certificatesigningrequests`.

**Why HIGH.** Creating a ServiceAccount token produces a working credential for
that account. An approved CSR produces a client certificate the API server
trusts. Either lets a principal become an identity it was never granted.

## R12 — Broad standing cluster-admin · MEDIUM

**Detects** more standing admins than `--admin-threshold` (default 3), counting
both `aws-auth` principals and cluster-admin access entries.

**Why only MEDIUM.** Every individual admin may be justified. The finding is
about aggregate blast radius and the absence of just-in-time access, not about
any one grant being wrong.

## R13 — aws-auth posture · MEDIUM / LOW

Keyed off the cluster's real `authenticationMode`:

| Mode | Severity | Meaning |
|---|---|---|
| `CONFIG_MAP` | MEDIUM | Only the ConfigMap is evaluated. Migrate to access entries. |
| `API_AND_CONFIG_MAP` | MEDIUM | Both are live, access entries taking precedence. Finish the migration. |
| `API` + ConfigMap present | LOW | The ConfigMap is inert but misleading. Delete it. |
| Unreadable | MEDIUM, marked `unverified` | AWS API unavailable; the mode is a guess. |

**Why it matters.** ConfigMap-based auth has no per-principal audit trail, cannot
express IAM condition keys or session policies, and one bad `apply` can lock every
administrator out of the cluster irreversibly.

Note that switching modes is one-way: `CONFIG_MAP` → `API_AND_CONFIG_MAP` → `API`
cannot be reversed.

## R14 — Control-plane exposure · MEDIUM

Two independent checks:

- **Public endpoint open to `0.0.0.0/0`** — removes the network as a defence
  layer, making every other finding internet-reachable.
- **`audit` or `authenticator` logging disabled** — without these there is no
  record of who read Secrets or exec'd into a pod, and no record of which IAM
  principal mapped to which Kubernetes identity. An incident involving anything
  else in this report would not be reconstructable.

Requires AWS credentials.

## R15 — ServiceAccount token automount · LOW

**Detects** ≥90% of ServiceAccounts not setting
`automountServiceAccountToken: false`.

**Why LOW.** This is the Kubernetes default, so it is ubiquitous rather than
exceptional. It still matters: every pod without an explicit opt-out mounts a
usable API token, so a compromised container hands the attacker that token even
when the workload never calls the API.

## R16 — Controller ServiceAccounts with Secret read · LOW

**Detects** controller and add-on ServiceAccounts (CSI drivers, ingress
controllers, cert managers) bound to roles granting Secret read.

**Why LOW and not higher.** These usually need the access for TLS material and
credentials. The finding exists to prompt a scoping check, not to claim a
misconfiguration. Kubernetes' own `system:controller:*` roles are excluded
entirely — flagging them tells an operator nothing they can act on.

## R17 — Caller context · INFORMATIONAL

Records which context was audited, at what version, and what the auditing
identity could not see — including the common webhook-authorizer warning that
`auth can-i --list` may be incomplete.

**Why it is always present.** Findings are bounded by what the caller could read.
A report that does not state its own blind spots invites the reader to treat
absence of findings as absence of problems.
