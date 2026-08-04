# Writing a finding rule

A rule is a function that takes a `RuleContext` and returns a list of `Finding`s.
Rules never mutate the context and never depend on each other's output, so they
can be added, reordered, and tested independently.

## The shape

```python
def default_service_account_bindings(ctx: RuleContext) -> list[Finding]:
    """Rule 9 — the per-namespace ``default`` ServiceAccount carrying permissions."""
    bound = ctx.sa_posture.default_bound
    if not bound:
        return [Finding(
            severity="INFORMATIONAL",
            title="No default ServiceAccount is bound to any Role or ClusterRole",
            evidence=(f"{ctx.sa_posture.default_count} default ServiceAccounts exist; "
                      f"none appears as a subject in any binding.",),
            impact="Pods that do not declare a ServiceAccount fall back to default. "
                   "Because default holds no permissions here, that fallback grants nothing.",
            remediation=("No action required. Re-check when new namespaces are onboarded.",),
            category="serviceaccount",
            rule_id="R9",
        )]
    ...
```

Register it in `ALL_RULES` at the bottom of `rules_rbac.py` (Kubernetes RBAC) or
`rules_eks.py` (anything involving AWS identity).

## Querying the cluster state

`RuleContext` (in `rules_common.py`) is the whole API available to a rule:

| Query | Returns |
|---|---|
| `ctx.custom_roles` | Roles and ClusterRoles excluding Kubernetes and EKS built-ins |
| `ctx.all_bindings` | Every ClusterRoleBinding and RoleBinding |
| `ctx.bindings_to(name)` | Bindings whose `roleRef` names a role |
| `ctx.subjects_reaching(name)` | Readable subject list bound to a role |
| `ctx.groups_reaching(name)` | Kubernetes groups bound to a role — the bridge back to `aws-auth` |
| `ctx.mapped_principals_for_role(name)` | IAM principals that reach a role through a group |
| `ctx.principals_in_group(group)` | `aws-auth` principals in a Kubernetes group |
| `ctx.is_admin_role(name)` | Whether a role is `cluster-admin` or a full wildcard |
| `ctx.sa_posture` | ServiceAccount token and default-SA exposure |
| `ctx.eks` | EKS control-plane data, or `None` |
| `ctx.thresholds` | Tunables from the CLI |

`role.flags` (a `RuleFlags`) answers what a role actually grants: `secrets_read`,
`exec_pods`, `escalate`, `bind`, `impersonate`, `token_create`, `csr_create`,
`full_wildcard`, `any_dangerous`. Use these rather than re-parsing rules —
`inventory.rule_flags()` already handles the awkward cases, like a wildcard
resource with a read verb reaching Secrets without naming them.

## Writing the finding itself

The report is read by someone deciding whether to act tonight or next quarter.
Write for them.

**Evidence** is what you actually saw, specific enough to verify by hand. Name
the object, the rule, and who holds it:

> `ClusterRole cluster-reader rule: apiGroups: [*] resources: [pods/exec] verbs: [create]`
> `IAM principals reaching it via aws-auth: qa-analyst, report-exporter`

**Impact** is what an attacker gains, in concrete terms. Not "this is a security
risk" — say what it lets someone do:

> Reading Secrets exposes ServiceAccount tokens, database credentials, and TLS
> private keys; the ability to exec into a pod turns any of those into code
> execution inside the cluster.

**Remediation** is steps, not "review this". If you cannot name the fix, the
finding is not ready.

**Severity** follows blast radius and exploitability:

| | |
|---|---|
| CRITICAL | Direct path to cluster compromise, exploitable now |
| HIGH | Significant privilege beyond intent, or a credential that does not expire |
| MEDIUM | Weakens the security posture; needs a decision, not a page |
| LOW | Worth tightening; usually the platform default |
| INFORMATIONAL | Context, or a control verified sound |

## The part people skip

**Name the legitimate case that looks identical, and handle it.**

Every rule has one. The upstream `admin` and `edit` ClusterRoles grant Secret
read *and* pod exec by design — without excluding roles labelled
`kubernetes.io/bootstrapping: rbac-defaults`, R2 would fire two false CRITICALs
on every Kubernetes cluster in existence. Kubernetes' own `system:controller:*`
roles read Secrets as part of the control loop, so R16 excludes them.

A rule that cries wolf gets the whole report ignored. If you cannot separate the
dangerous case from the legitimate one, either lower the severity and say so in
the impact, or do not ship the rule.

**Emit a positive when you find nothing.** If a rule can meaningfully confirm a
control is sound, return an INFORMATIONAL finding saying so. A reader must be
able to distinguish "checked, and it is fine" from "not checked".

## Testing

Two tests minimum, both in `tests/test_analyze.py`:

```python
def test_r9_default_service_account_binding_is_flagged(clean_dump):
    """Fires: inject exactly one problem into the clean cluster."""
    bindings = clean_dump.cluster_role_bindings + (
        binding("app-default", "app-viewer",
                [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}]),
    )
    finding = rule(analyze.analyze(dump_with(clean_dump, cluster_role_bindings=bindings)), "R9")
    assert finding is not None and finding.severity == "HIGH"
```

The `clean_dump` fixture is a well-configured cluster; `dump_with()` injects one
problem at a time so a failure points at exactly one rule. The existing
`test_clean_cluster_has_no_critical_or_high_findings` then covers the quiet case
for free — if your rule misfires on a good cluster, that test breaks.

If your rule has a heuristic (a name match, a threshold), test its boundaries.
`test_lookalike_names_are_not_treated_as_read_only` exists because `preview`
contains `view` and `credential` contains `read`.

## Adding a new data source

If your rule needs data the tool does not collect:

1. Add the command to `collector.py`. It must be on the read-only allowlist in
   `kubectl.py` — see [CONTRIBUTING.md](../CONTRIBUTING.md).
2. Extend `RawDump` with the parsed result.
3. Expose it on `RuleContext`.
4. **Degrade when it is missing.** Collection failures become warnings, never
   exceptions. Follow how `eksapi` returns `None` plus a warning and marks the
   affected finding `unverified`.
