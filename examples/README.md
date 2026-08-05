# Examples

## `generate_demo.py`

Renders the demo report published at
**https://amartinawi.github.io/eks-rbac-audit/**

```bash
python3 examples/generate_demo.py            # -> demo-report.html
python3 examples/generate_demo.py out.html
```

It builds a fictional cluster (`acme-prod`) carrying a realistic spread of
misconfigurations, then runs the real analysis and rendering pipeline over it.
Nothing is faked downstream of the input: the findings, severities, executive
summary, and evidence are all produced by the same code a live audit uses.

**Everything in it is invented.** The AWS account is the documentation-range
`111122223333`, and every role, namespace, and principal name was made up to
demonstrate a specific rule. No real cluster was involved.

The generated timestamp is fixed, so regenerating produces no diff noise.

### What the demo cluster demonstrates

| Object | Rule |
|---|---|
| ClusterRole `platform-readonly` | R1 — named read-only, grants Secret read and pod exec |
| ClusterRole `incident-debug` | R2 — Secret read plus pod exec, admin-equivalent |
| `acme-ci-deploy-role`, `acme-jenkins-runner`, `build-bot` | R3 — automation with standing cluster-admin |
| IAM users `a.rivera`, `m.chen`, `s.patel` | R3b — cluster-admin via non-expiring keys |
| Access entries `acme-terraform-apply`, `acme-break-glass` | R4 — admins the ConfigMap cannot show |
| ClusterRole `service-mesh-operator` | R8 — custom wildcard role |
| `default` SA in `checkout` | R9 — bound to a Role |
| ClusterRole `namespace-provisioner` | R10 — `escalate` and `bind` |
| ClusterRole `workload-identity-broker` | R11 — mints tokens and CSRs |
| `authenticationMode: API_AND_CONFIG_MAP` | R13 — two auth sources at once |
| Public endpoint `0.0.0.0/0`, audit logging off | R14 |
| ClusterRoles `admin`, `edit` | Deliberately **not** flagged — upstream defaults |

That last row matters as much as the others: it shows the tool distinguishing an
operator's dangerous role from Kubernetes' own, which is what keeps the report
worth reading.
