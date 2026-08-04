# Test fixtures

**Everything here is invented.** No fixture is derived from, or describes, a real
cluster. Account IDs use the AWS documentation range (`111122223333`), and every
role, namespace, and principal name was made up to exercise a specific rule.

The fixtures deliberately reproduce structural quirks that real clusters exhibit,
because those quirks are where parsers break:

- **`mapUsers` is fully quoted YAML while `mapRoles` is unquoted.** Real clusters
  routinely show this split, because each block was written by a different tool.
  `test_awsauth.py` asserts both styles parse identically.
- **Upstream default roles carry `kubernetes.io/bootstrapping: rbac-defaults`**
  and `rbac.authorization.kubernetes.io/autoupdate: "true"`. That is how the tool
  distinguishes them from operator-defined roles.
- **IRSA annotations** (`eks.amazonaws.com/role-arn`) and Helm release metadata
  appear on ServiceAccounts, as they do in practice.

## `k8s/` — a deliberately imperfect cluster

Models a real-world cluster carrying the problems this tool exists to find.

| Object | Why it is there |
|---|---|
| ClusterRole `cluster-reader` | Named read-only, actually grants cluster-wide Secret read **and** pod exec → **R1** |
| ClusterRoles `admin`, `edit` | Grant secrets + exec *by design*, but carry the bootstrapping label → must **not** be flagged |
| aws-auth `ci-pipeline-role`, `build-bot` | Automation principals in `system:masters` → **R3** |
| aws-auth `alice`, `bob`, `carol` | IAM users in `system:masters` (non-expiring keys) → **R3b** |
| aws-auth `eks-node-group-*` | Correctly mapped node roles → node-mapping positive |
| 12 ServiceAccounts, 1 opting out | 92% implicitly mount a token → **R15** |
| `efs-csi-provisioner-secrets`, `ingress-controller` | Controllers holding Secret read → **R16** |
| `system:public-info-viewer` → `system:unauthenticated` | The upstream default → **R7** informational, not a finding |

## `k8s/clean/` — a well-configured cluster

The negative case. Least-privilege custom role, no wildcards outside
`cluster-admin`, no bound `default` ServiceAccount, every ServiceAccount opting
out of token automount, node roles mapped correctly.

It must produce **zero CRITICAL and zero HIGH findings**. The one MEDIUM it does
carry is R13 — a correctly run cluster on the legacy `aws-auth` ConfigMap is
still on the legacy path, and the report says so.

Passing `aws_auth=None` turns it into a clean non-EKS cluster with nothing
actionable at all, which is how the "no findings" summary wording is tested.

## Adding a fixture

Keep them small and purposeful: a fixture should exist to prove one rule fires or
one rule stays quiet. Do not paste real cluster output — sanitizing it reliably is
harder than writing the four objects you actually need.
