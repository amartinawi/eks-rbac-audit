# Architecture

The tool is a straight pipeline: gather, analyse, render. Each stage hands the
next an immutable value, so any stage can be tested in isolation by constructing
its input directly — which is how the entire suite runs without a cluster.

```
kubectl / aws CLI
        │
        ▼
   collector.py ──────► RawDump          raw JSON + text, dumped to the work dir
        │                  │
        │                  ├─► awsauth.py ──► tuple[AuthMapping]
        │                  └─► inventory.py ─► Inventory, SaPosture
        │
   eksapi.py ───────► EksAccess          optional; None when unavailable
        │
        ▼
   analyze.py ────────► AuditResult      RuleContext → 17 rules → sorted findings
        │
        ▼
   render.py ─────────► one HTML file    Jinja2 + inlined CSS, no external refs
```

## Modules

| Module | Responsibility |
|---|---|
| `kubectl.py` | The only place a subprocess is spawned. Enforces the read-only allowlist and records every command. |
| `tooling.py` | Detects and optionally installs the krew plugins. Returns a status so callers degrade rather than fail. |
| `collector.py` | Runs every probe, writes `<label>.out`/`.err` to the work directory, turns failures into warnings. |
| `awsauth.py` | Parses the `aws-auth` ConfigMap's embedded YAML. PyYAML when available, built-in fallback otherwise. |
| `eksapi.py` | Resolves the context to an EKS cluster and reads the control plane. Entirely optional. |
| `inventory.py` | Reduces raw RBAC JSON to structured objects — the layer that answers "what does this role actually grant?" |
| `rules_common.py` | The `RuleContext` and the predicates rules query it with. |
| `rules_rbac.py` | Findings derived from Kubernetes RBAC alone. |
| `rules_eks.py` | Findings about how IAM principals become Kubernetes identities. |
| `analyze.py` | Orchestration: build context, run rules, sort, assemble the summary. |
| `render.py` | View-model construction and HTML output. |
| `config.py` | Every threshold, constant, and heuristic. No magic values elsewhere. |
| `models.py` | Frozen dataclasses. Nothing mutates after construction. |

## Why the layers split where they do

**`inventory.py` separate from the rules.** Turning
`{"verbs": ["*"], "resources": ["*"]}` into "this grants everything" is JSON
spelunking; deciding that this is a HIGH finding is policy. Keeping them apart
lets the rules read as policy statements rather than as parsing code, and lets
`rule_flags()` be tested exhaustively on its own.

**`rules_rbac` separate from `rules_eks`.** The RBAC rules apply to any
Kubernetes cluster; the EKS rules need an AWS identity layer and return nothing
without one. The split is what makes non-EKS support fall out naturally rather
than requiring conditionals throughout.

**`render.py` builds a view model.** `build_view()` flattens the result into
exactly what the template renders, so the numbers shown in the report can be
asserted in tests without parsing HTML, and the template stays declarative.

**`kubectl.py` as a single chokepoint.** Concentrating every subprocess call in
one place is what makes the read-only guarantee checkable. If commands were
spawned throughout the codebase, "we only read" would be a claim rather than a
property.

## Data flow details

### Collection is failure-tolerant by design

Only one failure is fatal: the API server not answering. Everything else becomes
a warning carried into the report's *Collection caveats* section.

This is not defensive programming for its own sake. Real audits routinely hit a
caller who cannot list one API group, a webhook authorizer that refuses to
enumerate rules, or a `who-can` query for a resource type the cluster does not
have. An audit that aborts on the first of these produces nothing; one that
continues and states its gaps produces something useful and honest.

Reachability is decided by the presence of a `Server Version` line, not by the
exit code — `kubectl version` prints the *client* version and exits non-zero when
the server is unreachable, so a non-empty stdout proves nothing. Getting this
wrong turns an unreachable cluster into a multi-minute hang instead of a fast
failure.

### Determinism

Same cluster state must produce the same report. Every collection is sorted by a
stable key, findings sort by `(severity rank, rule id, title)`, and the executive
summary is assembled from the findings rather than written by hand. The only
varying content is the generation timestamp; `tests/test_render.py` asserts that
two renders of the same result differ in nothing else.

### The context is never switched

Every command carries `--context <name>`. The kubeconfig is never written, so
concurrent audits do not interfere and a crash cannot leave an operator pointed
at the wrong cluster. `--use-context` opts into the older behaviour for anyone
who wants it.

## Extending

- **A new finding** → [writing-rules.md](writing-rules.md).
- **A new data source** → add a collector function, extend `RawDump`, expose it
  on `RuleContext`. Make it optional and degrade when absent, as `eksapi` does.
- **A new report section** → add to `build_view()` in `render.py`, then to the
  template. Wide tables belong in `table_wrap` so they collapse past 25 rows.
