# Contributing

Thanks for helping. This document covers the two things most likely to trip you
up: the read-only invariant, and the rule that no real cluster data enters the
repository.

## Setup

```bash
git clone https://github.com/amartinawi/eks-rbac-audit.git
cd eks-rbac-audit
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
python3 -m pytest tests/ -q
```

The suite runs entirely offline. You do not need a cluster, AWS credentials, or
network access to develop or test this project — and if a change makes that
untrue, the change is wrong.

## Two hard rules

### 1. Never add a mutating command

Every cluster command goes through `Runner` in `eksaudit/kubectl.py`, which
checks the verb against an allowlist before spawning anything. If your change
needs a new command:

- Confirm it genuinely only reads. `auth can-i create pods` is a question;
  `auth reconcile` writes RBAC objects.
- Add the verb to `ALLOWED_VERBS`, narrowing subcommands where a verb has both
  reading and writing forms (see how `auth` and `config` are handled).
- Add it to the read-only list in `tests/test_kubectl.py`.

CI fails the build if any mutating verb becomes reachable. This is deliberate.

### 2. Never commit real cluster data

Fixtures, tests, examples, docs, and commit messages must contain no real AWS
account ID, ARN, cluster name, namespace, or principal. Use `111122223333` for
accounts and invent the rest.

This is not paranoia. A sanitization pass on this project's own fixtures once
missed an account ID buried inside a `last-applied-configuration` annotation and
an IRSA `role-arn`. Writing four synthetic objects is faster and safer than
scrubbing a real dump — see [tests/fixtures/README.md](tests/fixtures/README.md).

## Adding a finding rule

Read [docs/writing-rules.md](docs/writing-rules.md). In short: a rule is a
function taking a `RuleContext` and returning a list of `Finding`s, registered in
`ALL_RULES` in either `rules_rbac.py` or `rules_eks.py`.

Every rule needs a test that it fires at the right severity, and a test that it
stays quiet on the clean cluster. A rule that cannot be made quiet on a
well-configured cluster is a rule that will be ignored in practice.

**State the legitimate case.** Every rule has a configuration that looks
identical but is correct — upstream `admin` and `edit` grant Secret read and pod
exec by design. Handle it explicitly rather than shipping a known false positive.

## Style

The project follows a few conventions consistently. Match them:

- **Immutability.** Models are frozen dataclasses holding tuples. Analysis
  returns new objects; nothing is mutated after construction. The one exception
  is `Runner`'s command log, an explicitly encapsulated append-only accumulator.
- **Small, focused modules.** Roughly 200–400 lines. `rules_rbac.py` is the
  largest at ~500 and would be split before growing further.
- **Comments explain why, not what.** `# Kubernetes' own controllers legitimately
  read Secrets as part of the control loop` earns its place. `# loop over roles`
  does not.
- **Findings are written for the person who has to fix it.** Impact says what an
  attacker gains in concrete terms. Remediation gives steps, not "review this".

## Testing expectations

New behaviour needs a test. Changed behaviour needs an updated one. Beyond that:

- **Degradation paths matter as much as happy paths.** A missing ConfigMap, a
  forbidden API group, an absent plugin, unparseable JSON — each must warn and
  continue, never crash. `tests/test_collector.py` shows the fake-runner pattern.
- **Determinism is a feature.** Same cluster state must produce the same report.
  If you introduce ordering, sort it.

Run `python3 -m pytest tests/ -q` before opening a PR. CI runs it on Python
3.9–3.13, plus a job without PyYAML installed to prove the fallback parser works.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
