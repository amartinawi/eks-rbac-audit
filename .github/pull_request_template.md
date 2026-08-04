## What this changes

<!-- One or two sentences. If it adds or changes a finding rule, say which. -->

## Why

<!-- The problem this solves. For a rule change, what does it catch or stop
     mis-flagging, and what is the legitimate case that looks similar? -->

## Checklist

- [ ] `python3 -m pytest tests/ -q` passes
- [ ] New behaviour has a test; changed behaviour has an updated one
- [ ] No real cluster data in fixtures, tests, or examples — account IDs use `111122223333`
- [ ] If a command was added, it is on the read-only allowlist in `eksaudit/kubectl.py` and is genuinely a read
- [ ] Docs updated if a rule, flag, or report section changed
