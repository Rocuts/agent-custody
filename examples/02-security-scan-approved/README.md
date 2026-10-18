# Security agent runs an approved scan, and a second one is denied

A security agent requests an active scan. The policy engine escalates, a human approves the in-scope target, the scan runs.
Later the agent asks to scan a host outside the approved scope; the policy engine records a `deny` and the action is
never executed. The denial is part of the evidence too.

What to notice:

- The denied request has **no** `executed` entry. A `deny` followed by an `executed` entry for the same request would
  fail the `approval_gate` layer (see `vectors/fail-15-executed-after-deny`) unless a later human approval lifted the
  deny; a later `allow` decision does not (`vectors/fail-46-deny-lifted-by-allow`).
- Findings are stored as `result_digest` (a hash). The raw scan output stays outside the log, so the log can be shared
  with an auditor without leaking scan data; the auditor can later check a disclosed output against the digest.

## Verify it

```sh
python3 verifier/agent_custody_verify.py examples/02-security-scan-approved/log.jsonl \
  --checkpoint examples/02-security-scan-approved/checkpoint.note \
  --vkey "$(cat examples/02-security-scan-approved/vkey.txt)" \
  --approver-key "$(cat examples/02-security-scan-approved/approver-key.txt)"
```

Then break it: change one character anywhere in `log.jsonl` and run the command again.

Everything here is synthetic: the keys are derived from public strings (NOT SECRET), the hosts end in `.test`, and there are no real people, customers or networks. `vkey.txt` sits next to the log only for convenience: in real use the checkpoint key must reach the verifier through a channel independent of the log.
