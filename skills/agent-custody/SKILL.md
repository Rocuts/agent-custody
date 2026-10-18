---
name: agent-custody
description: Use when an agent is about to take a consequential action that needs a tamper-evident record, a human approval, or a second-provider check, and when asked to verify an agent-custody log. Records events and runs the layered verifier.
---

# agent-custody: record and verify

Use this skill to (a) write a tamper-evident record of what you do and what a human approved, and (b) verify such a
record. It does not give a record legal standing; it only makes later changes detectable. Read `LIMITS.md` before describing
results to anyone.

## Record (writer)

Run from the root of the agent-custody checkout (the commands use relative paths `writer/` and `verifier/`), with
Python 3.10+ (`python3`). The reference writer is for demos; production use needs a real signer kept off this host.

1. Create the log once per task or session:
   `python3 writer/agent_custody_write.py new LOG.jsonl --agent-id <your-agent-id>`
2. **Before** a consequential action, append a `requested` action. Set `requires_approval` true for anything that
   changes shared state, touches credentials, scans networks, deletes, or spends money:
   `python3 writer/agent_custody_write.py append LOG.jsonl --event '{"type":"action","action_id":"a1","phase":"requested","actor":{"kind":"agent","id":"<id>"},"tool":"<tool>","summary":"<one line>","risk":"medium","requires_approval":true,"input_digest":"<sha256 hex of the input>"}'`
3. If approval is required, STOP and ask the human. Show them exactly what will run. Do not proceed on silence.
   Record their answer (`human_approval`) with `subject_entry_hash` = the `entry_hash` printed in step 2 and
   `presented_digest` = SHA-256 of the exact text you showed them. Use a new `approval_id` every time. If they reject,
   record `rejected` and do not execute:
   `python3 writer/agent_custody_write.py append LOG.jsonl --event '{"type":"human_approval","approval_id":"ap-1","subject_entry_hash":"<step-2 entry_hash>","outcome":"approved","approver":{"id":"<approver id>","method":"<how they approved, e.g. chat-confirmation>"},"presented_digest":"<sha256 hex of what they saw>","expires_at":"2026-01-01T12:00:00Z"}'`
   An approver signature (`approver_signature`) can only be made by the approver with their own key; never sign on
   their behalf. One approval covers **one** attempt: a retry or a second run needs a new approval.
4. After acting, append the `executed` (or `failed`) action with `request_entry_hash` = the step-2 `entry_hash`, and
   `result_digest`. Record `failed` honestly; never omit failures:
   `python3 writer/agent_custody_write.py append LOG.jsonl --event '{"type":"action","action_id":"a1","phase":"executed","actor":{"kind":"agent","id":"<id>"},"tool":"<tool>","summary":"<one line>","risk":"medium","request_entry_hash":"<step-2 entry_hash>","result_digest":"<sha256 hex of the result>"}'`
5. When another provider's model reviews your work, append a `cross_verification` event with the real provider and model
   names and each verdict, including disagreement.
6. Create a checkpoint at milestones and at the end, and store it where this host cannot rewrite it. The demo seed is
   read from a file or from `AGENT_CUSTODY_DEMO_SEED`; **never put a seed on the command line or in the log** (command
   lines end up in `ps`, shell history and transcripts):
   `python3 writer/agent_custody_write.py keygen --seed-file demo.seed` (once; writes a 0600 file, prints the vkey)
   `python3 writer/agent_custody_write.py checkpoint LOG.jsonl --seed-file demo.seed --name demo-key > LOG.checkpoint.note`

Rules while recording:
- Put **digests**, never secrets, credentials, tokens or personal data, in events. Hash the material and keep it elsewhere.
- Never edit or delete lines of an existing log. Append only.
- Do not invent approvals, providers or results. A missing approval is recorded as missing.
- Event schemas are in `SPEC.md` section 6 (full example: `examples/01-support-wifi-password/log.jsonl`); the writer
  refuses to append an invalid event, including a reused `approval_id`.

## Verify

```sh
python3 verifier/agent_custody_verify.py LOG.jsonl --checkpoint LOG.checkpoint.note \
  --vkey "<trusted verifier key>" [--approver-key "<id>=<hex>"] [--ots file.ots]
```

1. Obtain the `--vkey` (and any `--approver-key`) from a channel independent of the log. Never trust a key that came in
   the same bundle.
2. Read the per-layer output. Report each layer's state exactly: `ok`, `fail`, `not_checked`, `unavailable`.
3. Exit code 0 means "no layer failed", not "genuine". Add `--require checkpoint_signature,approver_signatures`
   (exit 3 if not `ok`) when a result must rest on specific layers.
4. When reporting, include: layers that were not `ok`, the unsigned-tail count if any, and the standing caveats
   (host compromise before the checkpoint, host-clock timestamps, no legal effect). On any `fail`, report which layer
   and stop treating the log as reliable evidence.

## Check your own setup

`python3 -m unittest discover -s tests` must pass before you trust the verifier in this checkout.
