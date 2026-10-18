# Support agent rotates a guest Wi-Fi passphrase, with human approval

A support agent reads a ticket, asks to replace a guest Wi-Fi passphrase, a policy engine escalates, a human approves
(signing the approval with their own key), the agent applies the change and answers the ticket.

What to notice in `log.jsonl`:

- The passphrase itself is **never** logged. The request records `input_digest`, a hash of the canonical request with the
  secret replaced by a placeholder. Log digests, not secrets.
- The `human_approval` entry carries `presented_digest` (a hash of what the human was shown) and an `approver_signature`.
  The verifier checks the signature against the approver key **you pin** with `--approver-key`.
- The `approval_gate` layer confirms that, in the recorded order, the action ran only after an unexpired approval.
  It checks the *record*, not that the real system actually waited.

## Verify it

```sh
python3 verifier/agent_custody_verify.py examples/01-support-wifi-password/log.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)" \
  --approver-key "$(cat examples/01-support-wifi-password/approver-key.txt)"
```

Then break it: change one character anywhere in `log.jsonl` and run the command again.

Everything here is synthetic: the keys are derived from public strings (NOT SECRET), the hosts end in `.test`, and there are no real people, customers or networks. `vkey.txt` sits next to the log only for convenience: in real use the checkpoint key must reach the verifier through a channel independent of the log.
