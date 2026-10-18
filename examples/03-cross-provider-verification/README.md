# Cross-provider verification: a second provider disagrees, the human decides

An agent backed by `provider-a` writes a script. A reviewer from a *different* provider (`provider-b`) disagrees and reports
two findings (stored as a digest). A human records a `deny`, the agent revises, and the same reviewer now agrees.

What to notice:

- `cross_verification` is a first-class event: who authored, which providers reviewed, each verdict, how many findings.
- `cross_provider` is recomputed by the verifier from the recorded provider names. Claiming cross-provider review while
  every reviewer shares the author's provider fails the `events` layer (see `vectors/fail-20-cross-provider-claim-false`).
- Provider and model names are **self-declared by whoever wrote the log**. The log does not prove that a different
  provider really answered; it makes the claim explicit, ordered and tamper-evident. Providers here are placeholders.

## Verify it

```sh
python3 verifier/agent_custody_verify.py examples/03-cross-provider-verification/log.jsonl \
  --checkpoint examples/03-cross-provider-verification/checkpoint.note \
  --vkey "$(cat examples/03-cross-provider-verification/vkey.txt)"
```

Then break it: change one character anywhere in `log.jsonl` and run the command again.

Everything here is synthetic: the keys are derived from public strings (NOT SECRET), the hosts end in `.test`, and there are no real people, customers or networks. `vkey.txt` sits next to the log only for convenience: in real use the checkpoint key must reach the verifier through a channel independent of the log.
