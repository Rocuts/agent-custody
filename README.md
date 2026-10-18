# agent-custody

**Tamper-evident, independently verifiable custody logs for AI agent actions and human approvals.**

When an AI agent changes something that matters, "trust our logs" is a weak answer. agent-custody gives you a small
log format and a **single-file, standard-library-only verifier** so that someone who does not trust you can check
that the record of what the agent did, which key holder approved it, and what a second AI provider said about it has
not been altered since it was checkpointed.

> **Status: v0.1, experimental.** Format may change before 1.0. No independent security review yet.
> Español: [resumen en español](docs/es/RESUMEN.md).

## Try it: three commands

Needs Python 3.10+ and nothing else (the verifier refuses to run on older versions). Commands use `python3`; on systems
where `python` is Python 3.10+, that works too.

```sh
# 1. verify a synthetic log: an agent rotates a Wi-Fi passphrase after a signed human approval
python3 verifier/agent_custody_verify.py examples/01-support-wifi-password/log.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)" \
  --approver-key "$(cat examples/01-support-wifi-password/approver-key.txt)"

# 2. tamper with a copy: change the approved target
sed 's/ap-guest-demo/ap-admin-demo/' examples/01-support-wifi-password/log.jsonl > /tmp/tampered.jsonl

# 3. verify again and watch it fail, layer by layer
python3 verifier/agent_custody_verify.py /tmp/tampered.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)"; echo "exit code: $?"
```

Command 1 prints one line per layer (`ok`, `fail`, `not_checked`, `unavailable`), exits with code 0 and ends with
this line, never a bare "VALID":

```
RESULT: NO INCONSISTENCY FOUND in the 8 layer(s) that passed; 2 layer(s) not checked or unavailable. This is not proof of authenticity, correctness or that the host was uncompromised (see LIMITS.md).
```

Command 3 exits with code 1 and names the broken layer:

```
[fail       ] entry_hashes         entry_hash does not match content at seq 3, 6
RESULT: FAIL - failed layers: entry_hashes
```

## How it works

```
 agent / tools ──► writer ──► log.jsonl      entries hash-chained: each commits to all before it
                                 │
                       Merkle root (RFC 6962)
                                 ▼
                        checkpoint.note  ◄── signed with YOUR key (kept off the agent's host)
                                 │
          ┌──────────────────────┼───────────────────────┐
          ▼                      ▼                       ▼
   timestamp (optional)   inclusion proof         verifier (stdlib, one file)
   OpenTimestamps /       reveal ONE entry,       per-layer verdict + honest
   RFC 3161               not the whole log       "what I did not check"
```

Events in the log (see [SPEC.md](SPEC.md)): `action` (request / executed / failed), `decision` (allow / deny /
escalate), `human_approval` (with what the human was shown, and an optional signature by the approver's own key),
`cross_verification` (author and reviewers from named providers, with verdicts), plus `x-*` extensions.

## Why another log format?

Plenty of projects hash-chain agent logs. What this one concentrates on:

1. **Human approvals are first-class and checkable.** An approval records what the human actually saw
   (`presented_digest`), can be signed with the approver's own key, and the `approval_gate` layer fails any log that
   records an approval-required action as executed before (or without) an approval, or any action executed after a
   policy `deny` that no later human approval lifted (a later `allow` does not), even when every hash is valid.
2. **Cross-provider verification is an event type.** "A model from provider B reviewed provider A's work and
   disagreed" becomes an ordered, tamper-evident entry; the verifier recomputes, from the provider names recorded in the
   log, whether the review was cross-provider. Those names are self-declared (see LIMITS.md).
3. **The verifier is honest about its own limits.** Each layer reports `ok / fail / not_checked / unavailable`.
   No checkpoint supplied? It says truncation cannot be detected. No trusted key? Signature `not_checked`. Timestamp
   proof present? It checks the digest binding and says Bitcoin was not verified, instead of pretending. An inclusion
   proof against a checkpoint no trusted key signed is `not_checked`, not `ok`.
4. **Nothing to install.** One Python file, standard library only, pure-Python Ed25519 (RFC 8032) and RFC 6962/9162
   Merkle proofs, cross-checked in tests against RFC vectors and the Certificate Transparency reference tree.
5. **Negative test vectors are the product.** [69 vectors](vectors/README.md): altered, reordered, truncated,
   transplanted, forged-checkpoint, replayed-approval, tampered-proof and malformed-input cases that MUST fail, and
   documented limits that pass on purpose.

Building blocks reused rather than reinvented: RFC 6962/9162 Merkle trees, RFC 8785 canonical JSON, C2SP signed-note
checkpoints, OpenTimestamps, RFC 3161.

## What's here

| path | what |
|---|---|
| [SPEC.md](SPEC.md) | format, hashing, checkpoints, verification layers, threat model (CC-BY-4.0) |
| [LIMITS.md](LIMITS.md) | what this does not do, and wording to avoid |
| `verifier/agent_custody_verify.py` | the verifier: one file, Python 3.10+, stdlib only |
| `writer/agent_custody_write.py` | small reference writer + CLI (demo signer only; see its docstring) |
| `vectors/` | pass/fail vectors with expected layer states |
| `examples/` | three synthetic scenarios: support agent + approval, security scan + denial, cross-provider review |
| `skills/agent-custody/SKILL.md` | a skill telling a coding agent how to record and verify |
| `tests/` | `python3 -m unittest discover -s tests` or `pytest` |
| [CHANGELOG.md](CHANGELOG.md) | changes, including format changes |

## What this does NOT prove

Read [LIMITS.md](LIMITS.md). The short version:

- It does **not** prove the recorded events really happened, or that nothing else happened. It proves the record has not
  changed since a checkpoint.
- It does **not** prove the machine that wrote the log was uncompromised. A host controlled by an attacker before the
  checkpoint can write a consistent false log.
- Without an externally stored, signed checkpoint, truncation or a full rewrite of a log is **undetectable**
  ([`pass-12`](vectors/pass-12-limit-full-rewrite-no-checkpoint), [`pass-13`](vectors/pass-13-limit-truncation-no-checkpoint)).
- Entry times (`ts`) are the writer's clock. Only an external timestamp on a checkpoint bounds when the checkpoint existed.
- A signature by an approver's key shows that the key holder signed that approval (including its expiry and method),
  not when they signed it. Linking a key to a person is up to you.
- It is **not** an electronic signature with legal effect, **not** a timestamp authority, and **not** a compliance
  certification. Whether any evidence is accepted anywhere depends on local law and contracts.
- A single operator can show different histories to different people (no witnesses in 0.1).

## Roadmap (not promises)

0.2: consistency proofs, witness cosignatures, signed-note interop tests with Go tooling in CI · 0.3: per-actor keys /
passkey attestations, key rotation record, receipt export.

## How this was built

The maintainers designed and directed this project and are responsible for it. Most of the code, tests and
documentation were drafted with AI coding assistants from two different providers, and the pre-publication reviews
(cryptography, security, licensing, documentation) were also carried out with AI assistance; their findings were fixed
with tests and vectors that are part of the test suite. No independent human security audit has been done (see
[SECURITY.md](SECURITY.md)). The project is not affiliated with, sponsored or endorsed by any AI provider; product names
mentioned anywhere in this repository are trademarks of their respective owners. Some AI-generated portions may not be
eligible for copyright protection in some jurisdictions; the licenses apply to the extent rights exist.

## Contributing, security, license

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
[AUTHORS](AUTHORS) · Code: Apache-2.0 ([LICENSE](LICENSE)), with RFC 8032-derived parts also under BSD-3-Clause
([NOTICE](NOTICE)) · Spec and docs: CC-BY-4.0 ([LICENSE-SPEC](LICENSE-SPEC)).
