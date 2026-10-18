# agent-custody

[![ci](https://github.com/Rocuts/agent-custody/actions/workflows/ci.yml/badge.svg)](https://github.com/Rocuts/agent-custody/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](verifier/agent_custody_verify.py)

Tamper-evident logs of what an AI agent did and which human approved it, checkable by someone who doesn't trust you.

Your agent changed a firewall rule at 3 a.m. Which key signed off on it, and can you show the log wasn't edited
afterward?

agent-custody is a log format and a one-file verifier for that question. The log records what the agent did,
which key holder approved it, and what a reviewer from a second AI provider said. Anyone holding your checkpoint key can then
check that none of it changed after the checkpoint was signed. The verifier is plain Python with no dependencies.

Status: v0.1, experimental. The format may change before 1.0. [Resumen en español](docs/es/RESUMEN.md).

## Who it's for

- Teams running agents that can touch production: infrastructure, credentials, customer data.
- MSPs and MSSPs whose agents act inside client environments and need to hand the client a record they can check.
- Authorized pentest and red-team work, where each scan or exploit step should trace back to a signed approval.
- Auditors and customers who want to verify that record themselves instead of reading a screenshot of it.

## Quickstart

You need Python 3.10 or newer. The verifier refuses to run on anything older, and some systems still ship an older
`python3` (stock macOS has 3.9), so check `python3 --version` first.

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

The first command prints one line per layer (`ok`, `fail`, `not_checked` or `unavailable`) and exits 0. It never
prints a bare "VALID". The last line reads:

```
RESULT: NO INCONSISTENCY FOUND in the 8 layer(s) that passed; 2 layer(s) not checked or unavailable. This is not proof of authenticity, correctness or that the host was uncompromised (see LIMITS.md).
```

The third command exits 1 and names the layer that broke:

```
[fail       ] entry_hashes         entry_hash does not match content at seq 3, 6
RESULT: FAIL - failed layers: entry_hashes
```

## How it works

```
 agent / tools ──► writer ──► log.jsonl        each entry hashes the one before it
                                 │
                       Merkle root (RFC 6962)
                                 ▼
                        checkpoint.note  ◄──  signed with your key, kept off the agent's host
                                 │
          ┌──────────────────────┼───────────────────────┐
          ▼                      ▼                       ▼
   timestamp (optional)   inclusion proof         verifier (one file, stdlib)
   OpenTimestamps or      reveals one entry,      a verdict per layer, including
   RFC 3161               not the whole log       the ones it could not check
```

The log holds four event types, plus `x-*` extensions: `action` (requested, executed, failed), `decision` (allow,
deny, escalate), `human_approval` and `cross_verification`. [SPEC.md](SPEC.md) has the details.

## What's different

Plenty of projects hash-chain agent logs. This one adds three things.

1. **Approvals are checked, not just stored.** An approval records a digest of what the human was shown and can be
   signed with the approver's own key. The `approval_gate` layer fails a log that records an approval-required action
   as executed before or without its approval, or any action executed after a policy `deny` that no later human
   approval lifted (a later `allow` does not count). It fails even when every hash is valid.
2. **Cross-provider review is an event.** "A model from provider B reviewed provider A's work and disagreed" becomes an
   ordered, hash-chained entry. The verifier works out from the recorded provider names whether reviewer and author
   came from different providers. Those names are self-declared.
3. **Small enough to read.** The verifier is a single Python file using only the standard library, with pure-Python
   Ed25519 (RFC 8032) and RFC 6962/9162 Merkle proofs. It is tested against the RFC vectors, the Certificate Transparency
   reference tree, and [69 vectors](vectors/README.md) of altered, reordered, truncated, transplanted and forged logs
   that must fail.

It reuses existing standards rather than inventing new ones: RFC 6962/9162 Merkle trees, RFC 8785 canonical JSON,
C2SP signed-note checkpoints, OpenTimestamps and RFC 3161.

## Limits

The full list is in [LIMITS.md](LIMITS.md). The three that matter most:

- It shows the record hasn't changed since a checkpoint. It doesn't show the events happened, or that the host writing
  them was clean. An attacker who controls the host before the checkpoint can write a consistent false log.
- Without a signed checkpoint stored where the log writer can't reach it, truncation or a full rewrite goes undetected
  ([`pass-12`](vectors/pass-12-limit-full-rewrite-no-checkpoint), [`pass-13`](vectors/pass-13-limit-truncation-no-checkpoint)).
- It is not an electronic signature with legal effect, a timestamp authority or a compliance certification.

## What's here

| path | what |
|---|---|
| [SPEC.md](SPEC.md) | format, hashing, checkpoints, verification layers, threat model (CC-BY-4.0) |
| [LIMITS.md](LIMITS.md) | what this does not do, and wording to avoid |
| `verifier/agent_custody_verify.py` | the verifier: one file, Python 3.10+, stdlib only |
| `writer/agent_custody_write.py` | small reference writer and CLI (demo signer only; see its docstring) |
| `vectors/` | pass/fail vectors with expected layer states |
| `examples/` | three synthetic scenarios: support agent with approval, security scan with a denial, cross-provider review |
| `skills/agent-custody/SKILL.md` | instructions for a coding agent on how to record and verify |
| `tests/` | `python3 -m unittest discover -s tests` or `pytest` |
| [CHANGELOG.md](CHANGELOG.md) | changes, including format changes |

## Roadmap

Plans, not promises. 0.2: consistency proofs, witness cosignatures, and signed-note interop tests against Go tooling
in CI. 0.3: per-actor keys and passkey attestations, a key rotation record, and receipt export.

## How this was built

The maintainers designed and directed the project and are responsible for it. Most of the code, tests and docs, and the
pre-publication reviews, were done with AI coding assistants from two providers; no independent human security audit has
been done, and the project is not affiliated with or endorsed by any AI provider.

## Contributing, security, license

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
[AUTHORS](AUTHORS)

Code is Apache-2.0 ([LICENSE](LICENSE)); the parts derived from RFC 8032 are also under BSD-3-Clause ([NOTICE](NOTICE)).
The spec and docs are CC-BY-4.0 ([LICENSE-SPEC](LICENSE-SPEC)). Some AI-generated portions may not be eligible for
copyright in some jurisdictions; the licenses apply to the extent rights exist. Product names are trademarks of their
owners.
