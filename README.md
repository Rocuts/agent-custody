# agent-custody

[![ci](https://github.com/Rocuts/agent-custody/actions/workflows/ci.yml/badge.svg)](https://github.com/Rocuts/agent-custody/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](verifier/agent_custody_verify.py)

A tamper-evident log of what an AI agent did and which key holder approved it, plus a verifier that someone who
doesn't trust you can run.

Your agent changed a firewall rule at 3 a.m. Which key signed off on it, and can you show the log wasn't edited
afterward?

agent-custody is a log format and a one-file verifier for that question. The log records each action the agent asked
for and ran, the policy decisions, the human approvals, and what a reviewer from a second AI provider said. You sign
checkpoints of the log with a key that should live off the agent's host. Anyone with the matching public key can then
check that the entries a checkpoint covers have not changed since it was signed. The verifier is a single Python file
with no dependencies.

Status: v0.1, experimental. The format may change before 1.0. [Resumen en español](docs/es/RESUMEN.md).

## Who it's for

- Teams whose agents can touch production systems, credentials or customer data.
- MSPs and MSSPs whose agents work inside client environments and who need to give the client a record the client can
  check.
- Authorized pentest and red-team work, where every scan or exploit step should trace back to a signed approval.
- Auditors and customers who want to run the check themselves.

## Quickstart

You need Python 3.10 or newer. Check `python3 --version` first: stock macOS still ships 3.9, and the verifier exits
with an error on anything older than 3.10.

```sh
# 1. verify a synthetic log: an agent rotates a Wi-Fi passphrase after a signed human approval
python3 verifier/agent_custody_verify.py examples/01-support-wifi-password/log.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)" \
  --approver-key "$(cat examples/01-support-wifi-password/approver-key.txt)"

# 2. tamper with a copy: change the approved target
sed 's/ap-guest-demo/ap-admin-demo/' examples/01-support-wifi-password/log.jsonl > /tmp/tampered.jsonl

# 3. verify the copy
python3 verifier/agent_custody_verify.py /tmp/tampered.jsonl \
  --checkpoint examples/01-support-wifi-password/checkpoint.note \
  --vkey "$(cat examples/01-support-wifi-password/vkey.txt)"; echo "exit code: $?"
```

The first command prints one line per layer, each `ok`, `fail`, `not_checked` or `unavailable`, and exits 0. It never
prints a bare "VALID". Its last line is:

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

Entry 0 is always a `chain_open` event. After it come `action` (phase `requested`, `executed` or `failed`),
`decision` (`allow`, `deny` or `escalate`), `human_approval` and `cross_verification`. Custom event types must start
with `x-`. [SPEC.md](SPEC.md) has the schemas.

## What's different

Plenty of projects hash-chain agent logs. Three things set this one apart.

1. The verifier checks approvals against actions. An approval records a digest of what the human was shown, and the
   approver can sign it with their own key. The `approval_gate` layer fails the log if an action that needed approval
   ran while its most recent approval was missing, rejected or expired, reused an approval that an earlier attempt had
   already consumed, or ran after a policy `deny` that no later human approval lifted. A later `allow` does not lift a deny. This layer can
   fail even when every hash is valid.
2. Cross-provider review has its own event type. When a model from one provider reviews another provider's work, the
   reviewers and their verdicts go into the chain like any other entry. The verifier recomputes from the recorded
   provider names whether author and reviewer differ. The writer declares those names; nothing authenticates them.
3. The verifier is about 1,200 lines of standard-library Python, including its own Ed25519 (RFC 8032) and RFC
   6962/9162 Merkle proofs. The tests use the RFC 8032 vectors, the RFC 6962 reference tree from Certificate
   Transparency, and [69 vectors](vectors/README.md) of altered, reordered, truncated, transplanted and forged logs
   that must fail.

The format builds on RFC 6962/9162 Merkle trees, RFC 8785 canonical JSON, C2SP signed-note checkpoints, OpenTimestamps
and RFC 3161.

## Limits

The full list is in [LIMITS.md](LIMITS.md). The ones that matter most:

- It shows the record hasn't changed since a checkpoint. It doesn't show the events happened, or that the host writing
  them was clean. An attacker who controls the host before the checkpoint can write a consistent false log.
- Without a signed checkpoint stored where the log writer can't reach it, truncation or a full rewrite goes undetected
  ([`pass-12`](vectors/pass-12-limit-full-rewrite-no-checkpoint), [`pass-13`](vectors/pass-13-limit-truncation-no-checkpoint)).
- An approver signature shows that the holder of a key signed. Tying that key to a person is up to your organisation.
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

Nothing here is promised. Planned for 0.2: consistency proofs between checkpoints, witness cosignatures, and CI
interop tests against Go signed-note tooling. For 0.3: per-actor keys and passkey attestations, a key rotation record,
and receipt export.

## How this was built

The maintainers designed and directed the project and are responsible for it. AI coding assistants from two providers
wrote most of the code, tests and docs, and did the pre-publication reviews. No independent human security audit has
been done. The project is not affiliated with or endorsed by any AI provider.

## Contributing, security, license

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
[AUTHORS](AUTHORS)

Code is Apache-2.0 ([LICENSE](LICENSE)); the parts derived from RFC 8032 are also under BSD-3-Clause ([NOTICE](NOTICE)).
The spec and docs are CC-BY-4.0 ([LICENSE-SPEC](LICENSE-SPEC)). Some AI-generated portions may not be eligible for
copyright in some jurisdictions; the licenses apply to the extent rights exist. Product names are trademarks of their
owners.
