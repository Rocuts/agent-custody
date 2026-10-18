# Limits: what agent-custody does and does not do

*License: CC-BY-4.0. Read this before you describe the project to anyone, including in a sales deck or a compliance
document.*

agent-custody makes a log of agent actions and human approvals tamper-evident: a third party who holds a trusted
checkpoint key can detect changes made after the fact. That is the whole claim. Everything below follows from it.

## What it is not

1. Not an electronic signature with legal effect. The Ed25519 signatures are ordinary cryptographic signatures, with
   no certificate authority, accredited provider or regulator behind them. Whether a court or counterparty accepts
   them depends on local law and on contract, so ask a lawyer in your jurisdiction. Whether they count as any kind of
   electronic signature under a given law is a legal question this project does not answer.
2. Not a trusted-timestamp service. OpenTimestamps and RFC 3161 support is optional and external. An OpenTimestamps
   proof shows a hash existed before a Bitcoin block. An RFC 3161 token shows a hash existed before a time asserted by
   a timestamp authority. Neither makes this project a qualified or accredited timestamp, and the stdlib verifier
   verifies neither fully; it reports `unavailable`.
3. Not proof that the host was intact. If the machine that writes the log, the agent runtime or the signing key is
   compromised *before* a checkpoint is signed, the log can be false and still verify. A hash chain detects changes
   after the fact. It cannot detect lies told at write time.
4. Not proof that the recorded events happened. It shows what was recorded, in what order, and that the record has not
   changed since the checkpoint. It does not observe the agent or the world.
5. Not an identity system. A pinned approver key shows that whoever held that key signed that approval. Whether that
   was the named person is an organisational question (key custody, onboarding), not a cryptographic one.
6. Not a compliance certification. It can produce evidence that helps with record-keeping and oversight duties, such
   as logging obligations in AI or security regulation. It does not make a system or organisation compliant with any
   regulation, standard or framework, and nothing in this repository claims that it does.
7. Not confidentiality. Logs are plain JSON. Keep secrets and personal data out of events; record digests instead.
8. Not availability or backup. If a log and all its checkpoints are deleted, there is nothing left to compare against.

## What an approver signature covers

An `approver_signature` (SPEC section 6.4, signing domain `agent-custody/approval/v2`) covers exactly these fields:
`chain_id`, `approval_id`, `subject_entry_hash` (the request), `outcome`, `presented_digest`, `approver.id`,
`approver.method`, and `expires_at` or its absence. Nothing else in the event or the entry is signed.

- It does not cover `seq`, `ts`, `prev_hash` or any nonce, so it gives no freshness. A key holder's signature may be
  old, and a writer can leave out a signed approval it did not like.
- Re-use inside one chain is blocked by rules, not by the signature alone. `approval_id` must be unique in the chain
  (`events` layer), and one `approved` approval authorises exactly one execution attempt, `executed` or `failed`
  (`approval_gate` layer). A retry needs a new approval.
- `presented_digest` is a hash the writer chooses. The signature shows the key holder signed that hash, not that the
  human read or understood what it stands for.

## Specific blind spots

Each one has a test vector or is stated in SPEC section 12.

| Blind spot | Consequence |
|---|---|
| No checkpoint, no detection of truncation or of a complete re-chained rewrite (`vectors/pass-12`, `pass-13`). | Create checkpoints, store them where the log writer cannot rewrite them, and verify against them. |
| Unsigned tail. Entries after the last verified checkpoint are not covered. | Checkpoint often. The verifier reports the length of the tail. |
| `ts` is the host's clock. An entry can be backdated at write time. | Only an external timestamp on a checkpoint bounds *when the checkpoint existed*, not when each entry was written. |
| Split view. A single operator can sign two different histories for two audiences. | Needs independent witnesses (planned, not in 0.1). |
| Trust in the checkpoint key. A verifier key delivered with the log proves nothing. | Pin the key through an independent channel. |
| The approval gate checks the record. | It cannot show that the real system waited for the human. It shows that the log never claims otherwise. |
| Cross-verification names are self-declared. | The log does not authenticate that provider B really answered. |
| Execution is not bound to the approved request. An `executed` or `failed` entry references its request by hash and must repeat its `action_id`, but its `tool`, `risk` and `summary` are not compared with the request's, or with what the approver saw. | A writer can record an execution whose details differ from the approved request and still pass every layer. Judge what was approved from the request entry and its `presented_digest`, never from the execution entry. |
| `risk` and `requires_approval` are self-declared. | A writer can under-declare risk. The gate trusts the request entry it is shown. |
| Key loss or compromise. 0.1 has no rotation or revocation. | Treat a compromised key as invalidating future checkpoints, and re-establish trust out of band. |
| Pure-Python Ed25519. Verification is variable-time, which is fine because its inputs are public. The bundled signer is for demos only. | Use a real signer and keep keys off the agent host. |
| Not independently audited. This is experimental software with no external cryptographic review. | See `SECURITY.md`. |
| Inclusion proofs need a trusted checkpoint. A proof against a checkpoint no trusted key signed proves nothing, since anyone can build a tree. | The verifier reports `inclusion_proof` as `not_checked` unless the checkpoint signature verifies under a `--vkey`. With `--require inclusion_proof` it then exits 3. |
| Input limits. Nesting depth 64 per entry, 4096 code points for schema strings and, in the reference verifier, 64 MiB per input file by default (`--max-bytes`). | Larger or deeper input fails the layer that reads it. The verifier reads each file whole into memory, so set `--max-bytes` to what your machine can hold. |
| Interop is only hand-checked. Checkpoints were checked by hand in both directions against Go `golang.org/x/mod/sumdb/note` v0.42.0. This is not yet a CI test, and no other signed-note tooling has been tried. | Re-check with the tool you depend on. |

## How to describe it

Wording the project supports:

- "tamper-evident log of agent actions and human approvals"
- "independently verifiable by a third party who holds the checkpoint key"
- "detects alteration, reordering and truncation relative to a signed checkpoint"
- "the verifier tells you which checks it ran and which it could not"

Wording to avoid, because the project cannot back it up. It is listed here so reviewers can check text against it.

- *immutable*, *tamper-proof*, *unforgeable*
- *non-repudiation* (an approver key signature is evidence about a key holder, not a guarantee of attribution)
- *legally valid / legally binding / admissible* as a property of the product
- *certified*, *qualified*, *accredited* anything
- *AI Act compliant*, *compliant with* any standard, "satisfies Article N"
- *proves what the agent did*, *proves the host was secure*
