# Limits: what agent-custody does and does not do

*License: CC-BY-4.0. Read this before you describe the project to anyone, including in a sales deck or a compliance document.*

agent-custody makes a log of agent actions and human approvals **tamper-evident**: changes made after the fact are
detectable by a third party who holds a trusted checkpoint key. That is all it makes. Everything below is a consequence
of that sentence.

## What it is not

1. **Not an electronic signature with legal effect.** The Ed25519 signatures are ordinary cryptographic signatures. No
   certificate authority, accredited provider or regulator stands behind them. Whether a court or counterparty accepts
   them is a question of local law and of contract; ask a lawyer in your jurisdiction. Whether these signatures count as
   any kind of electronic signature under a given law is a legal question this project does not answer.
2. **Not a trusted-timestamp service.** OpenTimestamps and RFC 3161 support is optional and external. An OpenTimestamps
   proof shows a hash existed before a Bitcoin block; an RFC 3161 token shows a hash existed before a time asserted by a
   timestamp authority. Neither makes this project a qualified or accredited timestamp, and the stdlib verifier does not
   verify either fully (it says `unavailable`).
3. **Not proof of integrity of the host.** If the machine that writes the log (or the agent runtime, or the signing
   key) is compromised *before* a checkpoint is signed, the log can be false and still verify. A hash chain detects
   change after the fact; it cannot detect lies at write time.
4. **Not proof that the recorded events happened.** It proves what was recorded, in what order, and that it has not
   changed since the checkpoint. It does not observe the agent or the world.
5. **Not an identity system.** A pinned approver key proves that whoever held that key signed that approval. Whether
   that was the named person is organisational (key custody, onboarding), not cryptographic.
6. **Not a compliance certification.** It can produce evidence that helps with record-keeping and oversight duties
   (for example logging obligations in AI or security regulation). It does not make a system or organisation compliant
   with any regulation, standard or framework, and nothing in this repository claims that.
7. **Not confidentiality.** Logs are plain JSON. Do not put secrets or personal data in events; record digests.
8. **Not availability or backup.** Deleting a log and all its checkpoints leaves nothing to compare against.

## What an approver signature covers

An `approver_signature` (SPEC section 6.4, signing domain `agent-custody/approval/v2`) covers exactly: `chain_id`,
`approval_id`, `subject_entry_hash` (the request), `outcome`, `presented_digest`, `approver.id`, `approver.method` and
`expires_at` (or its absence). Nothing else in the event or the entry is signed.

- It does **not** cover `seq`, `ts`, `prev_hash` or any nonce: it gives **no freshness**. A key holder's signature may be
  old, and a writer can omit a signed approval it did not like.
- Re-use inside the same chain is stopped by rule, not by the signature alone: `approval_id` must be unique in the chain
  (`events` layer), and one `approved` approval authorises exactly **one** execution attempt, `executed` or `failed`
  (`approval_gate` layer). A retry needs a new approval.
- `presented_digest` is a hash chosen by the writer. The signature shows the key holder signed that hash, not that the
  human read or understood what it stands for.

## Specific blind spots (each has a test vector or is stated in SPEC section 12)

| Blind spot | Consequence |
|---|---|
| **No checkpoint, no detection** of truncation or of a complete re-chained rewrite (`vectors/pass-12`, `pass-13`). | Create checkpoints, store them somewhere the log writer cannot rewrite, and verify with them. |
| **Unsigned tail.** Entries after the last verified checkpoint are not covered. | Checkpoint often; the verifier reports the tail length. |
| **`ts` is the host's clock.** An entry can be backdated at write time. | Only an external timestamp on a checkpoint bounds *when the checkpoint existed*, not when each entry was written. |
| **Split view.** A single operator can sign two different histories for two audiences. | Needs independent witnesses (planned, not in 0.1). |
| **Trust in the checkpoint key.** A verifier key delivered with the log proves nothing. | Pin it from an independent channel. |
| **Approval gate checks the record.** | It cannot show the real system waited for the human; it shows the log never claims otherwise. |
| **Cross-verification names are self-declared.** | The log does not authenticate that provider B really answered. |
| **Execution is not bound to the approved request.** An `executed`/`failed` entry references its request by hash and must repeat its `action_id`, but its `tool`, `risk` and `summary` are not compared with the request's (or with what the approver saw). | A writer can record an execution whose details differ from the approved request and still pass every layer. Judge what was approved from the request entry and its `presented_digest`, never from the execution entry. |
| **Self-declared `risk`, `requires_approval`.** | A writer can under-declare risk. The gate trusts the request entry it is shown. |
| **Key loss/compromise.** No rotation or revocation in 0.1. | Treat a compromised key as invalidating future checkpoints and re-establish out of band. |
| **Pure-Python Ed25519.** Verification is variable-time (fine: public inputs). The bundled signer is for demos only. | Use a real signer and keep keys off the agent host. |
| **Not independently audited.** Experimental software, no external cryptographic review. | See `SECURITY.md`. |
| **Inclusion proofs need a trusted checkpoint.** A proof against a checkpoint no trusted key signed proves nothing (anyone can make a tree). | The verifier reports `inclusion_proof` as `not_checked` unless the checkpoint signature verifies under a `--vkey`; `--require inclusion_proof` then exits 3. |
| **Input limits.** Nesting depth 64 per entry, 4096 code points for schema strings, and, in the reference verifier, 64 MiB per input file by default (`--max-bytes`). | A larger or deeper input fails the layer that reads it. The verifier reads a whole file into memory, so set `--max-bytes` to what your machine can hold. |
| **Interop only hand-checked.** Checkpoints were cross-checked by hand in both directions against Go `golang.org/x/mod/sumdb/note` v0.42.0; this is not yet a CI test, and no other signed-note tooling has been tried. | Re-check with the tool you depend on. |

## How to describe it

Supported wording:

- "tamper-evident log of agent actions and human approvals"
- "independently verifiable by a third party who holds the checkpoint key"
- "detects alteration, reordering and truncation relative to a signed checkpoint"
- "the verifier tells you which checks it ran and which it could not"

Wording to avoid, because the project cannot support it (kept here so reviewers can check text against it):

- *immutable*, *tamper-proof*, *unforgeable*
- *non-repudiation* (an approver key signature is evidence for a key holder, not a guarantee of attribution)
- *legally valid / legally binding / admissible* as a property of the product
- *certified*, *qualified*, *accredited* anything
- *AI Act compliant*, *compliant with* any standard, "satisfies Article N"
- *proves what the agent did*, *proves the host was secure*
