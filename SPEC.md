# agent-custody specification, version 0.1 (experimental)

*License: CC-BY-4.0 (see `LICENSE-SPEC`). Reference code: Apache-2.0.*

Status: **draft, experimental.** Anything in this document may change before 1.0. Version strings in the data
(`v: 1`, `spec: "agent-custody/0.1"`, origin prefix `agent-custody/v1/`, signing domains `agent-custody/entry/v1` and
`agent-custody/approval/v2`) let verifiers fail closed on formats they do not understand. The approval signing domain
is `v2` because the signed approval statement gained members before the first release (see `CHANGELOG.md`); an
approval signed under the earlier statement does not verify.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose and non-goals

agent-custody defines a **log format and a verification procedure** so that a third party can check, offline and
without trusting the party that produced the log, that:

1. a sequence of recorded AI-agent actions, policy decisions, human approvals and cross-provider checks has not been
   altered, reordered, spliced or (relative to a signed checkpoint) truncated since the checkpoint was made;
2. the recorded order is consistent with a stated approval policy (an action that needed a human approval was not
   recorded as executed before, or without, one);
3. optionally, a specific entry belongs to a signed checkpoint (selective disclosure), and a checkpoint existed
   no later than an externally timestamped moment.

It does **not** make anyone honest, prove that the recorded actions really happened, or prove who the human was.
Section 12 and `LIMITS.md` are normative for how results may be described.

Non-goals for 0.1: a log server, witnesses/cosignatures, consistency proofs between checkpoints, per-actor key
infrastructure, encryption, redaction tooling, a legal-evidence profile.

## 2. Terminology

- **Log**: a JSONL file of **entries**, one chain.
- **Chain**: entries linked by `prev_hash`, identified by a 256-bit `chain_id`.
- **Checkpoint**: a signed statement "the first *N* entries of chain *C* have Merkle root *R*" in C2SP signed-note format.
- **Trusted key**: a checkpoint-signing public key that the verifier obtained through a channel independent of the log.
- **Layer**: one independently reported verification check (section 11).

## 3. Log file

UTF-8, no BOM, one JSON object per line, **every** line (including the last) terminated by `\n` (0x0A), no blank
lines. A `\r` before the `\n` (CRLF) and a last line without `\n` (an interrupted write looks like that) MUST be
rejected. A line is an **entry** with exactly these members (no others):

| member | type | meaning |
|---|---|---|
| `v` | integer | entry format version; MUST be `1` |
| `chain_id` | string | 64 lowercase hex chars (32 bytes); identical for every entry of the chain |
| `seq` | integer | 0-based position; MUST equal the line index |
| `ts` | string | `YYYY-MM-DDTHH:MM:SSZ`, **the writer host's clock**, not an attested time |
| `prev_hash` | string | `entry_hash` of the previous entry; 64 zeros for `seq` 0 |
| `event` | object | the payload (section 6) |
| `entry_hash` | string | 64 lowercase hex, defined in section 5 |

Parsers MUST reject duplicate object keys, NaN/Infinity, any non-integer number, and integers outside ±(2^53−1)
anywhere in the entry (so `seq` is at most 2^53−1). Line formatting (spacing, key order) is irrelevant to verification:
the verifier re-canonicalises.

Exact formats: hex members are exactly the stated number of lowercase hex characters and times are exactly
`YYYY-MM-DDTHH:MM:SSZ`, with nothing before or after (a trailing newline inside the string is an error), and times MUST
be real UTC calendar times (no month 13, no 30 February). The seconds field is `00`–`59`: a leap second written
`:60` (for example `2016-12-31T23:59:60Z`) is rejected, so that every implementation compares times as plain strings;
a writer records a leap second as `:59`.

Limits (a log that exceeds them fails `format`, or `events` for the string limit):

- nesting depth of objects and arrays within an entry: at most **64**, the entry object itself being depth 1;
- exactly these strings are 1 to **4096** Unicode code points: `chain_open` `agent.id`; `action` `action_id`,
  `actor.id`, `tool`, `summary`; `decision` `decision_id`, `actor.id`; `human_approval` `approval_id`, `approver.id`,
  `approver.method`; `cross_verification` `verification_id`, `author.provider`, `author.model`, and each reviewer's
  `provider` and `model`. No other string has a length limit (for example `agent.runtime`, `rationale`, the `type` of an
  `x-` extension, or members inside an extension): those are only bound by the depth limit and the input size;
- the size of each input file is an implementation limit, not a format rule. The reference verifier reads at most
  64 MiB per file by default (`--max-bytes`) and reports `fail` for the layer that reads a larger file.

Example (first entry of `vectors/pass-01-approval-flow-full`, pretty-printed):

```json
{ "v": 1, "seq": 0, "ts": "2026-03-01T09:00:00Z",
  "chain_id": "71c1224b0c1b6d2548b9712f98a43a59fcc80ef3c3c16d201ac212b8d594253e",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "event": { "type": "chain_open", "spec": "agent-custody/0.1",
             "chain_id": "71c1224b0c1b6d2548b9712f98a43a59fcc80ef3c3c16d201ac212b8d594253e",
             "agent": { "id": "agent-demo-1", "runtime": "demo-runtime" } },
  "entry_hash": "917b27bf55644c4563cd95537125896a967de74c7748fe82ee2b364fb8732281" }
```

## 4. Canonical JSON

Canonical form is the **RFC 8785 (JCS) subset without floating-point numbers**:

- no insignificant whitespace; UTF-8;
- object members sorted by the UTF-16 code units of their names (this differs from code-point order for characters
  above U+FFFF; `vectors/pass-08-unicode-canonical-form` covers it);
- strings escaped as RFC 8785 requires (`\"`, `\\`, `\b \f \n \r \t`, other control characters as `\u00xx` in lowercase
  hex; everything else, including non-ASCII, emitted raw). Lone surrogates are rejected;
- integers only, as minimal decimal, within ±(2^53−1); `true`, `false`, `null`, arrays as usual.

Because no floats are allowed, the subset coincides with full JCS on every value this format admits. Unicode
normalisation is NOT applied: two strings that differ only in normalisation form hash differently.

`canon(x)` below denotes this byte string.

## 5. Entry hash and chaining

```
body       = { "v", "chain_id", "seq", "ts", "prev_hash", "event" }     (everything except entry_hash)
entry_hash = hex( SHA-256( "agent-custody/entry/v1" || 0x00 || canon(body) ) )
```

`chain_id` is inside `body`, so an entry is bound to its chain: moving an entry to another chain breaks its hash or its
`chain_id` check. `prev_hash` is inside `body`, so each entry commits to all earlier ones.

`chain_id` SHOULD be 32 random bytes chosen at creation. Entry 0 MUST be a `chain_open` event whose `chain_id` equals
the entry's.

## 6. Events

Every `event` has a string `type`. Members not listed for a type are allowed and ignored by 0.1 verifiers (they are
still hashed). Types not defined here MUST start with `x-` (opaque extension) or the log fails verification.
Fields named `*_digest` are 64 lowercase hex characters: SHA-256 of canonical JSON (or any bytes) kept **outside** the
log. Put digests in the log, not secrets or personal data (section 13).

References (`*_entry_hash`) point to the `entry_hash` of an **earlier** entry.

### 6.1 `chain_open` (seq 0 only)
`chain_id` (= entry chain_id), `spec` (= `"agent-custody/0.1"`), `agent` `{id, runtime?}`.

### 6.2 `action`
`action_id`, `phase` ∈ `requested | executed | failed`, `actor` `{kind ∈ agent|human|system, id}`, `tool`, `summary`,
`risk` ∈ `low|medium|high|critical`, optional `input_digest`, `result_digest`.
- `requested`: MUST carry `requires_approval` (boolean) — the policy's claim at request time.
- `executed` / `failed`: MUST carry `request_entry_hash` referencing a `requested` action with the same `action_id`.

### 6.3 `decision`
`decision_id`, `subject_entry_hash` (a `requested` action), `outcome` ∈ `allow|deny|escalate`,
`basis` ∈ `policy|model|human`, `actor`, optional `rationale`.

### 6.4 `human_approval`
`approval_id`, `subject_entry_hash` (a `requested` action), `outcome` ∈ `approved|rejected`,
`approver` `{id, method}`, `presented_digest` (hash of what the human was actually shown), optional `expires_at`
(same time format as `ts`), optional `approver_signature` `{public_key, signature}` (hex Ed25519).

`approval_id` MUST be unique within a chain: a second `human_approval` with an `approval_id` already used by an earlier
entry fails the `events` layer, whatever its outcome or subject.

The approver signs, with their own key, every member the approval gate (6.6) relies on:

```
msg = "agent-custody/approval/v2" || 0x00 || canon({ chain_id, approval_id, subject_entry_hash, outcome,
                                                    presented_digest, approver_id, approver_method,
                                                    expires_at })
```
where `approver_id` = `approver.id`, `approver_method` = `approver.method`, and `expires_at` is the event's value or
`null` when absent. Consequences:

- binding `chain_id` and the subject prevents replaying an approval in another chain or for another action;
- binding `expires_at` and `method` means removing, extending or adding an expiry, or changing the recorded method,
  invalidates the signature;
- binding `approval_id`, together with its uniqueness, means a signed approval cannot be copied to a later position of
  the same chain (for example after a `rejected`) and counted again;
- the signature does **not** bind a position, a time or a nonce: it gives no freshness. The approver could have signed
  long before the entry was written, and nothing stops the writer from leaving a signed approval out of the log.

The verifier validates the signature; it can only link the key to the person if the caller **pins** it
(`--approver-key approver-id=<hex>`) obtained independently. Small-order public keys are rejected (section 9).

### 6.5 `cross_verification`
`verification_id`, `subject_entry_hash` (any earlier entry), `author` `{provider, model}`,
`reviewers[]` of `{provider, model, verdict ∈ agree|disagree|inconclusive, finding_count?, findings_digest?}`,
`cross_provider` (boolean). The verifier recomputes `cross_provider` as "at least one reviewer's provider differs from
the author's" and fails the `events` layer if the claim disagrees. Two provider names are the same provider when they
are equal after, in this order: Unicode NFC normalisation; removal of leading and trailing ASCII space, tab, CR and LF;
mapping the ASCII letters `A`–`Z` to `a`–`z` (no other case mapping: `Ä` and `ä`, or `STRASSE` and `straße`, are
different names). This rule is deliberately narrow so that every implementation computes the same answer.
Provider and model names are **self-declared by the writer**; the format makes the claim explicit and ordered, it does
not authenticate the providers.

### 6.6 Approval gate (policy over the recorded order)
An **execution attempt** is an `action` with `phase = executed` or `phase = failed` (a failure can follow a partial
execution, so both are gated). For every attempt whose `requested` entry has `requires_approval = true`:

1. the latest `human_approval` for that request with a lower `seq` MUST have `outcome = approved`;
2. if it has `expires_at`, the attempt's `ts ≤ expires_at`;
3. **one approval authorises exactly one attempt**: that approval MUST NOT have authorised an earlier attempt. A retry
   after a `failed` attempt, or a second run of the same request, needs a new `approved` approval (with a new
   `approval_id`) recorded after the previous attempt.

**Deny rule** (independent of `requires_approval`, so it applies to every attempt): if any `decision` with
`outcome = deny` for the attempt's request has a lower `seq` than the attempt, let D be the latest of them. Then

4. a `human_approval` for that request MUST exist with D.`seq` < `seq` < the attempt's `seq`, and the **latest** such
   approval MUST have `outcome = approved` (approved then rejected after the deny: the deny stands);
5. if that approval has `expires_at`, the attempt's `ts ≤ expires_at`.

Only a human approval lifts a deny. A later `decision` (`allow`, `escalate` or another `deny`) does not, and an approval
recorded before D does not. For a request with `requires_approval = true` the approval in rule 4 is necessarily the one
rules 1–3 evaluate, so it is also consumed by the attempt. Attempts whose request has `requires_approval = false` are not
limited in number, also after a lifted deny.

`approval_gate` is `ok` when at least one attempt was evaluated under rules 1–3 or rules 4–5 and none failed, and
`not_checked` when the log has no such attempt.
This checks the *record*; it does not prove the real system waited for the human.

## 7. Merkle tree

Leaves are the entries, in order. RFC 6962 hashing over the **entry hash bytes**:

```
leaf_i   = SHA-256( 0x00 || bytes(entry_hash_i) )
node     = SHA-256( 0x01 || left || right )
MTH(D)   = per RFC 6962 section 2.1 (split at the largest power of two < n); MTH of one leaf is the leaf hash
```
Hashing `entry_hash` rather than the entry text keeps the tree independent of JSON formatting.

**Inclusion proof** (JSON, member set exact): `{ "v": 1, "chain_id", "leaf_index", "tree_size", "entry_hash",
"audit_path": [hex, ...] }` where `v` is the integer `1` (not `true`) and `leaf_index`, `tree_size` are integers in
0..2^53−1, verified with the algorithm of RFC 9162 section 2.1.3 against the root of a checkpoint with the same size and
chain. The `size` MUST come from the signed checkpoint: the algorithm alone cannot bind a path to a size. Therefore
`inclusion_proof` is `ok` only when that checkpoint carries a valid signature from a **trusted** key. A path that
reconstructs the root of a checkpoint no trusted key signed (no `--vkey`, or only unknown signers) is `not_checked`,
never `ok`; a path that does not reconstruct the root is `fail` either way.

A **disclosed entry** presented with a proof MUST satisfy every entry rule of section 4 (exact member set, types,
formats, limits), must hash to the proven `entry_hash`, and must carry the proof's `chain_id` and `seq = leaf_index`.
Members outside the entry hash are not authenticated, so a disclosed entry with any extra member is `fail`, not
"matched".

## 8. Checkpoints

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note). Body (exactly three lines, `\n`-terminated):

```
agent-custody/v1/<chain_id>
<tree_size, decimal, 1..2^53−1, no leading zeros>
<base64 of the 32-byte Merkle root>
```
followed by a blank line and 1 to 16 signature lines `— <key name> <base64(key_id[4] || signature)>`
(U+2014 EM DASH, space). Layout follows C2SP `tlog-checkpoint` (origin, size, root) with a project-specific origin.
The signature (Ed25519, note type `0x01`) is over the body bytes including the final newline.
`key_id = SHA-256(name || 0x0A || 0x01 || public_key)[:4]`.
Verifier keys are written `name+<8 hex of key_id>+base64(0x01 || public_key)`.

A checkpoint MUST carry at most **16** signature lines; a note with more is malformed (`fail`), which bounds the work a
hostile checkpoint can force (each trusted-looking line costs one Ed25519 verification). A verifier MUST ignore
signature lines whose (name, key id) it does not trust, and MUST treat a checkpoint with no
signature from a trusted key as unverified. Implementation note: the checkpoint format was cross-checked by hand, in
both directions, against Go `golang.org/x/mod/sumdb/note` v0.42.0 (Go accepts this repository's checkpoints and rejects
the forged ones; a note signed by Go verifies here). That check is not yet automated in CI, and other signed-note
tooling has not been tried.

A checkpoint covering N entries commits to those N entries. Entries after N are the **unsigned tail**; the verifier
reports their count and does not vouch for them.

## 9. Keys and Ed25519

- Algorithm: Ed25519 (RFC 8032). The reference verifier implements verification in pure Python (RFC 8032 section 5.1.7,
  cofactorless equation, `s < L` enforced, non-canonical point encodings rejected). Public keys that do not decode or
  that have small order (8·A is the neutral element, for example the identity point `01 00…00`) MUST be rejected,
  both as approver keys and as checkpoint keys: such a key satisfies the verification equation for many messages. It is variable-time, which is acceptable because all verification
  inputs are public. The reference **writer's** pure-Python signer is for tests and demos only; production signers
  MUST use a vetted implementation and keep the private key off the machine that runs the agent.
- Trust in a checkpoint key MUST come from outside the log bundle (a pinned file, a prior release, a published
  fingerprint). A key shipped next to the log proves nothing about who made the log.
- 0.1 defines no key rotation, revocation or delegation. Use a new `chain_id` or a new key name and distribute the new
  verifier key out of band.

## 10. Timestamps (optional)

The timestamped object is `SHA-256(checkpoint body bytes)` — the three-line body, without signature lines.

- **OpenTimestamps**: a `.ots` file that stamps the checkpoint body as a file: its file-hash operation is SHA-256 and
  the file digest it records is exactly the digest above (what `ots stamp` produces for a file holding the body
  bytes; there is no second hashing). The stdlib verifier checks only that the file is an OTS proof for the right digest and reports `unavailable` for the Bitcoin attestation; run the official
  `ots verify` for that. A *pending* proof is not yet a timestamp.
- **RFC 3161**: a `.tsr` whose `messageImprint` is that digest. The stdlib verifier reports `unavailable`; run
  `openssl ts -verify`.

What a timestamp adds: the checkpoint existed **no later than** that moment. It says nothing about the entry `ts` values,
which remain the writer host's clock. Neither mechanism has any particular legal status by itself; see `LIMITS.md`.

## 11. Verification procedure

A verifier evaluates these layers independently and reports each as:

`ok` (checked, passed) · `fail` (checked, failed) · `not_checked` (needed input not supplied) ·
`unavailable` (input supplied but this verifier cannot perform the check).

| layer | checks |
|---|---|
| `format` | JSONL with `\n` line ends, strict JSON, exact member set, `v`, exact hex/time formats, integer range, nesting depth, input size |
| `entry_hashes` | each `entry_hash` recomputes (section 5) |
| `chain_links` | `seq` = index, `prev_hash` links (zeros at 0), one `chain_id` throughout |
| `events` | event schemas, string limits, `chain_open` first and only first, references to earlier entries, unique `approval_id`, `cross_provider` recomputation |
| `approval_gate` | section 6.6 (every execution attempt; one approval per attempt; deny lifted only by a later human approval) |
| `approver_signatures` | section 6.4; `ok` only if every approval is signed, valid, and its approver key is pinned |
| `checkpoint_root` | origin matches `chain_id`; checkpoint size ≤ log length; recomputed root equals the checkpoint root |
| `checkpoint_signature` | a trusted key signed the body (`not_checked` if no trusted key supplied) |
| `inclusion_proof` | section 7, against the supplied checkpoint; `ok` only if a trusted key signed that checkpoint |
| `timestamp` | section 10 |

Rules:
- An unknown `v`, spec string or event type is `fail`, never skipped.
- A verifier MUST NOT print a single unqualified "valid". With no `fail`, it reports that **no inconsistency was found
  in the layers that passed** and lists the others.
- Exit codes of the reference CLI: 0 no layer failed; 1 a layer failed; 2 usage or I/O error; 3 a layer named by
  `--require` was not `ok`.
- Vectors in `vectors/` define expected layer states; a conforming implementation MUST agree on them.

## 12. Threat model

**What a clean result supports** (all relative to the layers actually `ok`):

| layer set | supports the statement |
|---|---|
| `entry_hashes`+`chain_links` | the entries are internally consistent: no entry was edited, removed from the middle, reordered or inserted without rewriting everything after it |
| + `checkpoint_root`+`checkpoint_signature` (trusted key) | the first N entries are the ones the key holder committed to at checkpoint time: later edits, deletions, truncation below N, and wholesale rewrites that the holder did not re-sign are detected. Read the two together with `entry_hashes`: the Merkle tree is computed over the **declared** `entry_hash` values, so if an entry's content is edited but its `entry_hash` left alone, `checkpoint_root` still reports a match and only `entry_hashes` fails |
| + `inclusion_proof` | one disclosed entry belongs to a checkpoint signed by a trusted key, without revealing the others |
| + `approver_signatures` with pinned keys | the holder of the pinned key signed that exact approval (id, outcome, subject, presented context, method, expiry) for this chain; not when they signed it (no freshness) |
| + `timestamp` (verified externally) | the checkpoint existed no later than the proven time |
| `approval_gate` | the *recorded order* satisfies the approval policy |

**What it does not prove** (normative; see `LIMITS.md` for the longer list):

- That recorded actions happened, or that unrecorded ones did not. The log contains what the writer chose to write.
- That the writing host or agent runtime was uncompromised. An attacker who controls the writer *before* a checkpoint is
  signed can write a perfectly consistent false log. Hash chains detect change **after** the fact, not lies at write time.
- Anything about entries after the last verified checkpoint (the unsigned tail), or about truncation/rewrite when no
  external checkpoint exists (`pass-12`, `pass-13` demonstrate this on purpose).
- Who a human is. A pinned key identifies a key holder; binding it to a person is an out-of-band, organisational step.
- When an individual entry was written. `ts` is the writer's clock.
- That a cross-verification involved the providers it names.
- Legal effect of any kind. This is a technical integrity format, not an electronic signature scheme with legal status
  and not a trusted-timestamp service.
- Freshness or absence of forks: with a single operator and no witnesses, the operator can sign two different histories
  to different audiences (split view). Mitigation (witnesses cosigning checkpoints) is planned, not part of 0.1.

## 13. Privacy and data minimisation

Logs are evidence, so they tend to be kept. Record **digests of** inputs/outputs, not secrets, credentials, or personal
data; store the underlying material elsewhere under its own retention rules and reveal it only when needed (a recipient
can recompute the digest). Hashes of low-entropy data (e.g. a short PIN) can be brute-forced: hash a high-entropy
salted value instead. A published checkpoint reveals chain size and timing.

## 14. Extensibility and roadmap

Unknown future versions fail closed. Extension events use the `x-` prefix. Candidate work, none of it promised:

- 0.2: RFC 6962 consistency proofs between checkpoints; C2SP `tlog-witness` cosignatures (anti split-view); automated
  signed-note interoperability tests against Go tooling in CI.
- 0.3: per-actor keys and passkey/WebAuthn attestations as approval evidence; key rotation record type; export to
  OpenTelemetry/SCITT-style receipts.

## 15. Relationship to other work

The checkpoint and Merkle layers reuse C2SP signed-note/tlog-checkpoint conventions and RFC 6962/9162. The event model
is a small profile aimed at agent actions and human approvals; IETF individual drafts on agent audit trails and SCITT
are moving targets and **no conformance to them is claimed**. Several open-source projects record agent actions with
hash chains and signatures; this spec's emphasis is the human-approval event, the cross-provider verification event,
and a verifier that states what it did not check.
