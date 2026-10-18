# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, any release may change the data format; when the
bytes that are hashed or signed change, the corresponding version string changes too, so older verifiers fail closed.

## [0.1.0] - 2026-10-18

First public version: specification (`SPEC.md`), limits (`LIMITS.md`), single-file standard-library verifier,
reference writer, 69 pass/fail vectors, three synthetic examples and an agent skill.

Changes made during the pre-publication review (none of them affects a released log, because none exists yet):

### Changed (format)
- Approver signatures now cover `approver.method` and `expires_at` (or its absence) in addition to the earlier members.
  The signing domain is `agent-custody/approval/v2`; approvals signed under the earlier statement do not verify.
- `approval_id` must be unique within a chain.
- The approval gate applies to every execution attempt (`executed` and `failed`), and one `approved` approval
  authorises exactly one attempt.
- Provider names in `cross_verification` are compared after NFC normalisation, ASCII-whitespace trimming and ASCII-only
  lowercasing (was: unspecified Unicode lowercasing).
- `inclusion_proof` is `ok` only against a checkpoint signed by a trusted key; otherwise `not_checked`.
- Deny rule written out exactly (SPEC section 6.6, rules 4-5): after a `deny`, an attempt needs a later human approval
  whose latest instance is `approved` (and unexpired); a later `allow` decision no longer lifts a deny, and an
  approval followed by a rejection no longer does either. `approval_gate` is `ok` when the deny rule was evaluated.
- A disclosed entry checked with `--entry` must follow every entry rule (exact member set): members outside the entry
  hash are rejected instead of reported as matched.
- Checkpoints carry at most 16 signature lines.
- Leap seconds (`:60`) are rejected explicitly; the list of strings bound by the 4096 code-point limit is exhaustive.

### Added
- Format limits written down in SPEC section 3: lines end with `\n` (CRLF and a missing final newline are rejected),
  exact hex/time formats, real calendar times, nesting depth 64, schema strings up to 4096 code points.
- Rejection of small-order Ed25519 public keys (approver keys, `--vkey`, `--approver-key`).
- `--max-bytes` input size limit in the verifier (default 64 MiB per file).
- Python version guard (3.10+) in the verifier.
- Writer: demo seed read from `--seed-file` or `AGENT_CUSTODY_DEMO_SEED`, never from the command line; `keygen` writes
  a 0600 seed file; checkpoint and proof sizes are bounds-checked; `ts`, `chain_id` and checkpoint key names are
  validated; an existing log is re-verified before anything is appended to it.
- Licence notice for the code derived from RFC 8032 section 6 (BSD-3-Clause, IETF Trust).
- `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `AUTHORS`, issue and pull request templates, pinned and hash-checked CI.

### Fixed
- Out-of-range integers, oversized checkpoint sizes and deeply nested input now fail a layer (exit 1) instead of
  producing a usage error or an uncaught exception.
