# Security policy

agent-custody is **experimental (v0.1)** and has had **no independent security review**. Do not rely on it as the only
control for anything where failure is costly.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability. Report it privately through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose **"Report a vulnerability"**, or go directly
to <https://github.com/Rocuts/agent-custody/security/advisories/new>. There is no security e-mail address.

This is the single contact point of the project; `CODE_OF_CONDUCT.md` refers here.

Include: affected file and version, a minimal log/checkpoint that reproduces the problem, and what you expected.
We aim to acknowledge reports within 7 days. This is a volunteer-maintained project; there is no bounty or SLA.

## What counts as a security bug

- A tampered, reordered, truncated or transplanted log, proof or checkpoint that the verifier accepts when it should
  report `fail` (the most important class; please add a failing vector).
- A parser crash, hang or excessive resource use on hostile input within the documented limits (SPEC.md section 3:
  nesting depth 64, input size `--max-bytes`); the verifier must fail closed, never crash or hang.
- The verifier reporting `ok` for a layer it did not run, or for a layer whose result rests on an untrusted input
  (for example an inclusion proof against a checkpoint no trusted key signed).
- Wrong Ed25519 / Merkle behaviour against RFC 8032 / RFC 6962 / RFC 9162 test data.
- Documentation that over-claims what the format proves (see `LIMITS.md`).

## Out of scope

- Compromise of the host, agent runtime or signing key that writes the log (documented in `LIMITS.md`).
- Side channels in the demo signer (`writer/`); it is explicitly not for production keys.
- Missing features listed in the roadmap, `SPEC.md` section 14.

## Supported versions

Only the latest release/`main`. Formats may change before 1.0; format changes are announced in
[CHANGELOG.md](CHANGELOG.md) and by bumping the version strings, so old verifiers fail closed.
