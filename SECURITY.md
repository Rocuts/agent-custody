# Security policy

agent-custody is experimental (v0.1) and has not had an independent security review. Don't make it the only control
for anything where failure is expensive.

## Reporting a vulnerability

Please don't open a public issue for a vulnerability. Report it privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to
<https://github.com/Rocuts/agent-custody/security/advisories/new>. There is no security e-mail address.

This is the project's only contact point. `CODE_OF_CONDUCT.md` points here too.

Include the affected file and version, a minimal log or checkpoint that reproduces the problem, and what you expected
to happen. We aim to acknowledge reports within 7 days. The project is maintained by volunteers, with no bounty and no
SLA.

## What counts as a security bug

- The verifier accepts a tampered, reordered, truncated or transplanted log, proof or checkpoint that it should report
  as `fail`. This is the most important class; please include a failing vector.
- A parser crash, hang or excessive resource use on hostile input within the documented limits (SPEC.md section 3:
  nesting depth 64, input size `--max-bytes`). The verifier must fail closed, never crash or hang.
- The verifier reports `ok` for a layer it did not run, or for a layer whose result rests on untrusted input, such as
  an inclusion proof against a checkpoint no trusted key signed.
- Ed25519 or Merkle behaviour that disagrees with the RFC 8032, RFC 6962 or RFC 9162 test data.
- Documentation that claims more than the format proves (see `LIMITS.md`).

## Out of scope

- Compromise of the host, agent runtime or signing key that writes the log. This is documented in `LIMITS.md`.
- Side channels in the demo signer (`writer/`). It is not meant for production keys.
- Features listed in the roadmap, `SPEC.md` section 14.

## Supported versions

Only the latest release and `main`. Formats may change before 1.0. Format changes are announced in
[CHANGELOG.md](CHANGELOG.md) and come with new version strings, so older verifiers fail closed.
