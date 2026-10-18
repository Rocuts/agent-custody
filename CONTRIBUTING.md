# Contributing

Thanks for looking. This is a small, deliberately boring project: a spec, one verifier file, and test vectors.

## Ground rules

1. **The verifier stays one file, Python 3.10+, standard library only.** No third-party imports in
   `verifier/agent_custody_verify.py` (a test enforces this). Optional cross-checks may use `cryptography` inside tests
   and must skip when it is absent.
2. **Every behaviour change needs vectors.** A change that makes the verifier accept more input needs a `fail-*` vector
   showing what is still rejected; a change that rejects more needs a `pass-*` vector for what stays accepted. Edit
   `tools/make_vectors.py`, run it, commit the output; a test regenerates the vectors and fails on any drift.
3. **Honest output beats pretty output.** If a layer was not run, it says `not_checked` or `unavailable`. Never add a
   code path that prints an unqualified "valid".
4. **Fail closed.** Unknown version, unknown event type, malformed input => `fail`.
5. **Synthetic data only.** Vectors, examples and docs must not contain real people, customers, hosts, networks, paths,
   addresses or credentials. Use `*.example.test` hostnames and obviously fake identifiers. A test scans the tree.
6. **Wording.** Docs may describe the project as tamper-evident and independently verifiable. Do not claim legal
   validity, compliance, certification, or properties listed under "Wording to avoid" in `LIMITS.md`. A test scans the
   tree for the banned terms (only `LIMITS.md` and this file may name them).

## Running the tests

Python 3.10 or newer. Use `python3` if `python` is not found.

```sh
python3 -m unittest discover -s tests -v      # no dependencies
python3 -m pip install --require-hashes -r requirements-dev.txt   # pinned pytest + cryptography, optional
python3 -m pytest -q                           # same tests, plus the cross-check against `cryptography`
python3 tools/make_vectors.py && python3 tools/make_examples.py   # regenerate; then `git status --porcelain` must be empty
```

## Spec changes

Open an [issue](https://github.com/Rocuts/agent-custody/issues) first for anything touching hashing, canonicalisation, checkpoint format or layer semantics: those change
what every existing log means. Bump the version strings when bytes change.

## Licensing and sign-off

Code is Apache-2.0, specification and docs are CC-BY-4.0. By contributing you agree your contribution is licensed under
the same terms.

**Sign-off (DCO).** Every commit must carry a `Signed-off-by:` line (`git commit -s`) certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). Pull requests without sign-off are not merged.

**AI-assisted contributions** are welcome if you have reviewed and understood every line, can explain it, and take
responsibility for it under the DCO. Say in the pull request description which tools you used. Do not submit output you
could not have licensed yourself (for example, code reproduced from a project with an incompatible license).

## Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
