# Contributing

Thanks for looking. This is a small, deliberately boring project: a spec, one verifier file and a set of test vectors.

## Ground rules

1. The verifier stays one file, Python 3.10+, standard library only. No third-party imports in
   `verifier/agent_custody_verify.py`; a test enforces this. Optional cross-checks may use `cryptography` inside tests
   and must skip when it is not installed.
2. Every behaviour change comes with vectors. If the verifier starts accepting more input, add a `fail-*` vector that
   shows what is still rejected. If it starts rejecting more, add a `pass-*` vector for what is still accepted. Edit
   `tools/make_vectors.py`, run it and commit the output. A test regenerates the vectors and fails on any drift.
3. Accurate output over pretty output. A layer that was not run says `not_checked` or `unavailable`. Never add a code
   path that prints an unqualified "valid".
4. Fail closed. Unknown version, unknown event type or malformed input means `fail`.
5. Synthetic data only. Vectors, examples and docs must not contain real people, customers, hosts, networks, paths,
   addresses or credentials. Use `*.example.test` hostnames and obviously fake identifiers. A test scans the tree.
6. Wording. Docs may call the project tamper-evident and independently verifiable. Do not claim legal validity,
   compliance, certification, or anything under "Wording to avoid" in `LIMITS.md`. A test scans the tree for the
   banned terms; only `LIMITS.md` and this file may name them.

## Running the tests

You need Python 3.10 or newer. Use `python3` if `python` is not found.

```sh
python3 -m unittest discover -s tests -v      # no dependencies
python3 -m pip install --require-hashes -r requirements-dev.txt   # pinned pytest + cryptography, optional
python3 -m pytest -q                           # same tests, plus the cross-check against `cryptography`
python3 tools/make_vectors.py && python3 tools/make_examples.py   # regenerate; then `git status --porcelain` must be empty
```

## Spec changes

Open an [issue](https://github.com/Rocuts/agent-custody/issues) first for anything that touches hashing,
canonicalisation, the checkpoint format or layer semantics. Those change what every existing log means. Bump the
version strings whenever the bytes change.

## Licensing and sign-off

Code is Apache-2.0; the specification and docs are CC-BY-4.0. By contributing, you agree that your contribution is
licensed under the same terms.

Every commit needs a `Signed-off-by:` line (`git commit -s`) certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/). Pull requests without sign-off are not
merged.

AI-assisted contributions are welcome if you have reviewed and understood every line, can explain it, and take
responsibility for it under the DCO. Say in the pull request which tools you used. Don't submit output you couldn't
have licensed yourself, such as code reproduced from a project with an incompatible license.

## Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
