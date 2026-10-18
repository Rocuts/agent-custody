## What and why

<!-- One paragraph. Link the issue for any spec change. -->

## Checklist

- [ ] `python -m unittest discover -s tests` and `python -m pytest -q` pass
- [ ] Behaviour change? Vectors added or updated in `tools/make_vectors.py`, regenerated, and `git status` is clean
- [ ] The verifier and writer still import only the standard library
- [ ] Docs do not claim more than `LIMITS.md` allows
- [ ] Synthetic data only (no real hosts, people, paths, addresses or credentials)
- [ ] Every commit is signed off (`git commit -s`, [DCO 1.1](https://developercertificate.org/))
- [ ] AI tools used for this change, if any: <!-- name them, or write "none" -->
