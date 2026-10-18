# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Runs every directory under vectors/ and examples/ (anything with a case.json)
through the verifier twice: as a library call and as a subprocess with `python -I`
(proves the single file works with the standard library only).

Works with pytest and with `python -m unittest discover -s tests`.
"""
import filecmp
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "verifier"))
import agent_custody_verify as v  # noqa: E402

VERIFIER = os.path.join(ROOT, "verifier", "agent_custody_verify.py")


def case_dirs():
    out = []
    for top in ("vectors", "examples"):
        base = os.path.join(ROOT, top)
        for name in sorted(os.listdir(base)):
            d = os.path.join(base, name)
            if os.path.isfile(os.path.join(d, "case.json")):
                out.append(d)
    return out


def load(d):
    with open(os.path.join(d, "case.json"), encoding="utf-8") as f:
        return json.load(f)


def rel(d, p):
    return os.path.join(d, p) if p else None


def lib_args(d, a):
    return dict(
        log_path=rel(d, a["log"]), checkpoints=[rel(d, c) for c in a["checkpoints"]], vkeys=a["vkeys"],
        approver_keys=a["approver_keys"], ots_path=rel(d, a["ots"]), tsr_path=rel(d, a["tsr"]),
        proof_path=rel(d, a["proof"]), entry_path=rel(d, a["entry"]))


def cli_args(d, a):
    argv = []
    if a["log"]:
        argv.append(rel(d, a["log"]))
    for c in a["checkpoints"]:
        argv += ["--checkpoint", rel(d, c)]
    for k in a["vkeys"]:
        argv += ["--vkey", k]
    for k in a["approver_keys"]:
        argv += ["--approver-key", k]
    for flag, key in (("--ots", "ots"), ("--tsr", "tsr"), ("--proof", "proof"), ("--entry", "entry")):
        if a[key]:
            argv += [flag, rel(d, a[key])]
    return argv


class VectorTests(unittest.TestCase):
    def test_there_are_vectors(self):
        dirs = case_dirs()
        names = [os.path.basename(d) for d in dirs]
        self.assertGreaterEqual(sum(n.startswith("pass-") for n in names), 10)
        self.assertGreaterEqual(sum(n.startswith("fail-") for n in names), 25)

    def test_library(self):
        for d in case_dirs():
            with self.subTest(vector=os.path.basename(d)):
                case = load(d)
                rep = v.verify(**lib_args(d, case["args"]))
                for layer, state in case["expect"]["layers"].items():
                    self.assertEqual(rep.layers[layer][0], state, "%s: %s" % (layer, rep.layers[layer][1]))
                self.assertEqual(1 if rep.failed else 0, case["expect"]["exit"])

    def test_cli_stdlib_only(self):
        for d in case_dirs():
            with self.subTest(vector=os.path.basename(d)):
                case = load(d)
                p = subprocess.run([sys.executable, "-I", VERIFIER, "--json"] + cli_args(d, case["args"]),
                                   capture_output=True, text=True, timeout=120)
                self.assertEqual(p.returncode, case["expect"]["exit"], p.stdout + p.stderr)
                got = json.loads(p.stdout)
                for layer, state in case["expect"]["layers"].items():
                    self.assertEqual(got["layers"][layer]["state"], state)

    def test_fail_vectors_never_report_clean(self):
        for d in case_dirs():
            if os.path.basename(d).startswith("fail-"):
                with self.subTest(vector=os.path.basename(d)):
                    rep = v.verify(**lib_args(d, load(d)["args"]))
                    self.assertEqual(rep.overall, "fail")

    def test_vectors_are_reproducible(self):
        """Regenerating vectors/ must give byte-identical files."""
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_vectors.py"), tmp], check=True, capture_output=True)
            committed = os.path.join(ROOT, "vectors")
            cmp = filecmp.dircmp(committed, tmp)
            self.assertEqual(cmp.left_only, [])
            self.assertEqual(cmp.right_only, [])
            for name in os.listdir(tmp):
                a, b = os.path.join(committed, name), os.path.join(tmp, name)
                if os.path.isdir(a):
                    m = filecmp.dircmp(a, b)
                    self.assertEqual((m.left_only, m.right_only, m.diff_files), ([], [], []), name)
                else:
                    self.assertTrue(filecmp.cmp(a, b, shallow=False), name)

    def test_exit_codes_and_require(self):
        d = os.path.join(ROOT, "vectors", "pass-01-approval-flow-full")
        a = load(d)["args"]
        base = [sys.executable, "-I", VERIFIER] + cli_args(d, a)
        self.assertEqual(subprocess.run(base, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(base + ["--require", "checkpoint_signature"], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(base + ["--require", "timestamp"], capture_output=True).returncode, 3)
        self.assertEqual(subprocess.run(base + ["--require", "nonsense"], capture_output=True).returncode, 2)
        self.assertEqual(subprocess.run([sys.executable, "-I", VERIFIER], capture_output=True).returncode, 2)
        self.assertEqual(subprocess.run([sys.executable, "-I", VERIFIER, "/no/such/file.jsonl"], capture_output=True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
