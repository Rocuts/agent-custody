# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Repository-level checks: synthetic data only, banned claims, reproducible examples, writer CLI round trip."""
import filecmp
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WRITER = os.path.join(ROOT, "writer", "agent_custody_write.py")
VERIFIER = os.path.join(ROOT, "verifier", "agent_custody_verify.py")
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}
THIS = os.path.abspath(__file__)

# Terms the project must not use to describe itself. Only the files that explain the rule may name them.
BANNED = [r"immutab", r"tamper[- ]?proof", r"non-?repudiation", r"legally (valid|binding)", r"ai act[- ]compliant",
          r"inmutable", r"no repudio", r"a prueba de manipulaci", r"unforgeable"]
BANNED_ALLOWED_IN = {"LIMITS.md", "CONTRIBUTING.md"}
FORBIDDEN = [r"/Users/", r"/home/\w", r"C:\\Users",
             r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"BEGIN [A-Z ]*PRIVATE KEY", r"AKIA[0-9A-Z]{16}",
             r"gh[pousr]_[A-Za-z0-9]{30,}", r"@[a-z0-9-]+\.(com|co|io|net|org)\b"]
# The project's own repository URL, in plain text. Private-name checks run outside the repository before publication.
REPO_URL = "https://github.com/Rocuts/agent-custody"


def text_files():
    return list(_text_files())


def _text_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            p = os.path.join(base, fn)
            if os.path.abspath(p) == THIS:
                continue
            try:
                with open(p, encoding="utf-8") as f:
                    yield os.path.relpath(p, ROOT), f.read()
            except UnicodeDecodeError:
                continue  # binary (the synthetic .ots files)


class RepoHygiene(unittest.TestCase):
    def test_no_real_paths_ips_names_or_secrets(self):
        for rel, text in text_files():
            for pat in FORBIDDEN:
                m = re.search(pat, text, re.IGNORECASE)
                self.assertIsNone(m, "%s matches %r: %r" % (rel, pat, m.group(0) if m else ""))

    def test_repository_url_is_the_published_one(self):
        for rel, text in text_files():
            for m in re.finditer(r"https://github\.com/([A-Za-z0-9-]+)/agent-custody(?![\w.-])", text):
                self.assertEqual(m.group(0), REPO_URL, rel)

    def test_banned_claim_terms(self):
        for rel, text in text_files():
            if os.path.basename(rel) in BANNED_ALLOWED_IN:
                continue
            for pat in BANNED:
                m = re.search(pat, text, re.IGNORECASE)
                self.assertIsNone(m, "%s uses banned term %r" % (rel, m.group(0) if m else ""))

    def test_required_files_exist(self):
        for rel in ("README.md", "SPEC.md", "LIMITS.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE", "LICENSE-SPEC", "NOTICE",
                    ".github/workflows/ci.yml", "skills/agent-custody/SKILL.md", "verifier/agent_custody_verify.py",
                    "docs/es/RESUMEN.md", "CHANGELOG.md", "CODE_OF_CONDUCT.md", "AUTHORS", "requirements-dev.txt"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)
        with open(os.path.join(ROOT, "LICENSE"), encoding="utf-8") as f:
            self.assertIn("Apache License", f.read(200))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class PublicationReadiness(unittest.TestCase):
    """Licensing notices, community files, CI pinning and docs that quote real output."""

    def test_rfc8032_derived_code_carries_the_ietf_bsd_notice(self):
        for rel in ("verifier/agent_custody_verify.py", "writer/agent_custody_write.py"):
            src = read(rel)
            for needle in ("RFC 8032, Section 6", "IETF Trust", "Revised BSD License", "trustee.ietf.org/license-info"):
                self.assertIn(needle, src, rel)
        notice = read("NOTICE")
        self.assertNotIn("no third-party code is included", notice)
        self.assertIn("RFC 8032, Section 6", notice)
        self.assertIn("Copyright (c) 2017 IETF Trust", read("LICENSES/BSD-3-Clause-IETF.txt"))

    def test_community_files(self):
        self.assertIn("## [0.1.0]", read("CHANGELOG.md"))
        coc = read("CODE_OF_CONDUCT.md")
        self.assertIn("Contributor Covenant", coc)
        self.assertIn("version 2.1", coc)
        self.assertNotIn("[INSERT", coc)
        for rel in (".github/ISSUE_TEMPLATE/bug_report.md", ".github/ISSUE_TEMPLATE/spec_change.md", ".github/PULL_REQUEST_TEMPLATE.md"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)
        self.assertIn("developercertificate.org", read("CONTRIBUTING.md"))
        self.assertIn("Copyright holder: Orbexs (https://orbexs.co).", read("AUTHORS"))
        for rel in ("NOTICE", "LICENSE-SPEC", "verifier/agent_custody_verify.py", "writer/agent_custody_write.py"):
            self.assertIn("Copyright 2026 Orbexs and the agent-custody contributors", read(rel), rel)
        self.assertIn("Copyright [yyyy] [name of copyright owner]", read("LICENSE"))  # appendix kept verbatim; holder in NOTICE
        self.assertEqual([rel for rel, text in text_files() if "agent-custody authors\"" in text or "The agent-custody authors" in text], [])

    def test_owner_decisions_are_resolved(self):
        sec = read("SECURITY.md")
        self.assertNotIn("MAINTAINER", sec)
        self.assertIn("section 14", sec)
        self.assertIn("CHANGELOG.md", sec)
        self.assertIn("/agent-custody/security/advisories/new", sec)
        self.assertIn("Report a vulnerability", sec)
        self.assertIn("/agent-custody/security/advisories/new", read(".github/ISSUE_TEMPLATE/config.yml"))
        marker = re.compile(r"(?<![A-Za-z_])PENDING(?![A-Za-z_])")
        self.assertEqual([rel for rel, text in text_files() if marker.search(text)], [])

    def test_ci_is_pinned(self):
        ci = read(".github/workflows/ci.yml")
        uses = re.findall(r"uses:\s*(\S+)", ci)
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"@[0-9a-f]{40}$", u)
        self.assertIn("--require-hashes", ci)
        self.assertIn("git status --porcelain", ci)
        reqs = read("requirements-dev.txt")
        for line in reqs.splitlines():
            if re.match(r"[a-z]", line):
                self.assertRegex(line, r"^[a-z0-9_.-]+==[0-9][^ ;]*", line)
        self.assertIn("--hash=sha256:", reqs)

    def test_readme_quotes_real_output(self):
        readme = read("README.md")
        ex = "examples/01-support-wifi-password/"
        p = subprocess.run([sys.executable, "-I", VERIFIER, ROOT + "/" + ex + "log.jsonl", "--checkpoint", ROOT + "/" + ex + "checkpoint.note",
                            "--vkey", read(ex + "vkey.txt").strip(), "--approver-key", read(ex + "approver-key.txt").strip()],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        result = [l for l in p.stdout.splitlines() if l.startswith("RESULT:")][0]
        self.assertIn(result, readme)
        self.assertNotIn("who approved it", readme)
        self.assertIn("which key holder approved it", readme)
        self.assertIn("## How this was built", readme)
        self.assertNotRegex(readme, r"(?m)^python (verifier|writer)/")
        n = len([d for d in os.listdir(os.path.join(ROOT, "vectors")) if os.path.isdir(os.path.join(ROOT, "vectors", d))])
        self.assertIn("[%d vectors]" % n, readme)

    def test_skill_shows_approval_and_execution_and_keeps_seeds_off_the_command_line(self):
        skill = read("skills/agent-custody/SKILL.md")
        self.assertIn('"type":"human_approval"', skill)
        self.assertIn('"phase":"executed"', skill)
        self.assertNotRegex(skill, r"--seed\s")
        self.assertIn("--seed-file", skill)

    def test_ct_test_data_cites_its_source(self):
        self.assertRegex(read("tests/test_primitives.py"), r"# Source: RFC 6962 reference test tree")


class Reproducible(unittest.TestCase):
    def test_examples_regenerate_identically(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_examples.py"), tmp], check=True, capture_output=True)
            for name in sorted(os.listdir(tmp)):
                m = filecmp.dircmp(os.path.join(ROOT, "examples", name), os.path.join(tmp, name))
                self.assertEqual((m.left_only, m.right_only, m.diff_files), ([], [], []), name)


class WriterRoundTrip(unittest.TestCase):
    """The workflow in skills/agent-custody/SKILL.md, end to end, through the CLIs."""

    def run_py(self, *args, ok=True):
        p = subprocess.run([sys.executable, "-I"] + list(args), capture_output=True, text=True)
        if ok:
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p

    def test_skill_workflow(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            log, cp = os.path.join(tmp, "l.jsonl"), os.path.join(tmp, "l.note")
            seed = os.path.join(tmp, "demo.seed")
            kg = self.run_py(WRITER, "keygen", "--seed-file", seed).stdout.splitlines()
            vkey = kg[2].split(":", 1)[1].strip()
            self.run_py(WRITER, "new", log, "--agent-id", "agent-test")
            req = {"type": "action", "action_id": "a1", "phase": "requested", "actor": {"kind": "agent", "id": "agent-test"},
                   "tool": "t", "summary": "s", "risk": "high", "requires_approval": True}
            out = self.run_py(WRITER, "append", log, "--event", json.dumps(req)).stdout
            h = re.search(r"entry_hash=([0-9a-f]{64})", out).group(1)
            # executing before approval is refused by the verifier, not the writer: append it and expect fail
            ex = {"type": "action", "action_id": "a1", "phase": "executed", "actor": req["actor"], "tool": "t", "summary": "s",
                  "risk": "high", "request_entry_hash": h}
            self.run_py(WRITER, "append", log, "--event", json.dumps(ex))
            with open(cp, "w", encoding="utf-8") as f:
                f.write(self.run_py(WRITER, "checkpoint", log, "--seed-file", seed, "--name", "demo-key").stdout)
            p = self.run_py(VERIFIER, log, "--checkpoint", cp, "--vkey", vkey, ok=False)
            self.assertEqual(p.returncode, 1)
            self.assertIn("approval_gate", p.stdout)
            # the writer refuses a structurally invalid event
            bad = self.run_py(WRITER, "append", log, "--event", '{"type":"nonsense"}', ok=False)
            self.assertNotEqual(bad.returncode, 0)
            # a proof for entry 1 verifies against the checkpoint
            proof = os.path.join(tmp, "p.json")
            with open(proof, "w", encoding="utf-8") as f:
                f.write(self.run_py(WRITER, "proof", log, "--index", "1").stdout)
            p = self.run_py(VERIFIER, "--proof", proof, "--checkpoint", cp, "--vkey", vkey, "--json")
            self.assertEqual(json.loads(p.stdout)["layers"]["inclusion_proof"]["state"], "ok")


if __name__ == "__main__":
    unittest.main()
