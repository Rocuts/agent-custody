# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the second pre-publication review (deny rule, disclosed entries, limits, writer input).

Works with pytest and `python -m unittest discover -s tests`.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for sub in ("verifier", "writer", "tools"):
    sys.path.insert(0, os.path.join(ROOT, sub))
import agent_custody_verify as v  # noqa: E402
import agent_custody_write as w  # noqa: E402
import synth  # noqa: E402

PIN = "approver-1=" + synth.APPROVER_PUB.hex()


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def put(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
        return p

    def gate(self, b):
        rep = v.verify(self.put("log.jsonl", b.log_text()), approver_keys=[PIN])
        return rep.layers["approval_gate"]


# ------------------------------------------------- deny rule (SPEC 6.6)
class DenyRule(Tmp):
    def test_allow_after_deny_does_not_lift_it(self):
        b = synth.Builder("deny-allow")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high")
        b.decide(req, "deny", did="d1")
        b.decide(req, "allow", did="d2")
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "fail")

    def test_allow_after_deny_does_not_lift_it_when_gated(self):
        b = synth.Builder("approved-deny-allow")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=True)
        b.approve(req, aid="ap-1")
        b.decide(req, "deny", did="d1")
        b.decide(req, "allow", did="d2")
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "fail")

    def test_latest_human_word_after_deny_must_be_approved(self):
        b = synth.Builder("deny-approved-rejected")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high")
        b.decide(req, "deny", did="d1")
        b.approve(req, aid="ap-1")
        b.approve(req, outcome="rejected", aid="ap-2")
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "fail")

    def test_human_approval_after_deny_lifts_it(self):
        b = synth.Builder("deny-allow-approved")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high")
        b.decide(req, "deny", did="d1")
        b.decide(req, "allow", did="d2")
        b.approve(req, aid="ap-1")
        b.execute(req)
        st, msg = self.gate(b)
        self.assertEqual(st, "ok", msg)  # the deny rule was evaluated: not 'not_checked'

    def test_approval_before_deny_does_not_lift_it(self):
        b = synth.Builder("approved-then-deny")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high")
        b.approve(req, aid="ap-1")
        b.decide(req, "deny", did="d1")
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "fail")

    def test_gated_relift_needs_new_approval(self):
        b = synth.Builder("approved-deny-approved")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=True)
        b.approve(req, aid="ap-1")
        b.decide(req, "deny", did="d1")
        b.approve(req, aid="ap-2")
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "ok")

    def test_expired_lifting_approval_fails(self):
        b = synth.Builder("deny-approved-expired")
        req = b.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high")
        b.decide(req, "deny", did="d1")
        b.approve(req, aid="ap-1", expires_at="2026-03-01T09:00:20Z")
        b.t += 600
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "fail")

    def test_ungated_without_deny_stays_not_checked(self):
        b = synth.Builder("plain-low-risk")
        req = b.request("act-1", "fs.list", "List a synthetic directory")
        b.execute(req)
        self.assertEqual(self.gate(b)[0], "not_checked")


# ------------------------------------------ disclosed entry (--entry)
class DisclosedEntry(Tmp):
    def _case(self, mutate):
        b = synth.approval_flow()
        ent = copy.deepcopy(b.entries[3])
        mutate(ent)
        args = dict(proof_path=self.put("proof.json", json.dumps(b.proof(3))),
                    entry_path=self.put("entry.json", json.dumps(ent)),
                    checkpoints=[self.put("cp.note", b.checkpoint())], vkeys=[synth.LOG_VKEY])
        return v.verify(**args).layers["inclusion_proof"]

    def test_clean_entry_is_ok(self):
        self.assertEqual(self._case(lambda e: None)[0], "ok")

    def test_extra_member_is_rejected(self):
        st, msg = self._case(lambda e: e.__setitem__("human_approved_by", "CEO (verified)"))
        self.assertEqual(st, "fail", msg)

    def test_bool_seq_is_rejected(self):
        self.assertEqual(self._case(lambda e: e.__setitem__("seq", True))[0], "fail")

    def test_bad_ts_is_rejected(self):
        self.assertEqual(self._case(lambda e: e.__setitem__("ts", "yesterday"))[0], "fail")


# ------------------------------------------------ checkpoint signature lines
class SignatureLineCap(Tmp):
    def test_cap_is_documented(self):
        with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as f:
            self.assertIn("at most **%d** signature lines" % v.MAX_SIG_LINES, f.read())

    def test_too_many_signature_lines_rejected(self):
        b = synth.approval_flow()
        cp = b.checkpoint()
        body, sigline = cp.split(b"\n\n")
        note = body + b"\n\n" + sigline * (v.MAX_SIG_LINES + 1)
        with self.assertRaises(v.FormatError):
            v.parse_checkpoint(note)
        v.parse_checkpoint(body + b"\n\n" + sigline * v.MAX_SIG_LINES)  # the cap itself is accepted


# ------------------------------------------------------------ writer input
class WriterInput(Tmp):
    def _log(self):
        return w.Log.create(os.path.join(self.dir, "l.jsonl"), "agent-x", chain_id="ab" * 32, ts="2026-03-01T09:00:00Z")

    def test_bad_ts_refused(self):
        log = self._log()
        ev = {"type": "action", "action_id": "a", "phase": "requested", "actor": {"kind": "agent", "id": "x"},
              "tool": "t", "summary": "s", "risk": "low", "requires_approval": False}
        for bad in ("yesterday", "2026-02-30T00:00:00Z", "2026-03-01T09:00:00Z\n"):
            with self.assertRaises(ValueError):
                log.append(ev, ts=bad)
        self.assertEqual(len(v.load_log(log.path)), 1)

    def test_bad_create_args_refused(self):
        with self.assertRaises(ValueError):
            w.Log.create(os.path.join(self.dir, "a.jsonl"), "agent-x", chain_id="XYZ")
        with self.assertRaises(ValueError):
            w.Log.create(os.path.join(self.dir, "b.jsonl"), "agent-x", ts="2026-13-01T00:00:00Z")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "a.jsonl")))

    def test_bad_checkpoint_name_refused(self):
        log = self._log()
        seed = bytes(32)
        for bad in ("", "has space", "has+plus", "line\nbreak"):
            with self.assertRaises(ValueError):
                log.checkpoint(bad, w.seed_signer(seed), w.ed25519_public(seed))

    def test_open_refuses_tampered_log(self):
        log = self._log()
        with open(log.path, encoding="utf-8") as f:
            text = f.read()
        with open(log.path, "w", encoding="utf-8") as f:
            f.write(text.replace("agent-x", "agent-y"))
        with self.assertRaises(ValueError):
            w.Log.open(log.path)

    def test_cli_bad_ts_exit_2(self):
        p = os.path.join(self.dir, "c.jsonl")
        wr = os.path.join(ROOT, "writer", "agent_custody_write.py")
        subprocess.run([sys.executable, "-I", wr, "new", p, "--agent-id", "a"], check=True, capture_output=True)
        ev = '{"type":"action","action_id":"a","phase":"requested","actor":{"kind":"agent","id":"x"},"tool":"t","summary":"s","risk":"low","requires_approval":false}'
        r = subprocess.run([sys.executable, "-I", wr, "append", p, "--event", ev, "--ts", "yesterday"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)


# ------------------------------------------------------------ documentation
class Docs(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as f:
            return f.read()

    def test_string_limit_is_exhaustive(self):
        spec = self.read("SPEC.md")
        self.assertNotIn("and so on", spec)
        for member in ("agent.runtime", "rationale"):
            self.assertIn("`%s`" % member, spec)

    def test_leap_second_rule(self):
        self.assertIn(":60", self.read("SPEC.md"))
        self.assertFalse(v._is_ts("2016-12-31T23:59:60Z"))

    def test_limits_mentions_execution_not_bound_to_request(self):
        self.assertIn("not bound to the approved request", self.read("LIMITS.md"))

    def test_limits_list_is_not_split_by_a_heading(self):
        import re
        text = self.read("LIMITS.md")
        section = text[text.index("## What it is not"):text.index("## What an approver signature covers")]
        self.assertEqual([int(m) for m in re.findall(r"^(\d+)\. ", section, re.M)], list(range(1, 9)))

    def test_license_is_lf_only(self):
        with open(os.path.join(ROOT, "LICENSE"), "rb") as f:
            self.assertNotIn(b"\r", f.read())

    def test_license_spec_covers_every_file(self):
        ls = self.read("LICENSE-SPEC")
        for name in ("CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "AUTHORS", "README.md"):
            self.assertIn(name, ls)
        self.assertIn("Any other file", ls)

    def test_writer_ietf_notice_is_literal(self):
        verifier, writer = self.read("verifier/agent_custody_verify.py"), self.read("writer/agent_custody_write.py")
        anchor = "Redistribution and use in source and binary forms"
        self.assertIn(anchor, verifier)
        self.assertIn(anchor, writer)

    def test_spanish_summary_has_ai_and_bsd_note(self):
        es = self.read("docs/es/RESUMEN.md")
        self.assertIn("BSD-3-Clause", es)
        self.assertIn("asistentes de IA", es)

    def test_changelog_release_date(self):
        self.assertIn("## [0.1.0] - 2026-10-18", self.read("CHANGELOG.md"))


if __name__ == "__main__":
    unittest.main()
