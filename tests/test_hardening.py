# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the pre-publication review findings (verifier and writer hardening).

Each test builds a small synthetic log that the 0.1 pre-release verifier mishandled and states the
behaviour the specification now requires. Works with pytest and `python -m unittest discover -s tests`.
"""
import copy
import json
import os
import stat
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

VERIFIER = os.path.join(ROOT, "verifier", "agent_custody_verify.py")
WRITER = os.path.join(ROOT, "writer", "agent_custody_write.py")
PIN = "approver-1=" + synth.APPROVER_PUB.hex()
IDENTITY_POINT = bytes([1]) + bytes(31)  # y = 1: the neutral element, a small-order "public key"


def rechain(es, start=1):
    for i in range(start, len(es)):
        es[i]["prev_hash"] = es[i - 1]["entry_hash"]
        es[i]["entry_hash"] = v.compute_entry_hash(es[i])


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

    def log(self, entries, name="log.jsonl"):
        return self.put(name, "".join(w.dump_entry(e) + "\n" for e in entries))

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", VERIFIER] + list(args), capture_output=True, text=True, timeout=120)

    def layers(self, rep):
        return {k: s for k, (s, _) in rep.layers.items()}


# ----------------------------------------------------------------- M1
class ApprovalSignatureCoverage(Tmp):
    def _expired_flow(self):
        b = synth.Builder("r1-expiry")
        req = b.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
        b.approve(req, expires_at="2026-03-01T09:00:10Z")
        b.t += 600
        b.execute(req)
        return b

    def test_expiry_is_signed(self):
        es = copy.deepcopy(self._expired_flow().entries)
        del es[2]["event"]["expires_at"]  # attacker strips the expiry, keeps the signature, re-chains
        rechain(es, 2)
        rep = v.verify(self.log(es), approver_keys=[PIN])
        self.assertEqual(rep.layers["approver_signatures"][0], "fail", rep.layers["approver_signatures"][1])

    def test_extended_expiry_is_detected(self):
        es = copy.deepcopy(self._expired_flow().entries)
        es[2]["event"]["expires_at"] = "2099-01-01T00:00:00Z"
        rechain(es, 2)
        rep = v.verify(self.log(es), approver_keys=[PIN])
        self.assertEqual(rep.layers["approver_signatures"][0], "fail")

    def test_method_is_signed(self):
        b = synth.approval_flow(label="r1-method")
        es = copy.deepcopy(b.entries)
        es[3]["event"]["approver"]["method"] = "hardware-token"
        rechain(es, 3)
        rep = v.verify(self.log(es), approver_keys=[PIN])
        self.assertEqual(rep.layers["approver_signatures"][0], "fail")

    def test_signed_statement_is_versioned_v2(self):
        ev = synth.approval_flow(label="r1-msg").entries[3]["event"]
        msg = v.approval_message("00" * 32, ev)
        self.assertTrue(msg.startswith(b"agent-custody/approval/v2\x00"))
        stmt = json.loads(msg.split(b"\x00", 1)[1])
        self.assertEqual(stmt["approver_method"], "demo-console")
        self.assertIn("expires_at", stmt)
        self.assertIsNone(stmt["expires_at"])


# ----------------------------------------------------------------- M2 + B10
class ApprovalUse(Tmp):
    def _req(self, label):
        b = synth.Builder(label)
        return b, b.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)

    def test_replayed_approval_after_rejection_fails(self):
        b, req = self._req("r1-replay")
        ap = b.approve(req, aid="ap-1")
        b.approve(req, outcome="rejected", aid="ap-2")
        b.add(copy.deepcopy(ap["event"]), validate=False)  # literal copy of the earlier signed approval
        b.execute(req)
        rep = v.verify(self.log(b.entries), approver_keys=[PIN])
        self.assertEqual(rep.overall, "fail")
        self.assertEqual(rep.layers["events"][0], "fail", rep.layers["events"][1])

    def test_one_approval_authorises_one_execution(self):
        b, req = self._req("r1-reuse")
        b.approve(req)
        b.execute(req)
        b.execute(req)
        rep = v.verify(self.log(b.entries), approver_keys=[PIN])
        self.assertEqual(rep.layers["approval_gate"][0], "fail", rep.layers["approval_gate"][1])

    def test_fresh_approval_per_execution_passes(self):
        b, req = self._req("r1-two")
        b.approve(req, aid="ap-1")
        b.execute(req)
        b.approve(req, aid="ap-2")
        b.execute(req)
        rep = v.verify(self.log(b.entries), approver_keys=[PIN])
        self.assertEqual(rep.layers["approval_gate"][0], "ok", rep.layers["approval_gate"][1])
        self.assertEqual(rep.overall, "ok_partial")

    def test_failed_phase_is_gated(self):
        b, req = self._req("r1-failed")
        b.execute(req, phase="failed")
        rep = v.verify(self.log(b.entries))
        self.assertEqual(rep.layers["approval_gate"][0], "fail")

    def test_failed_attempt_consumes_the_approval(self):
        b, req = self._req("r1-failed-retry")
        b.approve(req)
        b.execute(req, phase="failed")
        b.execute(req)
        rep = v.verify(self.log(b.entries), approver_keys=[PIN])
        self.assertEqual(rep.layers["approval_gate"][0], "fail")

    def test_writer_refuses_duplicate_approval_id(self):
        p = os.path.join(self.dir, "w.jsonl")
        log = w.Log.create(p, "agent-test", chain_id="11" * 32, ts="2026-03-01T09:00:00Z")
        req = log.append({"type": "action", "action_id": "a", "phase": "requested", "actor": {"kind": "agent", "id": "x"},
                          "tool": "t", "summary": "s", "risk": "high", "requires_approval": True}, ts="2026-03-01T09:00:01Z")
        ap = {"type": "human_approval", "approval_id": "ap-1", "subject_entry_hash": req["entry_hash"], "outcome": "approved",
              "approver": {"id": "approver-1", "method": "demo"}, "presented_digest": "ab" * 32}
        log.append(dict(ap), ts="2026-03-01T09:00:02Z")
        with self.assertRaises(v.FormatError):
            log.append(dict(ap), ts="2026-03-01T09:00:03Z")


# ----------------------------------------------------------------- M3
class InclusionNeedsTrustedCheckpoint(Tmp):
    def setUp(self):
        super().setUp()
        b = synth.approval_flow(label="r1-proof")
        self.b = b
        self.proof = self.put("proof.json", json.dumps(b.proof(2)))
        self.entry = self.put("entry.json", json.dumps(b.entries[2]))
        self.cp = self.put("cp.note", b.checkpoint())
        self.foreign = self.put("foreign.note", b.checkpoint(seed_=synth.FOREIGN_SEED, pub=synth.FOREIGN_PUB, name=synth.FOREIGN_KEY_NAME))

    def test_without_vkey_is_not_checked(self):
        rep = v.verify(proof_path=self.proof, entry_path=self.entry, checkpoints=[self.foreign])
        self.assertEqual(rep.layers["inclusion_proof"][0], "not_checked", rep.layers["inclusion_proof"][1])
        rep = v.verify(self.log(self.b.entries), proof_path=self.proof, checkpoints=[self.cp])
        self.assertEqual(rep.layers["inclusion_proof"][0], "not_checked")

    def test_require_fails_without_trusted_checkpoint(self):
        p = self.cli("--proof", self.proof, "--entry", self.entry, "--checkpoint", self.foreign, "--require", "inclusion_proof")
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)

    def test_untrusted_signer_is_not_ok(self):
        rep = v.verify(proof_path=self.proof, entry_path=self.entry, checkpoints=[self.foreign], vkeys=[synth.LOG_VKEY])
        self.assertNotEqual(rep.layers["inclusion_proof"][0], "ok")

    def test_trusted_checkpoint_is_ok(self):
        rep = v.verify(proof_path=self.proof, entry_path=self.entry, checkpoints=[self.cp], vkeys=[synth.LOG_VKEY])
        self.assertEqual(rep.layers["inclusion_proof"][0], "ok")

    def test_proof_version_must_be_integer_one(self):  # B8
        pr = self.b.proof(2)
        pr["v"] = True
        p = self.put("proof-true.json", json.dumps(pr))
        rep = v.verify(proof_path=p, entry_path=self.entry, checkpoints=[self.cp], vkeys=[synth.LOG_VKEY])
        self.assertEqual(rep.layers["inclusion_proof"][0], "fail")


# ----------------------------------------------------------------- strict formats (B1, B2, B3, B6)
class StrictFormats(Tmp):
    def setUp(self):
        super().setUp()
        self.b = synth.approval_flow(label="r1-format")

    def test_trailing_newline_in_hex_field_is_rejected(self):
        es = copy.deepcopy(self.b.entries)
        for e in es:
            e["chain_id"] += "\n"
        es[0]["event"]["chain_id"] = es[0]["chain_id"]
        for e in es:
            e["entry_hash"] = v.compute_entry_hash(e)
        rechain(es, 1)
        rep = v.verify(self.log(es))
        self.assertEqual(rep.layers["format"][0], "fail")

    def test_trailing_newline_in_expires_at_is_rejected(self):
        self.assertEqual(self._bad_expiry("2026-03-01T10:00:00Z\n"), "fail")

    def _bad_expiry(self, value):
        b = synth.Builder("r1-exp-%s" % value.encode().hex())
        req = b.request("a", "t", "s", risk="high", requires_approval=True)
        b.add({"type": "human_approval", "approval_id": "ap", "subject_entry_hash": req["entry_hash"], "outcome": "approved",
               "approver": {"id": "approver-1", "method": "demo"}, "presented_digest": "ab" * 32, "expires_at": value}, validate=False)
        return v.verify(self.log(b.entries)).layers["events"][0]

    def test_trailing_newline_in_signature_hex_is_rejected(self):
        es = copy.deepcopy(self.b.entries)
        es[3]["event"]["approver_signature"]["signature"] += "\n"
        rechain(es, 3)
        self.assertEqual(v.verify(self.log(es)).layers["events"][0], "fail")

    def test_expires_at_must_be_a_real_date(self):
        self.assertEqual(self._bad_expiry("9999-99-99T99:99:99Z"), "fail")
        self.assertEqual(self._bad_expiry("2026-02-30T10:00:00Z"), "fail")

    def test_huge_seq_is_a_format_failure_not_a_usage_error(self):
        es = copy.deepcopy(self.b.entries)
        text = "".join(w.dump_entry(e) + "\n" for e in es).replace('"seq":4,', '"seq":9007199254740993,')
        p = self.put("big.jsonl", text)
        self.assertEqual(v.verify(p).layers["format"][0], "fail")
        r = self.cli(p, "--json")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(json.loads(r.stdout)["layers"]["format"]["state"], "fail")

    def test_huge_checkpoint_size_is_a_layer_failure(self):
        body = v.format_checkpoint(self.b.chain_id, 1, bytes(32)).replace(b"\n1\n", b"\n" + b"9" * 5000 + b"\n")
        cp = self.put("big.note", body + b"\n" + synth.sign_line(body, synth.LOG_SEED, synth.LOG_PUB, synth.LOG_KEY_NAME))
        r = self.cli(self.log(self.b.entries), "--checkpoint", cp, "--json")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(json.loads(r.stdout)["layers"]["checkpoint_root"]["state"], "fail")

    def test_crlf_is_rejected(self):
        p = self.put("crlf.jsonl", "".join(w.dump_entry(e) + "\r\n" for e in self.b.entries))
        self.assertEqual(v.verify(p).layers["format"][0], "fail")

    def test_missing_final_newline_is_rejected(self):
        p = self.put("nonl.jsonl", "\n".join(w.dump_entry(e) for e in self.b.entries))
        self.assertEqual(v.verify(p).layers["format"][0], "fail")


# ----------------------------------------------------------------- B4 / security M2, size limit
class HostileInput(Tmp):
    def test_deep_nesting_fails_cleanly(self):
        b = synth.Builder("r1-deep")
        nested = {}
        cur = nested
        for _ in range(600):
            cur["x"] = {}
            cur = cur["x"]
        es = copy.deepcopy(b.entries)
        p = self.log(es)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps({"v": 1, "chain_id": b.chain_id, "seq": 1, "ts": "2026-03-01T09:00:07Z",
                                "prev_hash": es[0]["entry_hash"], "event": {"type": "x-deep", "n": nested},
                                "entry_hash": "00" * 32}) + "\n")
        rep = v.verify(p)  # must not raise RecursionError
        self.assertEqual(rep.layers["format"][0], "fail")
        r = self.cli(p, "--json")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(json.loads(r.stdout)["layers"]["format"]["state"], "fail")

    def test_depth_limit_is_documented_value(self):
        ok = {"type": "x-d"}
        cur = ok
        for _ in range(v.MAX_DEPTH - 3):  # entry (1) > event (2) > ... stays within the limit
            cur["x"] = {}
            cur = cur["x"]
        v.canon({"v": 1, "event": ok})
        cur["x"] = {"y": {}}
        with self.assertRaises(v.FormatError):
            v.canon({"v": 1, "event": ok})

    def test_input_size_limit(self):
        p = self.log(synth.approval_flow(label="r1-size").entries)
        self.assertEqual(v.verify(p, max_bytes=100).layers["format"][0], "fail")
        self.assertEqual(self.cli(p, "--max-bytes", "100").returncode, 1)
        self.assertEqual(v.verify(p).layers["format"][0], "ok")


# ----------------------------------------------------------------- B7 small-order keys
class SmallOrderKeys(Tmp):
    def test_identity_key_never_verifies(self):
        sig = v._compress(v._G) + bytes(32)  # R = B, s = 0 ... any R works for the identity key
        self.assertFalse(v.ed25519_verify(IDENTITY_POINT, b"anything", v._compress(v._IDENT) + bytes(32)))
        self.assertFalse(v.ed25519_verify(IDENTITY_POINT, b"anything", sig))

    def test_small_order_approver_key_fails_layer(self):
        b = synth.Builder("r1-small")
        req = b.request("a", "t", "s", risk="high", requires_approval=True)
        ap = b.approve(req, sign=False)
        es = copy.deepcopy(b.entries)
        es[2]["event"]["approver_signature"] = {"public_key": IDENTITY_POINT.hex(), "signature": (v._compress(v._IDENT) + bytes(32)).hex()}
        rechain(es, 2)
        self.assertIsNotNone(ap)
        rep = v.verify(self.log(es))
        self.assertEqual(rep.layers["approver_signatures"][0], "fail", rep.layers["approver_signatures"][1])

    def test_small_order_vkey_and_pin_rejected(self):
        with self.assertRaises(v.FormatError):
            v.parse_vkey(v.make_vkey("evil", IDENTITY_POINT))
        with self.assertRaises(ValueError):
            v.verify(self.log(synth.approval_flow(label="r1-pin").entries), approver_keys=["approver-1=" + IDENTITY_POINT.hex()])


# ----------------------------------------------------------------- B11 provider comparison
class ProviderComparison(Tmp):
    def _cv(self, author, reviewer, claim):
        b = synth.Builder("r1-cv-%s-%s" % (author.encode().hex(), reviewer.encode().hex()))
        req = b.request("a", "t", "s")
        ex = b.execute(req)
        b.add({"type": "cross_verification", "verification_id": "cv", "subject_entry_hash": ex["entry_hash"],
               "author": {"provider": author, "model": "m"}, "cross_provider": claim,
               "reviewers": [{"provider": reviewer, "model": "m2", "verdict": "agree"}]}, validate=False)
        return v.verify(self.log(b.entries)).layers["events"][0]

    def test_nfc_equivalent_names_are_the_same_provider(self):
        self.assertEqual(self._cv("café", "café", False), "ok")

    def test_only_ascii_letters_are_case_folded(self):
        self.assertEqual(self._cv("Provider-A", "provider-a", False), "ok")
        self.assertEqual(self._cv("STRASSE", "straße", True), "ok")
        self.assertEqual(self._cv("İx", "ix", True), "ok")
        self.assertEqual(self._cv("Ä", "ä", True), "ok")


# ----------------------------------------------------------------- B9 writer
class WriterGuards(Tmp):
    def _log(self):
        p = os.path.join(self.dir, "w.jsonl")
        log = w.Log.create(p, "agent-test", chain_id="22" * 32, ts="2026-03-01T09:00:00Z")
        log.append({"type": "x-note"}, ts="2026-03-01T09:00:01Z")
        return log

    def test_checkpoint_size_must_be_within_log(self):
        log = self._log()
        signer = w.seed_signer(synth.LOG_SEED)
        for bad in (0, 3, -1):
            with self.assertRaises(ValueError):
                log.checkpoint("k", signer, synth.LOG_PUB, size=bad)
        self.assertIn(b"\n2\n", log.checkpoint("k", signer, synth.LOG_PUB, size=2))

    def test_proof_bounds(self):
        log = self._log()
        for idx, size in ((0, 0), (0, 5), (2, 2), (-1, 2)):
            with self.assertRaises(ValueError):
                log.proof(idx, size)

    def test_extra_cannot_override_genesis_fields(self):
        for key in ("type", "chain_id", "spec", "agent"):
            with self.assertRaises(ValueError):
                w.Log.create(os.path.join(self.dir, "x-%s.jsonl" % key), "a", extra={key: "x"})


# ----------------------------------------------------------------- writer seed handling (security B3)
class WriterSeedHandling(Tmp):
    def run_w(self, *args, env=None):
        e = dict(os.environ)
        e.pop("AGENT_CUSTODY_DEMO_SEED", None)
        e.update(env or {})
        return subprocess.run([sys.executable, "-I", WRITER] + list(args), capture_output=True, text=True, env=e)

    def test_seed_is_not_accepted_on_the_command_line(self):
        log = os.path.join(self.dir, "s.jsonl")
        self.assertEqual(self.run_w("new", log, "--agent-id", "a").returncode, 0)
        p = self.run_w("checkpoint", log, "--seed", "00" * 32, "--name", "k")
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn("— k ", p.stdout)

    def test_keygen_writes_private_seed_file_and_checkpoint_reads_it(self):
        seed = os.path.join(self.dir, "demo.seed")
        kg = self.run_w("keygen", "--seed-file", seed)
        self.assertEqual(kg.returncode, 0, kg.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(seed).st_mode), 0o600)
        with open(seed, encoding="utf-8") as f:
            self.assertNotIn(f.read().strip(), kg.stdout)
        self.assertNotEqual(self.run_w("keygen", "--seed-file", seed).returncode, 0)  # never overwrites
        log = os.path.join(self.dir, "l.jsonl")
        self.assertEqual(self.run_w("new", log, "--agent-id", "a").returncode, 0)
        cp = self.run_w("checkpoint", log, "--seed-file", seed, "--name", "demo-key")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        with open(seed, encoding="utf-8") as f:
            env = self.run_w("checkpoint", log, "--name", "demo-key", env={"AGENT_CUSTODY_DEMO_SEED": f.read().strip()})
        self.assertEqual(env.returncode, 0, env.stderr)
        self.assertEqual(env.stdout, cp.stdout)
        self.assertNotEqual(self.run_w("checkpoint", log, "--name", "demo-key").returncode, 0)


class PythonVersionGuard(unittest.TestCase):
    def test_verifier_refuses_old_python(self):
        with open(VERIFIER, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("sys.version_info < (3, 10)", src)


if __name__ == "__main__":
    unittest.main()
