#!/usr/bin/env python3
# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Regenerate vectors/ deterministically:  python tools/make_vectors.py [OUT_DIR]

Every vector directory holds a case.json:
    {"description": ..., "args": {log, checkpoints, vkeys, approver_keys, ots, tsr, proof, entry},
     "expect": {"exit": 0|1, "layers": {layer: state, ...}}}
`expect.layers` lists only the layers the vector is about (valid vectors list all).
A test (tests/test_vectors.py) regenerates into a temp dir and compares bytes,
so committed vectors can never drift from this script.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from synth import (APPROVER2_PUB, APPROVER2_SEED, APPROVER_PUB, FOREIGN_KEY_NAME, FOREIGN_PUB,  # noqa: E402
                   FOREIGN_SEED, LOG_KEY_NAME, LOG_PUB, LOG_SEED, LOG_VKEY, Builder, approval_flow,
                   dumps_pretty, sign_line, v, w)

PIN = "approver-1=" + APPROVER_PUB.hex()
ALL_OK = {"format": "ok", "entry_hashes": "ok", "chain_links": "ok", "events": "ok",
          "approval_gate": "ok", "approver_signatures": "ok", "checkpoint_root": "ok",
          "checkpoint_signature": "ok", "inclusion_proof": "not_checked", "timestamp": "not_checked"}

OUT = None
INDEX = []


def emit(name, description, files, args, expect_exit, layers):
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    for fn, content in files.items():
        data = content.encode("utf-8") if isinstance(content, str) else content
        with open(os.path.join(d, fn), "wb") as f:
            f.write(data)
    case = {"description": description, "args": args, "expect": {"exit": expect_exit, "layers": layers}}
    with open(os.path.join(d, "case.json"), "w", encoding="utf-8") as f:
        f.write(dumps_pretty(case))
    INDEX.append((name, "MUST PASS" if expect_exit == 0 else "MUST FAIL", description))


def args(log=True, cp=True, vkey=True, pin=True, **more):
    a = {"log": "log.jsonl" if log else None, "checkpoints": ["checkpoint.note"] if cp else [],
         "vkeys": [LOG_VKEY] if vkey else [], "approver_keys": [PIN] if pin else [],
         "ots": None, "tsr": None, "proof": None, "entry": None}
    a.update(more)
    return a


def with_layers(**over):
    d = dict(ALL_OK)
    d.update(over)
    return d


def edit_entries(b, fn):
    """Deep-copy entries, let fn mutate them (hashes NOT recomputed)."""
    es = copy.deepcopy(b.entries)
    fn(es)
    return es


def rehash(e):
    e["entry_hash"] = v.compute_entry_hash(e)


def rechain(es, start=1):
    """Recompute prev_hash/entry_hash from `start` on (what a host-level attacker can do)."""
    for i in range(start, len(es)):
        es[i]["prev_hash"] = es[i - 1]["entry_hash"]
        rehash(es[i])


def build_all():
    # ===================================================== MUST PASS
    b = approval_flow()
    emit("pass-01-approval-flow-full", "Signed approval flow; checkpoint signed by the trusted key; approver key pinned. Every layer except timestamp/inclusion is ok.",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint()}, args(), 0, ALL_OK)

    m = Builder("minimal")
    r = m.request("act-1", "fs.read", "Read a synthetic config file", risk="low")
    m.execute(r)
    emit("pass-02-minimal-low-risk", "Smallest useful chain: open, request, executed. No approvals involved.",
         {"log.jsonl": m.log_text(), "checkpoint.note": m.checkpoint()}, args(pin=False), 0,
         with_layers(approval_gate="not_checked", approver_signatures="not_checked"))

    emit("pass-03-no-checkpoint", "Log alone. Passes, but checkpoint layers are not_checked: truncation or full rewrite would NOT be detected.",
         {"log.jsonl": b.log_text()}, args(cp=False, vkey=False), 0,
         with_layers(checkpoint_root="not_checked", checkpoint_signature="not_checked"))

    emit("pass-04-unsigned-tail", "Checkpoint covers the first 3 of 5 entries; the 2 trailing entries are unsigned and reported as such.",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint(size=3)}, args(), 0, ALL_OK)

    emit("pass-05-no-trusted-key", "Checkpoint supplied but no --vkey: root checked, signature not_checked (a key shipped with the log must not be trusted).",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint()}, args(vkey=False), 0,
         with_layers(checkpoint_signature="not_checked"))

    emit("pass-06-unpinned-approver", "Approval signatures verify under the embedded key but no approver key is pinned: identity binding is NOT established (not_checked).",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint()}, args(pin=False), 0,
         with_layers(approver_signatures="not_checked"))

    x = Builder("cross-verification")
    req = x.request("act-1", "code.generate", "Author a synthetic migration script", risk="low")
    ex = x.execute(req)
    x.add({"type": "cross_verification", "verification_id": "cv-1", "subject_entry_hash": ex["entry_hash"],
           "author": {"provider": "provider-a", "model": "model-a-1"}, "cross_provider": True,
           "reviewers": [{"provider": "provider-b", "model": "model-b-1", "verdict": "disagree",
                          "finding_count": 2, "findings_digest": w.digest_of(["finding-1", "finding-2"])},
                         {"provider": "provider-a", "model": "model-a-1-review", "verdict": "agree", "finding_count": 0}]})
    emit("pass-07-cross-verification", "A cross_verification event: author from provider-a, reviewers from provider-b (disagree) and provider-a (agree).",
         {"log.jsonl": x.log_text(), "checkpoint.note": x.checkpoint()}, args(pin=False), 0,
         with_layers(approval_gate="not_checked", approver_signatures="not_checked"))

    c = Builder("canon-unicode")
    c.add({"type": "x-canon-test", "text": "café ☃ \U0001f512", "k￿": 1, "k\U00010000": 2, "a": [True, None, -7, 9007199254740991]})
    emit("pass-08-unicode-canonical-form", "Non-ASCII strings and keys whose UTF-16 order differs from code-point order (RFC 8785 ordering).",
         {"log.jsonl": c.log_text(), "checkpoint.note": c.checkpoint()}, args(pin=False), 0,
         with_layers(approval_gate="not_checked", approver_signatures="not_checked"))

    # timestamp files (synthetic, structure only)
    cp = b.checkpoint()
    digest = v.sha256(cp[: cp.index(b"\n\n") + 1])
    uri = b"https://calendar.example.test"
    ots = v.OTS_MAGIC + b"\x01\x08" + digest + b"\x00" + v.OTS_PENDING_TAG + bytes([len(uri) + 1, len(uri)]) + uri
    emit("pass-09-ots-digest-binds", "Synthetic pending OpenTimestamps file whose digest equals SHA-256 of the checkpoint text. Binding is checked; Bitcoin attestation is NOT (unavailable).",
         {"log.jsonl": b.log_text(), "checkpoint.note": cp, "checkpoint.ots": ots}, args(ots="checkpoint.ots"), 0,
         with_layers(timestamp="unavailable"))

    # inclusion proof, proof-only mode (selective disclosure)
    idx = 3
    emit("pass-10-inclusion-proof-only", "Selective disclosure: only entry 3, its inclusion proof and the signed checkpoint. No other entry is revealed.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(b.proof(idx)), "entry.json": dumps_pretty(b.entries[idx])},
         args(log=False, pin=False, proof="proof.json", entry="entry.json"), 0,
         {"inclusion_proof": "ok", "checkpoint_signature": "ok", "format": "not_checked", "checkpoint_root": "not_checked"})

    emit("pass-11-inclusion-proof-with-log", "Inclusion proof checked alongside the full log.",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(b.proof(2))},
         args(proof="proof.json"), 0, with_layers(inclusion_proof="ok"))

    # documented limits: these PASS and that is the point
    forged = approval_flow(summary="Rotate the guest Wi-Fi passphrase on a synthetic access point (altered)", approver_seed=FOREIGN_SEED)
    emit("pass-12-limit-full-rewrite-no-checkpoint", "LIMIT: a host-level attacker rewrites and re-chains the whole log. With no external checkpoint nothing detects it. Passes with checkpoint layers not_checked.",
         {"log.jsonl": forged.log_text()}, args(cp=False, vkey=False, pin=False), 0,
         with_layers(checkpoint_root="not_checked", checkpoint_signature="not_checked", approver_signatures="not_checked"))

    tr = edit_entries(b, lambda es: es.__delitem__(slice(3, None)))
    emit("pass-13-limit-truncation-no-checkpoint", "LIMIT: dropping the last entries leaves a valid shorter chain. Without an external checkpoint this is undetectable.",
         {"log.jsonl": b.log_text(tr)}, args(cp=False, vkey=False, pin=False), 0,
         with_layers(checkpoint_root="not_checked", checkpoint_signature="not_checked", approval_gate="not_checked",
                     approver_signatures="not_checked"))

    ext = Builder("extension")
    ext.add({"type": "x-vendor-note", "anything": {"goes": ["here"]}})
    emit("pass-14-extension-event", "Event types prefixed 'x-' are opaque extensions: hashed and chained, not interpreted.",
         {"log.jsonl": ext.log_text(), "checkpoint.note": ext.checkpoint()}, args(pin=False), 0,
         with_layers(approval_gate="not_checked", approver_signatures="not_checked"))

    # ===================================================== MUST FAIL
    t = edit_entries(b, lambda es: es[1]["event"].__setitem__("summary", "Rotate the admin passphrase"))
    emit("fail-01-altered-entry", "One field of entry 1 changed, entry_hash left as is.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1, {"entry_hashes": "fail"})

    def alter_rehash(es):
        es[1]["event"]["summary"] = "Rotate the admin passphrase"
        rehash(es[1])
    t = edit_entries(b, alter_rehash)
    emit("fail-02-altered-entry-rehashed", "Entry 1 altered AND its own hash recomputed; the next entry's prev_hash exposes it, and the checkpoint root differs.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1,
         {"entry_hashes": "ok", "chain_links": "fail", "checkpoint_root": "fail"})

    forged = approval_flow(summary="Rotate the guest Wi-Fi passphrase on a synthetic access point (altered)", approver_seed=FOREIGN_SEED)
    emit("fail-03-full-rewrite-with-checkpoint", "The whole log is rewritten and re-chained consistently, but the earlier signed checkpoint no longer matches, and the approval is not signed by the pinned approver key.",
         {"log.jsonl": forged.log_text(), "checkpoint.note": b.checkpoint()}, args(), 1,
         {"entry_hashes": "ok", "chain_links": "ok", "events": "ok", "checkpoint_root": "fail", "approver_signatures": "fail"})

    t = edit_entries(b, lambda es: es.__setitem__(slice(2, 4), [es[3], es[2]]))
    emit("fail-04-reordered-entries", "Entries 2 and 3 swapped.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1, {"chain_links": "fail"})

    t = edit_entries(b, lambda es: es.__delitem__(2))
    emit("fail-05-deleted-middle-entry", "Entry 2 removed from the middle.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1, {"chain_links": "fail", "checkpoint_root": "fail"})

    t = edit_entries(b, lambda es: es.__delitem__(slice(3, None)))
    emit("fail-06-truncated-vs-checkpoint", "Log cut to 3 entries; the signed checkpoint covers 5, so the truncation is detected.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1,
         {"chain_links": "ok", "checkpoint_root": "fail"})

    body_sig = b.checkpoint()
    emit("fail-07-checkpoint-foreign-key", "Checkpoint signed by a different key with a different name; the trusted key has no signature on it.",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint(seed_=FOREIGN_SEED, pub=FOREIGN_PUB, name=FOREIGN_KEY_NAME)},
         args(), 1, {"checkpoint_root": "ok", "checkpoint_signature": "fail"})

    body = body_sig[: body_sig.index(b"\n\n") + 1]
    kid_line = v.SIG_PREFIX + "%s %s\n" % (LOG_KEY_NAME, __import__("base64").b64encode(v.key_id(LOG_KEY_NAME, LOG_PUB) + w.ed25519_sign_pure(FOREIGN_SEED, body)).decode())
    emit("fail-08-checkpoint-forged-keyid", "Attacker copies the trusted key name and key id but signs with its own key: the signature does not verify.",
         {"log.jsonl": b.log_text(), "checkpoint.note": body + b"\n" + kid_line.encode()}, args(), 1, {"checkpoint_signature": "fail"})

    lines = body.split(b"\n")
    flipped_root = __import__("base64").b64encode(bytes([v.merkle_root([v.leaf_hash(e["entry_hash"]) for e in b.entries])[0] ^ 1]) +
                                                   v.merkle_root([v.leaf_hash(e["entry_hash"]) for e in b.entries])[1:]).decode()
    flipped = (lines[0] + b"\n" + lines[1] + b"\n" + flipped_root.encode() + b"\n")
    sig_line = body_sig[body_sig.index(b"\n\n") + 2:]
    emit("fail-09-checkpoint-root-altered", "One bit of the checkpoint root flipped, original signature kept.",
         {"log.jsonl": b.log_text(), "checkpoint.note": flipped + b"\n" + sig_line}, args(), 1,
         {"checkpoint_root": "fail", "checkpoint_signature": "fail"})

    other = approval_flow(label="another-chain")
    emit("fail-10-checkpoint-from-other-chain", "A genuinely signed checkpoint of ANOTHER chain, presented for this log.",
         {"log.jsonl": b.log_text(), "checkpoint.note": other.checkpoint()}, args(), 1,
         {"checkpoint_root": "fail", "checkpoint_signature": "ok"})

    def transplant(es):
        es[4] = other.entries[4]
    t = edit_entries(b, transplant)
    emit("fail-11-transplanted-entry", "The last entry is replaced by a perfectly valid entry from a different chain.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1,
         {"entry_hashes": "ok", "chain_links": "fail", "checkpoint_root": "fail"})

    g = Builder("gate-missing")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.execute(req)
    emit("fail-12-executed-without-approval", "Self-consistent log that records an approval-required action executed with no human approval. All hashes are valid; the policy layer catches it.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(pin=False), 1,
         {"entry_hashes": "ok", "chain_links": "ok", "events": "ok", "approval_gate": "fail"})

    g = Builder("gate-late")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.execute(req)
    g.approve(req)
    emit("fail-13-approval-after-execution", "The approval is recorded AFTER the action ran.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"approval_gate": "fail"})

    g = Builder("gate-rejected")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.approve(req, outcome="rejected")
    g.execute(req)
    emit("fail-14-executed-after-rejection", "The human rejected the action, it ran anyway.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"approval_gate": "fail"})

    g = Builder("gate-deny")
    req = g.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=False)
    g.decide(req, "deny", basis="policy", rationale="outside allowed scope")
    g.execute(req)
    emit("fail-15-executed-after-deny", "A policy decision recorded 'deny'; the action was executed anyway.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(pin=False), 1, {"approval_gate": "fail"})

    g = Builder("gate-expired")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.approve(req, expires_at="2026-03-01T09:00:10Z")
    g.t += 600
    g.execute(req)
    emit("fail-16-approval-expired", "Executed after the approval's expires_at (compared on the host's own clock).",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"approval_gate": "fail"})

    bad = Builder("badsig")
    req = bad.request("act-1", "wifi.set_passphrase", "Rotate a synthetic passphrase", risk="medium", requires_approval=True)
    ev_entry = bad.approve(req)
    sig = ev_entry["event"]["approver_signature"]["signature"]
    ev_entry["event"]["approver_signature"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    rehash(ev_entry)
    bad.entries[-1] = ev_entry
    bad.execute(req)
    # rebuild chain linkage after editing the approval entry in place
    rechain(bad.entries)
    emit("fail-17-approver-signature-invalid", "The approver signature has a flipped nibble (hashes are re-chained so only the signature layer fails).",
         {"log.jsonl": bad.log_text(), "checkpoint.note": bad.checkpoint()}, args(), 1, {"entry_hashes": "ok", "chain_links": "ok", "approver_signatures": "fail"})

    p2 = approval_flow(approver_seed=APPROVER2_SEED)
    emit("fail-18-approver-key-not-pinned-key", "Signature is valid, but under a different key than the one pinned for 'approver-1'.",
         {"log.jsonl": p2.log_text(), "checkpoint.note": p2.checkpoint()}, args(), 1, {"approver_signatures": "fail"})

    rp = Builder("approval-flow")  # same label => same chain_id is NOT the point; replay uses another chain
    donor = approval_flow(label="donor-chain")
    victim = Builder("victim-chain")
    req = victim.request("act-1", "wifi.set_passphrase", "Rotate the guest Wi-Fi passphrase on a synthetic access point", risk="medium", requires_approval=True)
    stolen = copy.deepcopy(donor.entries[3]["event"])
    stolen["subject_entry_hash"] = req["entry_hash"]
    victim.add(stolen)
    victim.execute(req)
    emit("fail-19-approval-replayed-from-other-chain", "A signed approval lifted from another chain (subject re-pointed): the signature covers chain_id and subject, so it fails.",
         {"log.jsonl": victim.log_text(), "checkpoint.note": victim.checkpoint()}, args(), 1, {"approver_signatures": "fail"})

    cv = Builder("cv-lie")
    req = cv.request("act-1", "code.generate", "Author a synthetic script", risk="low")
    ex = cv.execute(req)
    ev = {"type": "cross_verification", "verification_id": "cv-1", "subject_entry_hash": ex["entry_hash"],
          "author": {"provider": "provider-a", "model": "model-a-1"}, "cross_provider": True,
          "reviewers": [{"provider": "Provider-A", "model": "model-a-2", "verdict": "agree"}]}
    cv.add(ev, validate=False)
    emit("fail-20-cross-provider-claim-false", "Claims cross_provider=true while every reviewer is from the author's provider.",
         {"log.jsonl": cv.log_text(), "checkpoint.note": cv.checkpoint()}, args(pin=False), 1, {"events": "fail"})

    t = edit_entries(b, lambda es: [e.__setitem__("v", 2) or rehash(e) for e in es])
    rechain(t, 1)
    emit("fail-21-unknown-entry-version", "Entries declare v=2. A v1 verifier fails closed instead of guessing.",
         {"log.jsonl": b.log_text(t)}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    fl = b.log_text().replace('"risk":"medium"', '"risk":"medium","score":1.5', 1)
    emit("fail-22-float-in-event", "A float inside an event: not representable in the canonical form, rejected at parse time.",
         {"log.jsonl": fl}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    dup = b.log_text().replace('"risk":"medium"', '"risk":"medium","risk":"low"', 1)
    emit("fail-23-duplicate-json-key", "A JSON object with a duplicated key (parsers disagree on which wins): rejected.",
         {"log.jsonl": dup}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    ng = Builder("no-genesis")
    ng.entries = []
    ng.add({"type": "action", "action_id": "a", "phase": "requested", "actor": {"kind": "agent", "id": "x"},
            "tool": "t", "summary": "s", "risk": "low", "requires_approval": False}, validate=False)
    emit("fail-24-first-entry-not-chain-open", "Chain does not begin with chain_open.",
         {"log.jsonl": ng.log_text()}, args(cp=False, vkey=False, pin=False), 1, {"events": "fail"})

    pr = b.proof(3)
    pr["audit_path"][0] = ("0" if pr["audit_path"][0][0] != "0" else "1") + pr["audit_path"][0][1:]
    emit("fail-25-inclusion-proof-tampered", "One byte of the audit path changed.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(pr), "entry.json": dumps_pretty(b.entries[3])},
         args(log=False, pin=False, proof="proof.json", entry="entry.json"), 1, {"inclusion_proof": "fail"})

    pr = b.proof(3)
    pr["leaf_index"] = 2
    emit("fail-26-inclusion-proof-wrong-index", "Proof for entry 3 claims to be for index 2.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(pr)},
         args(log=False, pin=False, proof="proof.json"), 1, {"inclusion_proof": "fail"})

    ent = copy.deepcopy(b.entries[3])
    ent["event"]["outcome"] = "rejected"
    emit("fail-27-inclusion-proof-entry-altered", "The disclosed entry content was edited after the proof was made.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(b.proof(3)), "entry.json": dumps_pretty(ent)},
         args(log=False, pin=False, proof="proof.json", entry="entry.json"), 1, {"inclusion_proof": "fail"})

    pr = b.proof(3, size=4)
    emit("fail-28-inclusion-proof-wrong-tree-size", "Proof generated for a 4-entry tree presented against the 5-entry checkpoint.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(pr)},
         args(log=False, pin=False, proof="proof.json"), 1, {"inclusion_proof": "fail"})

    wrong = bytearray(ots)
    wrong[len(v.OTS_MAGIC) + 2] ^= 1
    emit("fail-29-ots-wrong-digest", "OpenTimestamps file stamps a different digest than the checkpoint.",
         {"log.jsonl": b.log_text(), "checkpoint.note": cp, "checkpoint.ots": bytes(wrong)}, args(ots="checkpoint.ots"), 1, {"timestamp": "fail"})

    emit("fail-30-ots-not-an-ots-file", "A file that is not an OpenTimestamps proof.",
         {"log.jsonl": b.log_text(), "checkpoint.note": cp, "checkpoint.ots": b"not a proof"}, args(ots="checkpoint.ots"), 1, {"timestamp": "fail"})

    t = edit_entries(b, lambda es: es[0].__setitem__("chain_id", "00" * 32))
    emit("fail-31-chain-id-changed-in-genesis", "chain_id edited in entry 0: its hash, every later chain_id and the checkpoint origin all disagree.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": b.checkpoint()}, args(), 1, {"entry_hashes": "fail"})

    # ============================================ pre-publication review additions
    # --- inclusion proofs need a trusted checkpoint
    emit("pass-15-inclusion-proof-untrusted-checkpoint", "A correct audit path, but no trusted --vkey: the checkpoint size and root are unauthenticated, so inclusion_proof is not_checked (never ok).",
         {"log.jsonl": b.log_text(), "checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(b.proof(2))},
         args(vkey=False, proof="proof.json"), 0, with_layers(checkpoint_signature="not_checked", inclusion_proof="not_checked"))

    pr = b.proof(3)
    pr["v"] = True
    emit("fail-44-inclusion-proof-version-not-integer", "The proof declares \"v\": true. Only the integer 1 is accepted.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(pr), "entry.json": dumps_pretty(b.entries[3])},
         args(log=False, pin=False, proof="proof.json", entry="entry.json"), 1, {"inclusion_proof": "fail"})

    # --- the approver signature covers expiry and method
    g = Builder("expiry-stripped")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.approve(req, expires_at="2026-03-01T09:00:10Z")
    g.t += 600
    g.execute(req)

    def strip_expiry(es):
        del es[2]["event"]["expires_at"]
        rechain(es, 2)
    t = edit_entries(g, strip_expiry)
    emit("fail-32-approval-expiry-stripped", "expires_at removed from a signed approval so a late execution passes the gate; the approver signature covers expires_at, so it no longer verifies.",
         {"log.jsonl": g.log_text(t), "checkpoint.note": Builder.checkpoint_of(g.chain_id, t)}, args(), 1,
         {"entry_hashes": "ok", "chain_links": "ok", "approval_gate": "ok", "approver_signatures": "fail"})

    def alter_method(es):
        es[3]["event"]["approver"]["method"] = "hardware-token"
        rechain(es, 3)
    t = edit_entries(b, alter_method)
    emit("fail-33-approval-method-altered", "The recorded approval method is changed after signing; the signature covers it.",
         {"log.jsonl": b.log_text(t), "checkpoint.note": Builder.checkpoint_of(b.chain_id, t)}, args(), 1,
         {"entry_hashes": "ok", "chain_links": "ok", "approver_signatures": "fail"})

    # --- approval use: unique ids, one approval per attempt, failed attempts are gated
    g = Builder("replay-after-rejection")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    ap = g.approve(req, aid="ap-1")
    g.approve(req, outcome="rejected", aid="ap-2")
    g.add(copy.deepcopy(ap["event"]), validate=False)
    g.execute(req)
    emit("fail-34-approval-replayed-after-rejection", "approved(ap-1), rejected(ap-2), then a literal copy of the signed ap-1 and an execution. approval_id must be unique in a chain.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"entry_hashes": "ok", "chain_links": "ok", "events": "fail"})

    g = Builder("one-approval-two-runs")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.approve(req)
    g.execute(req)
    g.execute(req)
    emit("fail-35-one-approval-two-executions", "One approval, two executions of the same request. An approval authorises exactly one attempt.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"events": "ok", "approval_gate": "fail"})

    g = Builder("fresh-approval-each-run")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.approve(req, aid="ap-1")
    g.execute(req, phase="failed")
    g.approve(req, aid="ap-2")
    g.execute(req)
    emit("pass-16-fresh-approval-per-attempt", "A failed attempt consumes its approval; the retry runs under a second, separately signed approval.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 0, ALL_OK)

    g = Builder("failed-without-approval")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.execute(req, phase="failed")
    emit("fail-36-failed-attempt-without-approval", "phase=failed may mean partial execution, so it is gated like executed: no approval, fail.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(pin=False), 1, {"events": "ok", "approval_gate": "fail"})

    # --- provider names: NFC, ASCII case only
    x = Builder("provider-normalisation")
    req = x.request("act-1", "code.generate", "Author a synthetic script", risk="low")
    ex = x.execute(req)
    x.add({"type": "cross_verification", "verification_id": "cv-1", "subject_entry_hash": ex["entry_hash"],
           "author": {"provider": "Caf\u00e9-Labs", "model": "model-a-1"}, "cross_provider": False,
           "reviewers": [{"provider": "cafe\u0301-labs", "model": "model-a-2", "verdict": "agree"}]})
    emit("pass-17-provider-names-nfc-ascii-case", "Provider names equal after NFC and ASCII lowercasing are the same provider, so cross_provider=false is consistent.",
         {"log.jsonl": x.log_text(), "checkpoint.note": x.checkpoint()}, args(pin=False), 0,
         with_layers(approval_gate="not_checked", approver_signatures="not_checked"))

    # --- strict formats
    nl = b.log_text().replace(b.chain_id + '"', b.chain_id + '\\n"')
    emit("fail-37-trailing-newline-in-chain-id", "chain_id carries a trailing newline escape (\"...\\n\"); hex fields are exactly 64 characters.",
         {"log.jsonl": nl}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    g = Builder("expiry-not-a-date")
    req = g.request("act-1", "net.scan", "Scan a synthetic lab host", risk="high", requires_approval=True)
    g.add({"type": "human_approval", "approval_id": "ap-1", "subject_entry_hash": req["entry_hash"], "outcome": "approved",
           "approver": {"id": "approver-1", "method": "demo-console"}, "presented_digest": w.digest_of("shown"),
           "expires_at": "9999-99-99T99:99:99Z"}, validate=False)
    emit("fail-38-expires-at-not-a-date", "expires_at matches the pattern but is not a real time (month 99): it would never expire.",
         {"log.jsonl": g.log_text()}, args(cp=False, vkey=False, pin=False), 1, {"events": "fail"})

    big = b.log_text().replace('"seq":4,', '"seq":9007199254740993,', 1)
    emit("fail-39-seq-beyond-safe-integer", "seq above 2**53-1: a format failure (exit 1), not a usage error.",
         {"log.jsonl": big}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    deep = '{"type":"x-deep","n":' + '{"x":' * 100 + '{}' + '}' * 100 + '}'
    line = '{"chain_id":"%s","entry_hash":"%s","event":%s,"prev_hash":"%s","seq":1,"ts":"2026-03-01T09:00:07Z","v":1}' % (
        ext.chain_id, "0" * 64, deep, ext.entries[0]["entry_hash"])
    emit("fail-40-deep-nesting", "An event nested 100 levels deep (limit: 64 per entry). Rejected cleanly, without a crash.",
         {"log.jsonl": ext.log_text(ext.entries[:1]) + line + "\n"}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    emit("fail-41-crlf-line-endings", "CRLF line endings. Lines end with \\n only.",
         {"log.jsonl": b.log_text().replace("\n", "\r\n")}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    emit("fail-42-missing-final-newline", "The last line has no terminating newline (an interrupted write looks like this).",
         {"log.jsonl": b.log_text()[:-1]}, args(cp=False, vkey=False, pin=False), 1, {"format": "fail"})

    def small_order(es):
        es[3]["event"]["approver_signature"] = {"public_key": "01" + "00" * 31, "signature": "01" + "00" * 63}
        rechain(es, 3)
    t = edit_entries(b, small_order)
    emit("fail-43-small-order-approver-key", "The approval is \"signed\" with the identity point as public key, which satisfies the equation for any message. Small-order keys are rejected.",
         {"log.jsonl": b.log_text(t)}, args(cp=False, vkey=False, pin=False), 1, {"events": "ok", "approver_signatures": "fail"})

    body = v.format_checkpoint(b.chain_id, 5, v.merkle_root([v.leaf_hash(e["entry_hash"]) for e in b.entries])).replace(b"\n5\n", b"\n" + b"9" * 40 + b"\n")
    emit("fail-45-checkpoint-size-out-of-range", "A signed checkpoint whose size has 40 digits (above 2**53-1): the checkpoint is rejected as malformed (exit 1, not a usage error).",
         {"log.jsonl": b.log_text(), "checkpoint.note": body + b"\n" + sign_line(body, LOG_SEED, LOG_PUB, LOG_KEY_NAME)}, args(), 1,
         {"checkpoint_root": "fail", "checkpoint_signature": "fail"})

    # ============================================ second review additions
    # --- deny rule (SPEC 6.6 rules 4-5): only a later human approval lifts a deny
    g = Builder("deny-then-allow")
    req = g.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=False)
    g.decide(req, "deny", rationale="outside allowed scope", did="d1")
    g.decide(req, "allow", rationale="policy re-evaluated", did="d2")
    g.execute(req)
    emit("fail-46-deny-lifted-by-allow", "deny, then a later policy 'allow', then executed (no approval required). A later decision does not lift a deny; only a later human approval does.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(pin=False), 1, {"events": "ok", "approval_gate": "fail"})

    g = Builder("approved-deny-allow")
    req = g.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=True)
    g.approve(req, aid="ap-1")
    g.decide(req, "deny", rationale="outside allowed scope", did="d1")
    g.decide(req, "allow", rationale="policy re-evaluated", did="d2")
    g.execute(req)
    emit("fail-47-approved-then-deny-then-allow", "approved, then deny, then allow, then executed (approval required). The approval predates the deny, and the allow does not lift it.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"events": "ok", "approver_signatures": "ok", "approval_gate": "fail"})

    g = Builder("deny-approved-rejected")
    req = g.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=False)
    g.decide(req, "deny", rationale="outside allowed scope", did="d1")
    g.approve(req, aid="ap-1")
    g.approve(req, outcome="rejected", aid="ap-2")
    g.execute(req)
    emit("fail-48-deny-approved-then-rejected", "deny, approved, rejected, executed (no approval required). The latest human approval after the deny is 'rejected', so the deny stands.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 1, {"events": "ok", "approver_signatures": "ok", "approval_gate": "fail"})

    g = Builder("deny-allow-approved")
    req = g.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=False)
    g.decide(req, "deny", rationale="outside allowed scope", did="d1")
    g.decide(req, "allow", rationale="policy re-evaluated", did="d2")
    g.approve(req, aid="ap-1")
    g.execute(req)
    emit("pass-18-deny-lifted-by-human-approval", "deny, allow, then a signed human approval, then executed (no approval required). The human approval after the deny lifts it; approval_gate is ok because the deny rule was evaluated.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 0, ALL_OK)

    g = Builder("approved-deny-approved")
    req = g.request("act-1", "fs.delete", "Delete a synthetic directory", risk="high", requires_approval=True)
    g.approve(req, aid="ap-1")
    g.decide(req, "deny", rationale="outside allowed scope", did="d1")
    g.approve(req, aid="ap-2")
    g.execute(req)
    emit("pass-19-deny-after-approval-reapproved", "approved, deny, a second signed approval, executed (approval required). The second approval lifts the deny and authorises the one attempt.",
         {"log.jsonl": g.log_text(), "checkpoint.note": g.checkpoint()}, args(), 0, ALL_OK)

    # --- a disclosed entry must follow every entry rule: members outside the hash are not authenticated
    ent = copy.deepcopy(b.entries[3])
    ent["human_approved_by"] = "CEO (verified)"
    emit("fail-49-inclusion-proof-entry-extra-member", "The disclosed entry hashes correctly but carries an extra top-level member that the entry hash does not cover. It is rejected instead of being reported as matched.",
         {"checkpoint.note": b.checkpoint(), "proof.json": dumps_pretty(b.proof(3)), "entry.json": dumps_pretty(ent)},
         args(log=False, pin=False, proof="proof.json", entry="entry.json"), 1, {"inclusion_proof": "fail"})

    # --- signature-line cap (SPEC 8)
    body, sigline = b.checkpoint().split(b"\n\n")
    emit("fail-50-checkpoint-too-many-signature-lines", "A checkpoint with 17 copies of a valid signature line (the limit is 16). Rejected as malformed before any signature is verified.",
         {"log.jsonl": b.log_text(), "checkpoint.note": body + b"\n\n" + sigline * (v.MAX_SIG_LINES + 1)}, args(), 1,
         {"checkpoint_root": "fail", "checkpoint_signature": "fail"})


def main():
    global OUT
    OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors")
    os.makedirs(OUT, exist_ok=True)
    build_all()
    INDEX.sort()
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8") as f:
        f.write("# Test vectors\n\n"
                "Generated by `tools/make_vectors.py` (deterministic; a test regenerates them and compares bytes).\n"
                "All keys are derived from public strings and are NOT SECRET. All data is synthetic.\n\n"
                "Each directory has a `case.json` with the verifier arguments and the expected exit code / layer states.\n"
                "`pass-*` vectors MUST exit 0, `fail-*` vectors MUST exit 1. `pass-12` and `pass-13` document limits: they pass on purpose.\n\n"
                "| vector | expectation | what it shows |\n|---|---|---|\n")
        for name, exp, desc in INDEX:
            f.write("| `%s` | %s | %s |\n" % (name, exp, desc))
    print("wrote %d vectors to %s" % (len(INDEX), OUT))


if __name__ == "__main__":
    main()
