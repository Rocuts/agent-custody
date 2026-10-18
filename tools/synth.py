# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic synthetic chains for vectors and examples.

Everything here is fake: keys are derived from public strings (NOT SECRET),
ids and hosts are made up. Never use these seeds for anything real.
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "verifier"))
sys.path.insert(0, os.path.join(HERE, "..", "writer"))
import agent_custody_verify as v  # noqa: E402
import agent_custody_write as w  # noqa: E402

LOG_KEY_NAME = "demo-log-key"
FOREIGN_KEY_NAME = "other-log-key"


def seed(label: str) -> bytes:
    return hashlib.sha256(b"agent-custody DEMO key, public string, NOT SECRET: " + label.encode()).digest()


LOG_SEED = seed("log")
FOREIGN_SEED = seed("foreign")
APPROVER_SEED = seed("approver-1")
APPROVER2_SEED = seed("approver-2")
LOG_PUB = w.ed25519_public(LOG_SEED)
FOREIGN_PUB = w.ed25519_public(FOREIGN_SEED)
APPROVER_PUB = w.ed25519_public(APPROVER_SEED)
APPROVER2_PUB = w.ed25519_public(APPROVER2_SEED)
LOG_VKEY = v.make_vkey(LOG_KEY_NAME, LOG_PUB)
FOREIGN_VKEY = v.make_vkey(FOREIGN_KEY_NAME, FOREIGN_PUB)


def chain_id_for(label: str) -> str:
    return hashlib.sha256(b"agent-custody demo chain: " + label.encode()).hexdigest()


class Builder:
    """Builds a chain in memory with deterministic timestamps (+`step` s per entry)."""

    def __init__(self, label, agent_id="agent-demo-1", runtime="demo-runtime", t0=1772355600, step=7):
        self.label = label
        self.chain_id = chain_id_for(label)
        self.t = t0
        self.step = step
        self.entries = []
        self.add({"type": "chain_open", "chain_id": self.chain_id, "spec": v.SPEC_VERSION,
                  "agent": {"id": agent_id, "runtime": runtime}})

    def ts(self):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(self.t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def add(self, event, validate=True):
        seq = len(self.entries)
        if validate:
            by_hash = {e["entry_hash"]: (e["seq"], e["event"]) for e in self.entries}
            v.validate_event(event, seq, self.chain_id, by_hash)
        prev = self.entries[-1]["entry_hash"] if self.entries else v.ZERO_HASH
        e = w.make_entry(self.chain_id, seq, self.ts(), prev, event)
        self.t += self.step
        self.entries.append(e)
        return e

    # --- event helpers (return the new entry) -------------------------------
    def request(self, action_id, tool, summary, risk="low", requires_approval=False, actor_id="agent-demo-1", **extra):
        ev = {"type": "action", "action_id": action_id, "phase": "requested",
              "actor": {"kind": "agent", "id": actor_id}, "tool": tool, "summary": summary,
              "risk": risk, "requires_approval": requires_approval}
        ev.update(extra)
        return self.add(ev)

    def execute(self, req, phase="executed", **extra):
        r = req["event"]
        ev = {"type": "action", "action_id": r["action_id"], "phase": phase,
              "actor": r["actor"], "tool": r["tool"], "summary": r["summary"] if phase == "executed" else "failed: " + r["summary"],
              "risk": r["risk"], "request_entry_hash": req["entry_hash"]}
        ev.update(extra)
        return self.add(ev)

    def decide(self, req, outcome, basis="policy", rationale=None, did="d1"):
        ev = {"type": "decision", "decision_id": did, "subject_entry_hash": req["entry_hash"],
              "outcome": outcome, "basis": basis, "actor": {"kind": "system", "id": "policy-engine-demo"}}
        if rationale:
            ev["rationale"] = rationale
        return self.add(ev)

    def approve(self, req, outcome="approved", approver="approver-1", signer_seed=APPROVER_SEED,
                presented=None, aid="ap1", sign=True, **extra):
        ev = {"type": "human_approval", "approval_id": aid, "subject_entry_hash": req["entry_hash"],
              "outcome": outcome, "approver": {"id": approver, "method": "demo-console"},
              "presented_digest": presented or w.digest_of({"shown_to_human": req["event"]["summary"]})}
        ev.update(extra)
        if sign:
            ev = w.sign_approval(signer_seed, self.chain_id, ev)
        return self.add(ev)

    # --- outputs ---------------------------------------------------------------
    def log_text(self, entries=None):
        return "".join(w.dump_entry(e) + "\n" for e in (entries if entries is not None else self.entries))

    def checkpoint(self, size=None, seed_=LOG_SEED, pub=LOG_PUB, name=LOG_KEY_NAME):
        size = size or len(self.entries)
        leaves = [v.leaf_hash(e["entry_hash"]) for e in self.entries[:size]]
        body = v.format_checkpoint(self.chain_id, size, v.merkle_root(leaves))
        return body + b"\n" + sign_line(body, seed_, pub, name)

    @staticmethod
    def checkpoint_of(chain_id, entries, seed_=LOG_SEED, pub=LOG_PUB, name=LOG_KEY_NAME):
        """Checkpoint over an edited entry list (what an attacker holding the log key could sign)."""
        body = v.format_checkpoint(chain_id, len(entries), v.merkle_root([v.leaf_hash(e["entry_hash"]) for e in entries]))
        return body + b"\n" + sign_line(body, seed_, pub, name)

    def proof(self, index, size=None):
        size = size or len(self.entries)
        leaves = [v.leaf_hash(e["entry_hash"]) for e in self.entries[:size]]
        return {"v": 1, "chain_id": self.chain_id, "leaf_index": index, "tree_size": size,
                "entry_hash": self.entries[index]["entry_hash"],
                "audit_path": [h.hex() for h in v.merkle_inclusion_path(leaves, index)]}


def sign_line(body: bytes, seed_, pub, name) -> bytes:
    sig = w.ed25519_sign_pure(seed_, body)
    return ("%s%s %s\n" % (v.SIG_PREFIX, name, base64.b64encode(v.key_id(name, pub) + sig).decode())).encode()


def approval_flow(label="approval-flow", summary="Rotate the guest Wi-Fi passphrase on a synthetic access point",
                  approver_seed=APPROVER_SEED, **kw):
    """open -> request -> escalate -> approve(signed) -> executed. 5 entries."""
    b = Builder(label, **kw)
    req = b.request("act-1", "wifi.set_passphrase", summary, risk="medium", requires_approval=True,
                    input_digest=w.digest_of({"ap": "ap-guest-demo", "note": "passphrase intentionally not recorded"}))
    b.decide(req, "escalate", rationale="medium-risk change on shared infrastructure requires a human")
    b.approve(req, signer_seed=approver_seed)
    b.execute(req, result_digest=w.digest_of({"status": "applied"}))
    return b


def dumps_pretty(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
