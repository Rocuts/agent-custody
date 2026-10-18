#!/usr/bin/env python3
# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Regenerate examples/ (synthetic data only):  python tools/make_examples.py [OUT_DIR]"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from synth import APPROVER_PUB, LOG_VKEY, Builder, dumps_pretty, v, w  # noqa: E402

PIN = "approver-1=" + APPROVER_PUB.hex()
VERIFY = "python3 verifier/agent_custody_verify.py"


def write(out, name, b, readme, pin=True):
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "log.jsonl"), "w", encoding="utf-8") as f:
        f.write(b.log_text())
    with open(os.path.join(d, "checkpoint.note"), "wb") as f:
        f.write(b.checkpoint())
    case = {"description": readme.split("\n")[0].lstrip("# "),
            "args": {"log": "log.jsonl", "checkpoints": ["checkpoint.note"], "vkeys": [LOG_VKEY],
                     "approver_keys": [PIN] if pin else [], "ots": None, "tsr": None, "proof": None, "entry": None},
            "expect": {"exit": 0, "layers": {"format": "ok", "entry_hashes": "ok", "chain_links": "ok", "events": "ok",
                                              "checkpoint_root": "ok", "checkpoint_signature": "ok"}}}
    with open(os.path.join(d, "case.json"), "w", encoding="utf-8") as f:
        f.write(dumps_pretty(case))
    with open(os.path.join(d, "vkey.txt"), "w", encoding="utf-8") as f:
        f.write(LOG_VKEY + "\n")
    cmd = "%s examples/%s/log.jsonl \\\n  --checkpoint examples/%s/checkpoint.note \\\n  --vkey \"$(cat examples/%s/vkey.txt)\"" % (VERIFY, name, name, name)
    if pin:
        with open(os.path.join(d, "approver-key.txt"), "w", encoding="utf-8") as f:
            f.write(PIN + "\n")
        cmd += " \\\n  --approver-key \"$(cat examples/%s/approver-key.txt)\"" % name
    with open(os.path.join(d, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme + "\n## Verify it\n\n```sh\n" + cmd + "\n```\n\n"
                "Then break it: change one character anywhere in `log.jsonl` and run the command again.\n\n"
                "Everything here is synthetic: the keys are derived from public strings (NOT SECRET), the hosts end in `.test`, "
                "and there are no real people, customers or networks. `vkey.txt` sits next to the log only for convenience: "
                "in real use the checkpoint key must reach the verifier through a channel independent of the log.\n")
    print("wrote", name, "(%d entries)" % len(b.entries))


def ex1(out):
    b = Builder("example-support-wifi", agent_id="support-agent-demo", runtime="demo-runtime")
    r0 = b.request("t-1", "ticket.read", "Read support ticket T-1042 (synthetic): guest Wi-Fi password was shared in a public channel", risk="low", actor_id="support-agent-demo")
    b.execute(r0, result_digest=w.digest_of({"ticket": "T-1042", "fields": ["title", "body"]}))
    req = b.request("t-2", "wifi.set_passphrase", "Replace the guest Wi-Fi passphrase on access point ap-guest-demo",
                    risk="medium", requires_approval=True, actor_id="support-agent-demo",
                    input_digest=w.digest_of({"ap": "ap-guest-demo", "passphrase": "NOT RECORDED"}))
    b.decide(req, "escalate", rationale="changes shared network access; policy requires a human", did="dec-1")
    b.approve(req, approver="approver-1", aid="appr-1", presented=w.digest_of({"screen": "Replace guest Wi-Fi passphrase on ap-guest-demo? [approve/reject]"}))
    b.execute(req, result_digest=w.digest_of({"status": "applied", "ap": "ap-guest-demo"}))
    r3 = b.request("t-3", "ticket.reply", "Tell the requester the guest passphrase was rotated (new value sent over the approved channel)", risk="low", actor_id="support-agent-demo")
    b.execute(r3)
    readme = """# Support agent rotates a guest Wi-Fi passphrase, with human approval

A support agent reads a ticket, asks to replace a guest Wi-Fi passphrase, a policy engine escalates, a human approves
(signing the approval with their own key), the agent applies the change and answers the ticket.

What to notice in `log.jsonl`:

- The passphrase itself is **never** logged. The request records `input_digest`, a hash of the canonical request with the
  secret replaced by a placeholder. Log digests, not secrets.
- The `human_approval` entry carries `presented_digest` (a hash of what the human was shown) and an `approver_signature`.
  The verifier checks the signature against the approver key **you pin** with `--approver-key`.
- The `approval_gate` layer confirms that, in the recorded order, the action ran only after an unexpired approval.
  It checks the *record*, not that the real system actually waited.
"""
    write(out, "01-support-wifi-password", b, readme)


def ex2(out):
    b = Builder("example-security-scan", agent_id="security-agent-demo", runtime="demo-runtime")
    req = b.request("s-1", "net.scan", "Port scan of lab-host-a.example.test (in the approved test scope)", risk="high",
                    requires_approval=True, actor_id="security-agent-demo",
                    input_digest=w.digest_of({"target": "lab-host-a.example.test", "ports": "1-1024"}))
    b.decide(req, "escalate", rationale="active scanning needs a human to confirm scope", did="dec-1")
    b.approve(req, approver="approver-1", aid="appr-1", presented=w.digest_of({"scope": ["lab-host-a.example.test"], "window": "synthetic"}))
    b.execute(req, result_digest=w.digest_of({"open_ports": [22, 443], "host": "lab-host-a.example.test"}))
    out_of_scope = b.request("s-2", "net.scan", "Port scan of prod-host.example.test (NOT in the approved scope)", risk="high",
                             requires_approval=True, actor_id="security-agent-demo",
                             input_digest=w.digest_of({"target": "prod-host.example.test", "ports": "1-1024"}))
    b.decide(out_of_scope, "deny", rationale="target is outside the approved scope", did="dec-2")
    readme = """# Security agent runs an approved scan, and a second one is denied

A security agent requests an active scan. The policy engine escalates, a human approves the in-scope target, the scan runs.
Later the agent asks to scan a host outside the approved scope; the policy engine records a `deny` and the action is
never executed. The denial is part of the evidence too.

What to notice:

- The denied request has **no** `executed` entry. A `deny` followed by an `executed` entry for the same request would
  fail the `approval_gate` layer (see `vectors/fail-15-executed-after-deny`) unless a later human approval lifted the
  deny; a later `allow` decision does not (`vectors/fail-46-deny-lifted-by-allow`).
- Findings are stored as `result_digest` (a hash). The raw scan output stays outside the log, so the log can be shared
  with an auditor without leaking scan data; the auditor can later check a disclosed output against the digest.
"""
    write(out, "02-security-scan-approved", b, readme)


def ex3(out):
    b = Builder("example-cross-verification", agent_id="coding-agent-demo", runtime="demo-runtime")
    req = b.request("c-1", "code.write", "Generate a synthetic data-migration script", risk="medium", actor_id="coding-agent-demo",
                    input_digest=w.digest_of({"spec": "migrate table a to table b"}))
    ex = b.execute(req, result_digest=w.digest_of({"artifact": "migrate_a_to_b.py", "version": 1}))
    b.add({"type": "cross_verification", "verification_id": "cv-1", "subject_entry_hash": ex["entry_hash"],
           "author": {"provider": "provider-a", "model": "model-a-1"}, "cross_provider": True,
           "reviewers": [{"provider": "provider-b", "model": "model-b-1", "verdict": "disagree", "finding_count": 2,
                          "findings_digest": w.digest_of(["rollback path missing", "no transaction around the copy"])}]})
    b.add({"type": "decision", "decision_id": "dec-1", "subject_entry_hash": req["entry_hash"], "outcome": "deny",
           "basis": "human", "actor": {"kind": "human", "id": "reviewer-1"},
           "rationale": "reviewer from another provider found two real defects; do not ship version 1"})
    req2 = b.request("c-2", "code.write", "Revise the synthetic data-migration script (version 2)", risk="medium", actor_id="coding-agent-demo",
                     input_digest=w.digest_of({"spec": "migrate table a to table b", "fixes": ["rollback", "transaction"]}))
    ex2_ = b.execute(req2, result_digest=w.digest_of({"artifact": "migrate_a_to_b.py", "version": 2}))
    b.add({"type": "cross_verification", "verification_id": "cv-2", "subject_entry_hash": ex2_["entry_hash"],
           "author": {"provider": "provider-a", "model": "model-a-1"}, "cross_provider": True,
           "reviewers": [{"provider": "provider-b", "model": "model-b-1", "verdict": "agree", "finding_count": 0}]})
    readme = """# Cross-provider verification: a second provider disagrees, the human decides

An agent backed by `provider-a` writes a script. A reviewer from a *different* provider (`provider-b`) disagrees and reports
two findings (stored as a digest). A human records a `deny`, the agent revises, and the same reviewer now agrees.

What to notice:

- `cross_verification` is a first-class event: who authored, which providers reviewed, each verdict, how many findings.
- `cross_provider` is recomputed by the verifier from the recorded provider names. Claiming cross-provider review while
  every reviewer shares the author's provider fails the `events` layer (see `vectors/fail-20-cross-provider-claim-false`).
- Provider and model names are **self-declared by whoever wrote the log**. The log does not prove that a different
  provider really answered; it makes the claim explicit, ordered and tamper-evident. Providers here are placeholders.
"""
    write(out, "03-cross-provider-verification", b, readme, pin=False)


def main():
    out = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples")
    os.makedirs(out, exist_ok=True)
    ex1(out)
    ex2(out)
    ex3(out)


if __name__ == "__main__":
    main()
