#!/usr/bin/env python3
# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
# (BSD-3-Clause applies to the RFC 8032 Section 6 derived code; see the note above the Ed25519 section.)
"""Reference writer for agent-custody logs (v0.1, experimental).

Stdlib only. Appends events to a JSONL log, builds C2SP signed-note
checkpoints, emits RFC 6962 inclusion proofs. It reuses the primitives of
../verifier/agent_custody_verify.py so the two cannot drift apart.

Signing: checkpoints and approvals are signed through a `signer` callable
(bytes -> 64-byte Ed25519 signature). `ed25519_sign_pure` below is a pure
Python RFC 8032 implementation intended for tests, vectors and demos ONLY:
it is variable-time and keeps the seed in process memory. For real use plug
in a signer backed by your KMS/HSM/`cryptography`/libsodium and keep the key
off the host that runs the agent (see LIMITS.md).

CLI:
    agent_custody_write.py keygen --seed-file demo.seed      (writes the seed, mode 0600; prints public key and vkey)
    agent_custody_write.py new LOG --agent-id ID [--runtime TXT]
    agent_custody_write.py append LOG --event '{"type": ...}' [--ts 2026-01-01T00:00:00Z]
    agent_custody_write.py checkpoint LOG --seed-file demo.seed --name KEYNAME > cp.note
    agent_custody_write.py proof LOG --index N [--size M] > proof.json

The demo seed is read from --seed-file or from the AGENT_CUSTODY_DEMO_SEED environment
variable, never from a command-line argument (arguments end up in `ps`, shell history and
agent transcripts). It is still a demo signer: see above.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "verifier"))
import agent_custody_verify as v  # noqa: E402


# ------------------------------------------------ Ed25519 sign (TEST ONLY)
# The signing code below is derived from the Python illustration in
# RFC 8032, Section 6 (S. Josefsson, I. Liusvaara), building on the point
# arithmetic in the verifier. Please reproduce this note.
# Copyright (c) 2017 IETF Trust and the persons identified as authors of the code.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, is permitted pursuant to, and subject to the license terms
# contained in, the Revised BSD License set forth in Section 4.c of the IETF
# Trust's Legal Provisions Relating to IETF Documents
# (https://trustee.ietf.org/license-info).
# Modifications (renaming, demo-signer wrapper) are Copyright 2026 Orbexs and
# the agent-custody contributors and licensed under Apache-2.0.
def _expand(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little"), h[32:]


def ed25519_public(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return v._compress(v._point_mul(a, v._G))


def ed25519_sign_pure(seed: bytes, msg: bytes) -> bytes:
    """RFC 8032 section 5.1.6. NOT constant-time: demos/tests only."""
    a, prefix = _expand(seed)
    A = v._compress(v._point_mul(a, v._G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % v._Q
    Rs = v._compress(v._point_mul(r, v._G))
    h = int.from_bytes(hashlib.sha512(Rs + A + msg).digest(), "little") % v._Q
    s = (r + h * a) % v._Q
    return Rs + int.to_bytes(s, 32, "little")


def seed_signer(seed: bytes):
    return lambda msg: ed25519_sign_pure(seed, msg)


# ----------------------------------------------------------------- the log
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_entry(chain_id: str, seq: int, ts: str, prev_hash: str, event: dict) -> dict:
    e = {"v": 1, "chain_id": chain_id, "seq": seq, "ts": ts, "prev_hash": prev_hash, "event": event}
    e["entry_hash"] = v.compute_entry_hash(e)
    return e


def _check_ts(ts: str) -> str:
    if not v._is_ts(ts):
        raise ValueError("ts must be a real UTC time written YYYY-MM-DDTHH:MM:SSZ, got %r" % (ts,))
    return ts


def check_key_name(name: str) -> str:
    """Signed-note key name: non-empty, no whitespace, no '+' (the vkey separator)."""
    if not isinstance(name, str) or not name or "+" in name or any(c.isspace() for c in name):
        raise ValueError("key name must be non-empty, without spaces, newlines or '+', got %r" % (name,))
    return name


def dump_entry(e: dict) -> str:
    return json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Log:
    """Single-writer append-only JSONL log (no locking: one writer per file)."""

    def __init__(self, path: str, entries: list):
        self.path = path
        self.entries = entries

    @classmethod
    def create(cls, path, agent_id, runtime=None, chain_id=None, ts=None, extra=None):
        if os.path.exists(path):
            raise FileExistsError(path)
        chain_id = chain_id or os.urandom(32).hex()
        if not v._is_hex64(chain_id):
            raise ValueError("chain_id must be 64 lowercase hex characters")
        ts = _check_ts(ts) if ts is not None else utc_now()
        agent = {"id": agent_id}
        if runtime:
            agent["runtime"] = runtime
        event = {"type": "chain_open", "chain_id": chain_id, "spec": v.SPEC_VERSION, "agent": agent}
        if extra:
            clash = sorted(set(extra) & set(event))
            if clash:
                raise ValueError("extra may not override chain_open members %s" % clash)
            event.update(extra)
        e = make_entry(chain_id, 0, ts, v.ZERO_HASH, event)
        log = cls(path, [e])
        with open(path, "w", encoding="utf-8") as f:
            f.write(dump_entry(e) + "\n")
        return log

    @classmethod
    def open(cls, path):
        """Load and re-verify the log (hashes, links, events) so nothing is appended onto a damaged chain."""
        entries = v.load_log(path)
        bad = v._check_entry_hashes(entries)
        if bad:
            raise ValueError("%s: entry_hash does not match content at seq %s; refusing to append" % (path, bad[0]))
        problems = v._check_chain(entries)
        if problems:
            raise ValueError("%s: %s; refusing to append" % (path, problems[0]))
        v._check_events(entries)
        return cls(path, entries)

    @property
    def chain_id(self):
        return self.entries[0]["chain_id"]

    def append(self, event: dict, ts: str = None) -> dict:
        by_hash = {e["entry_hash"]: (e["seq"], e["event"]) for e in self.entries}
        v.validate_event(event, len(self.entries), self.chain_id, by_hash)  # refuse to write invalid events (incl. reused approval_id)
        ts = _check_ts(ts) if ts is not None else utc_now()
        e = make_entry(self.chain_id, len(self.entries), ts, self.entries[-1]["entry_hash"], event)
        v.canon(v.entry_body(e))  # floats, out-of-range integers, excessive nesting: refuse before writing
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(dump_entry(e) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.entries.append(e)
        return e

    def _size(self, size):
        """None means the whole log; anything else must be 1..len(log)."""
        if size is None:
            return len(self.entries)
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= len(self.entries):
            raise ValueError("size must be between 1 and the log length %d, got %r" % (len(self.entries), size))
        return size

    def leaves(self, size=None):
        return [v.leaf_hash(e["entry_hash"]) for e in self.entries[: self._size(size)]]

    def checkpoint(self, name: str, signer, pub: bytes, size: int = None) -> bytes:
        check_key_name(name)
        size = self._size(size)
        body = v.format_checkpoint(self.chain_id, size, v.merkle_root(self.leaves(size)))
        sig = signer(body)
        line = "%s%s %s\n" % (v.SIG_PREFIX, name, base64.b64encode(v.key_id(name, pub) + sig).decode())
        return body + b"\n" + line.encode("utf-8")

    def proof(self, index: int, size: int = None) -> dict:
        size = self._size(size)
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < size:
            raise ValueError("index must be between 0 and %d, got %r" % (size - 1, index))
        leaves = self.leaves(size)
        return {
            "v": 1,
            "chain_id": self.chain_id,
            "leaf_index": index,
            "tree_size": size,
            "entry_hash": self.entries[index]["entry_hash"],
            "audit_path": [h.hex() for h in v.merkle_inclusion_path(leaves, index)],
        }


def sign_approval(seed: bytes, chain_id: str, approval_event: dict) -> dict:
    """Return approval_event with `approver_signature` added (demo signer)."""
    ev = dict(approval_event)
    msg = v.approval_message(chain_id, ev)
    ev["approver_signature"] = {"public_key": ed25519_public(seed).hex(), "signature": ed25519_sign_pure(seed, msg).hex()}
    return ev


def digest_of(obj) -> str:
    """sha256 over canonical JSON: use this for input_digest/result_digest/presented_digest."""
    return hashlib.sha256(v.canon(obj)).hexdigest()


# --------------------------------------------------------------------- CLI
SEED_ENV = "AGENT_CUSTODY_DEMO_SEED"


def read_seed(path=None) -> bytes:
    """Demo seed from a file (64 hex chars) or, if no file is given, from $AGENT_CUSTODY_DEMO_SEED."""
    if path:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    else:
        text = os.environ.get(SEED_ENV, "").strip()
        if not text:
            raise ValueError("no demo seed: pass --seed-file FILE or set %s" % SEED_ENV)
    if not v.HEX64.fullmatch(text):
        raise ValueError("demo seed must be 64 lowercase hex characters")
    return bytes.fromhex(text)


def write_seed_file(path, seed: bytes) -> None:
    """Create `path` with mode 0600; refuse to overwrite an existing file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(seed.hex() + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="agent-custody reference writer (experimental)", allow_abbrev=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="write a fresh demo seed to a 0600 file; print public key and vkey (name 'demo-key')", allow_abbrev=False)
    p.add_argument("--seed-file", required=True, help="where to write the seed (must not exist)")
    p = sub.add_parser("new")
    p.add_argument("log")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--runtime")
    p = sub.add_parser("append")
    p.add_argument("log")
    p.add_argument("--event", required=True)
    p.add_argument("--ts")
    p = sub.add_parser("checkpoint", allow_abbrev=False)
    p.add_argument("log")
    p.add_argument("--seed-file", help="demo seed file (64 hex); default: $%s" % SEED_ENV)
    p.add_argument("--name", required=True)
    p = sub.add_parser("proof")
    p.add_argument("log")
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--size", type=int)
    a = ap.parse_args(argv)
    try:
        return _run(a)
    except (OSError, ValueError) as exc:  # FormatError is a ValueError
        print("error: %s" % exc, file=sys.stderr)
        return 2


def _run(a) -> int:
    if a.cmd == "keygen":
        seed = os.urandom(32)
        pub = ed25519_public(seed)
        try:
            write_seed_file(a.seed_file, seed)
        except FileExistsError:
            print("error: %s exists; refusing to overwrite a seed" % a.seed_file, file=sys.stderr)
            return 2
        print("seed:   written to %s (SECRET, demo signer only, mode 0600)" % a.seed_file)
        print("public: %s" % pub.hex())
        print("vkey:   %s" % v.make_vkey("demo-key", pub))
    elif a.cmd == "new":
        log = Log.create(a.log, a.agent_id, a.runtime)
        print("created %s chain_id=%s" % (a.log, log.chain_id))
    elif a.cmd == "append":
        e = Log.open(a.log).append(v.parse_json(a.event), a.ts)
        print("appended seq=%d entry_hash=%s" % (e["seq"], e["entry_hash"]))
    elif a.cmd == "checkpoint":
        try:
            seed = read_seed(a.seed_file)
        except (OSError, ValueError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        sys.stdout.write(Log.open(a.log).checkpoint(a.name, seed_signer(seed), ed25519_public(seed)).decode())
    elif a.cmd == "proof":
        print(json.dumps(Log.open(a.log).proof(a.index, a.size), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
