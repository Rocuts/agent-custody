#!/usr/bin/env python3
# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
# (BSD-3-Clause applies to the RFC 8032 Section 6 derived code; see the note above the Ed25519 section.)
"""agent-custody verifier (v0.1, experimental).

Single file, Python 3.10+, standard library only.

Checks a custody log (JSONL), optional C2SP signed-note checkpoints, optional
RFC 6962 inclusion proofs and optional timestamp files, and prints a verdict
PER LAYER. Every layer is one of:

    ok            checked, passed
    fail          checked, failed
    not_checked   not performed because the needed input was not supplied
    unavailable   input supplied, but this verifier cannot perform the check

There is deliberately no single "VALID" verdict: a clean run means "no
inconsistency found in the layers that were checked", nothing more. See
LIMITS.md and SPEC.md.

Ed25519 verification is implemented in pure Python following RFC 8032
section 5.1.7 (cofactorless check). It is variable-time, which is fine for
verification (all inputs are public) and must NOT be reused for signing
secrets. See SPEC.md section 9.

Usage:
    python3 agent_custody_verify.py LOG.jsonl [--checkpoint CP.note ...]
        [--vkey NAME+KEYID+BASE64] [--approver-key ID=HEX32] [--ots F.ots]
        [--tsr F.tsr] [--proof PROOF.json] [--entry ENTRY.json] [--json]
        [--require LAYER[,LAYER...]] [--max-bytes N]
    python3 agent_custody_verify.py --proof PROOF.json --checkpoint CP.note --vkey ...

Exit codes: 0 no layer failed; 1 at least one layer failed; 2 usage / I/O
error; 3 a layer named in --require was not "ok".
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime

if sys.version_info < (3, 10):
    raise SystemExit("agent-custody verifier needs Python 3.10 or newer (found %d.%d)" % sys.version_info[:2])

__version__ = "0.1.0"
SPEC_VERSION = "agent-custody/0.1"

# ---------------------------------------------------------------- constants
ENTRY_DOMAIN = b"agent-custody/entry/v1\x00"
APPROVAL_DOMAIN = b"agent-custody/approval/v2\x00"
ORIGIN_PREFIX = "agent-custody/v1/"
ZERO_HASH = "0" * 64
MAX_SAFE_INT = 2**53 - 1
MAX_STRING = 4096  # code points, for the schema strings listed in SPEC section 6
MAX_DEPTH = 64  # nesting of objects/arrays in an entry, the entry object itself is depth 1
MAX_INPUT_BYTES = 64 * 1024 * 1024  # per input file; --max-bytes overrides
MAX_SIG_LINES = 16  # signature lines per checkpoint (SPEC section 8)
# Patterns are applied with fullmatch(): "$" would accept a trailing newline.
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
SIG_PREFIX = "— "  # em dash + space, C2SP signed-note signature line

LAYERS = (
    "format",
    "entry_hashes",
    "chain_links",
    "events",
    "approval_gate",
    "approver_signatures",
    "checkpoint_root",
    "checkpoint_signature",
    "inclusion_proof",
    "timestamp",
)

OK, FAIL, NOT_CHECKED, UNAVAILABLE = "ok", "fail", "not_checked", "unavailable"


# ------------------------------------------------------------------ errors
class FormatError(ValueError):
    """Input is not valid agent-custody data."""


# ------------------------------------------------------- canonical JSON
def _check_str(s: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogate
        raise FormatError("string contains a lone surrogate") from exc


def _canon_str(s: str) -> str:
    _check_str(s)
    return json.dumps(s, ensure_ascii=False)


def canon(value) -> bytes:
    """Canonical JSON: the RFC 8785 (JCS) subset without floats.

    Objects: keys sorted by UTF-16 code units, no whitespace. Integers only
    (|n| <= 2**53-1). Strings are escaped per RFC 8785 (which is what
    json.dumps(ensure_ascii=False) produces). Bool/null/array as usual.
    """
    return _canon(value, 1).encode("utf-8")


def _canon(v, depth) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise FormatError("integer outside +-(2**53-1)")
        return str(v)
    if isinstance(v, float):
        raise FormatError("floats are not allowed in canonical JSON")
    if isinstance(v, str):
        return _canon_str(v)
    if isinstance(v, (list, tuple, dict)) and depth > MAX_DEPTH:
        raise FormatError("nesting deeper than %d levels" % MAX_DEPTH)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_canon(x, depth + 1) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise FormatError("object keys must be strings")
            _check_str(k)
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_canon_str(k) + ":" + _canon(x, depth + 1) for k, x in items) + "}"
    raise FormatError("unsupported type %s" % type(v).__name__)


def _no_dup_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise FormatError("duplicate object key %r" % k)
        d[k] = v
    return d


def _reject_float(s):
    raise FormatError("floats are not allowed (%s)" % s)


def _reject_const(s):
    raise FormatError("non-finite number %s" % s)


def parse_json(text: str):
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_dup_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_const,
        )
    except FormatError:
        raise
    except (ValueError, RecursionError) as exc:
        raise FormatError("invalid JSON: %s" % exc) from exc


# --------------------------------------------------------------- hashing
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def entry_body(entry: dict) -> dict:
    return {k: entry[k] for k in ("v", "chain_id", "seq", "ts", "prev_hash", "event")}


def compute_entry_hash(entry: dict) -> str:
    """entry_hash = SHA-256(ENTRY_DOMAIN || canon(entry without entry_hash))."""
    return sha256(ENTRY_DOMAIN + canon(entry_body(entry))).hex()


# ------------------------------------------------- Merkle tree (RFC 6962)
def leaf_hash(entry_hash_hex: str) -> bytes:
    return sha256(b"\x00" + bytes.fromhex(entry_hash_hex))


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def _largest_pow2_lt(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list) -> bytes:
    """MTH of RFC 6962 section 2.1 over already-hashed leaves."""
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaves[0]
    k = _largest_pow2_lt(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_inclusion_path(leaves: list, index: int) -> list:
    """Audit path PATH(m, D[n]) of RFC 6962 section 2.1.1 (producer side)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if index < k:
        return merkle_inclusion_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return merkle_inclusion_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, path: list, root: bytes) -> bool:
    """RFC 9162 section 2.1.3 inclusion verification (same maths as 6962)."""
    if index < 0 or size <= 0 or index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ------------------------------------------- Ed25519 verify (RFC 8032)
# The point arithmetic below is derived from the Python illustration in
# RFC 8032, Section 6 (S. Josefsson, I. Liusvaara). Please reproduce this note.
# Copyright (c) 2017 IETF Trust and the persons identified as authors of the code.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, is permitted pursuant to, and subject to the license terms
# contained in, the Revised BSD License set forth in Section 4.c of the IETF
# Trust's Legal Provisions Relating to IETF Documents
# (https://trustee.ietf.org/license-info).
# Modifications (renaming, input validation, small-order key rejection,
# fail-closed returns) are Copyright 2026 Orbexs and the agent-custody contributors and
# licensed under Apache-2.0.
_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_IDENT = (0, 1, 1, 0)


def _point_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_mul(s: int, pt):
    q = _IDENT
    while s > 0:
        if s & 1:
            q = _point_add(q, pt)
        pt = _point_add(pt, pt)
        s >>= 1
    return q


def _point_equal(a, b) -> bool:
    if (a[0] * b[2] - b[0] * a[2]) % _P != 0:
        return False
    return (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _compress(pt) -> bytes:
    zinv = pow(pt[2], _P - 2, _P)
    x, y = pt[0] * zinv % _P, pt[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def is_small_order(public: bytes) -> bool:
    """True if `public` does not decode, or decodes to a point of order 1, 2, 4 or 8.

    Such keys make the verification equation hold for many messages (the identity
    point accepts any message), so they are rejected wherever a key is accepted.
    """
    A = _decompress(public)
    return A is None or _point_equal(_point_mul(8, A), _IDENT)


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """RFC 8032 section 5.1.7, plus rejection of small-order public keys.

    Returns False on any malformed input.
    """
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    if A is None or _point_equal(_point_mul(8, A), _IDENT):
        return False
    Rs = signature[:32]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(Rs + public + msg).digest(), "little") % _Q
    return _point_equal(_point_mul(s, _G), _point_add(R, _point_mul(h, A)))


# ------------------------------------- C2SP signed-note checkpoint parsing
def key_id(name: str, pub: bytes) -> bytes:
    """signed-note key hash for Ed25519 (type 0x01): SHA-256(name\\n0x01 pub)[:4]."""
    return sha256(name.encode("utf-8") + b"\n\x01" + pub)[:4]


def make_vkey(name: str, pub: bytes) -> str:
    """Verifier-key string: name+<8 hex key id>+base64(0x01 || pub)."""
    return "%s+%s+%s" % (name, key_id(name, pub).hex(), base64.b64encode(b"\x01" + pub).decode())


def parse_vkey(s: str):
    try:
        name, kid, b64 = s.strip().split("+", 2)  # name has no "+", base64 may
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FormatError("malformed vkey") from exc
    if not name or " " in name or len(raw) != 33 or raw[0] != 1:
        raise FormatError("vkey must be an Ed25519 (type 0x01) key with a non-empty name")
    pub = raw[1:]
    if is_small_order(pub):
        raise FormatError("vkey public key is not a valid Ed25519 key (does not decode or has small order)")
    if kid != key_id(name, pub).hex():
        raise FormatError("vkey key-id does not match name and key")
    return name, pub


def checkpoint_trusted(cp, vkeys) -> bool:
    """True if at least one signature line verifies under a trusted (name, key) pair."""
    for name, kid, sig in cp.sigs:
        for vname, vpub in vkeys:
            if name == vname and kid == key_id(vname, vpub) and ed25519_verify(vpub, cp.text, sig):
                return True
    return False


class Checkpoint:
    def __init__(self, text: bytes, origin: str, size: int, root: bytes, sigs: list):
        self.text = text  # exact signed bytes (3 lines, trailing newline)
        self.origin = origin
        self.size = size
        self.root = root
        self.sigs = sigs  # [(name, key_id4, signature64)]

    @property
    def chain_id(self) -> str:
        return self.origin[len(ORIGIN_PREFIX):]


def parse_checkpoint(data: bytes) -> Checkpoint:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError("checkpoint is not UTF-8") from exc
    if "\n\n" not in s or not s.endswith("\n"):
        raise FormatError("signed note needs a text, a blank line and signature lines")
    text, sigpart = s.split("\n\n", 1)
    text += "\n"
    lines = text.split("\n")[:-1]
    if len(lines) != 3:
        raise FormatError("checkpoint body must have exactly 3 lines (origin, size, root)")
    origin, size_s, root_b64 = lines
    if not re.fullmatch(re.escape(ORIGIN_PREFIX) + r"[0-9a-f]{64}", origin):
        raise FormatError("checkpoint origin must be %s<64 hex chain_id>" % ORIGIN_PREFIX)
    if not re.fullmatch(r"[1-9][0-9]{0,15}", size_s) or int(size_s) > MAX_SAFE_INT:
        raise FormatError("checkpoint size must be a decimal integer in 1..2**53-1 without leading zeros")
    try:
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FormatError("checkpoint root is not base64") from exc
    if len(root) != 32:
        raise FormatError("checkpoint root must be 32 bytes")
    sig_lines = sigpart.split("\n")[:-1]
    if len(sig_lines) > MAX_SIG_LINES:
        raise FormatError("checkpoint has %d signature lines; at most %d are allowed" % (len(sig_lines), MAX_SIG_LINES))
    sigs = []
    for line in sig_lines:
        if not line.startswith(SIG_PREFIX):
            raise FormatError("signature line must start with an em dash and a space")
        try:
            name, b64 = line[len(SIG_PREFIX):].rsplit(" ", 1)
            blob = base64.b64decode(b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise FormatError("malformed signature line") from exc
        if not name or len(blob) < 5:
            raise FormatError("malformed signature line")
        sigs.append((name, blob[:4], blob[4:]))
    if not sigs:
        raise FormatError("checkpoint has no signature lines")
    return Checkpoint(text.encode("utf-8"), origin, int(size_s), root, sigs)


def format_checkpoint(chain_id: str, size: int, root: bytes) -> bytes:
    return ("%s%s\n%d\n%s\n" % (ORIGIN_PREFIX, chain_id, size, base64.b64encode(root).decode())).encode()


# ------------------------------------------------------- event validation
def _is_hex64(v) -> bool:
    return isinstance(v, str) and HEX64.fullmatch(v) is not None


def _is_ts(v) -> bool:
    """YYYY-MM-DDTHH:MM:SSZ, nothing before or after, and a real calendar date and time."""
    if not (isinstance(v, str) and TS_RE.fullmatch(v)):
        return False
    try:
        datetime.strptime(v, TS_FMT)
    except ValueError:
        return False
    return True


def provider_key(name: str) -> str:
    """Provider comparison key (SPEC 6.5): NFC, strip ASCII whitespace, lowercase ASCII A-Z only."""
    s = unicodedata.normalize("NFC", name).strip(" \t\n\r")
    return s.translate(_ASCII_LOWER)


_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def _nonempty_str(v) -> bool:
    return isinstance(v, str) and 0 < len(v) <= MAX_STRING


RISKS = ("low", "medium", "high", "critical")
PHASES = ("requested", "executed", "failed")
ACTOR_KINDS = ("agent", "human", "system")


def _validate_actor(a, where):
    if not (isinstance(a, dict) and a.get("kind") in ACTOR_KINDS and _nonempty_str(a.get("id"))):
        raise FormatError("%s: actor needs kind in %s and id" % (where, ACTOR_KINDS))


def validate_event(event, seq: int, chain_id: str, by_hash: dict, approval_ids=None) -> None:
    """Schema + reference checks. `by_hash` maps entry_hash -> (seq, event) of EARLIER entries.

    `approval_ids` is the set of approval_id values of earlier entries; when it is None it is
    recomputed from `by_hash`. approval_id MUST be unique within a chain (SPEC 6.4).
    """
    if not isinstance(event, dict) or not isinstance(event.get("type"), str):
        raise FormatError("event must be an object with a string 'type'")
    t = event["type"]
    w = "seq %d (%s)" % (seq, t)

    def ref(key, types=None, phase=None):
        h = event.get(key)
        if not _is_hex64(h):
            raise FormatError("%s: %s must be a 64-hex entry hash" % (w, key))
        if h not in by_hash:
            raise FormatError("%s: %s does not reference an earlier entry" % (w, key))
        ev = by_hash[h][1]
        if types and ev.get("type") not in types:
            raise FormatError("%s: %s must reference an event of type %s" % (w, key, types))
        if phase and ev.get("phase") != phase:
            raise FormatError("%s: %s must reference a phase=%s action" % (w, key, phase))
        return ev

    if t == "chain_open":
        if seq != 0:
            raise FormatError("%s: chain_open is only allowed at seq 0" % w)
        if event.get("chain_id") != chain_id:
            raise FormatError("%s: chain_open.chain_id differs from entry chain_id" % w)
        if event.get("spec") != SPEC_VERSION:
            raise FormatError("%s: unsupported spec %r (this verifier speaks %s)" % (w, event.get("spec"), SPEC_VERSION))
        ag = event.get("agent")
        if not (isinstance(ag, dict) and _nonempty_str(ag.get("id"))):
            raise FormatError("%s: agent.id required" % w)
    elif seq == 0:
        raise FormatError("%s: the first entry must be chain_open" % w)
    elif t == "action":
        if not _nonempty_str(event.get("action_id")):
            raise FormatError("%s: action_id required" % w)
        if event.get("phase") not in PHASES:
            raise FormatError("%s: phase must be one of %s" % (w, PHASES))
        _validate_actor(event.get("actor"), w)
        for k in ("tool", "summary"):
            if not _nonempty_str(event.get(k)):
                raise FormatError("%s: %s required" % (w, k))
        if event.get("risk") not in RISKS:
            raise FormatError("%s: risk must be one of %s" % (w, RISKS))
        for k in ("input_digest", "result_digest"):
            if k in event and not _is_hex64(event[k]):
                raise FormatError("%s: %s must be 64-hex" % (w, k))
        if event["phase"] == "requested":
            if not isinstance(event.get("requires_approval"), bool):
                raise FormatError("%s: requires_approval (bool) required on phase=requested" % w)
        else:
            req = ref("request_entry_hash", types=("action",), phase="requested")
            if req.get("action_id") != event["action_id"]:
                raise FormatError("%s: request_entry_hash references a different action_id" % w)
    elif t == "decision":
        if not _nonempty_str(event.get("decision_id")):
            raise FormatError("%s: decision_id required" % w)
        ref("subject_entry_hash", types=("action",), phase="requested")
        if event.get("outcome") not in ("allow", "deny", "escalate"):
            raise FormatError("%s: outcome must be allow|deny|escalate" % w)
        if event.get("basis") not in ("policy", "model", "human"):
            raise FormatError("%s: basis must be policy|model|human" % w)
        _validate_actor(event.get("actor"), w)
    elif t == "human_approval":
        if not _nonempty_str(event.get("approval_id")):
            raise FormatError("%s: approval_id required" % w)
        if approval_ids is None:
            approval_ids = {ev.get("approval_id") for _, ev in by_hash.values() if ev.get("type") == "human_approval"}
        if event["approval_id"] in approval_ids:
            raise FormatError("%s: approval_id %r is already used earlier in this chain (replayed or duplicated approval)" % (w, event["approval_id"]))
        ref("subject_entry_hash", types=("action",), phase="requested")
        if event.get("outcome") not in ("approved", "rejected"):
            raise FormatError("%s: outcome must be approved|rejected" % w)
        ap = event.get("approver")
        if not (isinstance(ap, dict) and _nonempty_str(ap.get("id")) and _nonempty_str(ap.get("method"))):
            raise FormatError("%s: approver needs id and method" % w)
        if not _is_hex64(event.get("presented_digest")):
            raise FormatError("%s: presented_digest (64-hex) required" % w)
        if "expires_at" in event and not _is_ts(event["expires_at"]):
            raise FormatError("%s: expires_at must be a real UTC time written YYYY-MM-DDTHH:MM:SSZ" % w)
        if "approver_signature" in event:
            sg = event["approver_signature"]
            if not (isinstance(sg, dict) and _is_hex64(sg.get("public_key")) and isinstance(sg.get("signature"), str) and HEX128.fullmatch(sg["signature"])):
                raise FormatError("%s: approver_signature needs public_key (64 hex) and signature (128 hex)" % w)
    elif t == "cross_verification":
        if not _nonempty_str(event.get("verification_id")):
            raise FormatError("%s: verification_id required" % w)
        ref("subject_entry_hash")
        au = event.get("author")
        if not (isinstance(au, dict) and _nonempty_str(au.get("provider")) and _nonempty_str(au.get("model"))):
            raise FormatError("%s: author needs provider and model" % w)
        rv = event.get("reviewers")
        if not (isinstance(rv, list) and rv):
            raise FormatError("%s: reviewers must be a non-empty list" % w)
        for r in rv:
            if not (isinstance(r, dict) and _nonempty_str(r.get("provider")) and _nonempty_str(r.get("model"))
                    and r.get("verdict") in ("agree", "disagree", "inconclusive")):
                raise FormatError("%s: each reviewer needs provider, model and verdict in agree|disagree|inconclusive" % w)
            if "findings_digest" in r and not _is_hex64(r["findings_digest"]):
                raise FormatError("%s: findings_digest must be 64-hex" % w)
            if "finding_count" in r and not (isinstance(r["finding_count"], int) and not isinstance(r["finding_count"], bool) and r["finding_count"] >= 0):
                raise FormatError("%s: finding_count must be a non-negative integer" % w)
        if not isinstance(event.get("cross_provider"), bool):
            raise FormatError("%s: cross_provider (bool) required" % w)
        actual = any(provider_key(r["provider"]) != provider_key(au["provider"]) for r in rv)
        if event["cross_provider"] != actual:
            raise FormatError("%s: cross_provider=%s contradicts the recorded providers (recomputed: %s)" % (w, event["cross_provider"], actual))
    elif t.startswith("x-"):
        pass  # vendor extension: opaque, still hashed and chained
    else:
        raise FormatError("%s: unknown event type (extensions must be prefixed 'x-')" % w)


def approval_message(chain_id: str, ev: dict) -> bytes:
    """Bytes the approver signs (SPEC 6.4): every member the approval gate relies on."""
    stmt = {
        "chain_id": chain_id,
        "approval_id": ev["approval_id"],
        "subject_entry_hash": ev["subject_entry_hash"],
        "outcome": ev["outcome"],
        "presented_digest": ev["presented_digest"],
        "approver_id": ev["approver"]["id"],
        "approver_method": ev["approver"]["method"],
        "expires_at": ev.get("expires_at"),
    }
    return APPROVAL_DOMAIN + canon(stmt)


# ------------------------------------------------------------- reporting
class Report:
    def __init__(self):
        self.layers = {name: [NOT_CHECKED, "not evaluated"] for name in LAYERS}
        self.info = {}
        self.warnings = []

    def set(self, layer, state, detail):
        self.layers[layer] = [state, detail]

    @property
    def failed(self):
        return [n for n, (s, _) in self.layers.items() if s == FAIL]

    @property
    def overall(self):
        if self.failed:
            return "fail"
        if all(s == OK for s, _ in self.layers.values()):
            return "ok_all_layers"
        return "ok_partial"

    def to_dict(self):
        return {
            "verifier": "agent-custody-verify %s" % __version__,
            "overall": self.overall,
            "layers": {n: {"state": s, "detail": d} for n, (s, d) in self.layers.items()},
            "info": self.info,
            "warnings": self.warnings,
        }

    def render(self) -> str:
        out = []
        for n in LAYERS:
            s, d = self.layers[n]
            out.append("[%-11s] %-20s %s" % (s, n, d))
        for w in self.warnings:
            out.append("[warning    ] %s" % w)
        if self.info:
            out.append("")
            for k, v in self.info.items():
                out.append("  %s: %s" % (k, v))
        out.append("")
        n_ok = sum(1 for s, _ in self.layers.values() if s == OK)
        if self.failed:
            out.append("RESULT: FAIL - failed layers: %s" % ", ".join(self.failed))
        else:
            skipped = len(LAYERS) - n_ok
            out.append(
                "RESULT: NO INCONSISTENCY FOUND in the %d layer(s) that passed; %d layer(s) not checked or unavailable. "
                "This is not proof of authenticity, correctness or that the host was uncompromised (see LIMITS.md)."
                % (n_ok, skipped)
            )
        return "\n".join(out)


# ------------------------------------------------------- log verification
def _read_bytes(path, max_bytes=MAX_INPUT_BYTES) -> bytes:
    with open(path, "rb") as f:
        raw = f.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise FormatError("%s is larger than the input limit of %d bytes (--max-bytes)" % (path, max_bytes))
    return raw


def _read_text(path, max_bytes=MAX_INPUT_BYTES) -> str:
    raw = _read_bytes(path, max_bytes)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError("%s is not UTF-8" % path) from exc


def load_log(path, max_bytes=MAX_INPUT_BYTES):
    """Parse a JSONL log. Returns list of entry dicts. Raises FormatError."""
    text = _read_text(path, max_bytes)
    if text.startswith("\ufeff"):
        raise FormatError("BOM not allowed")
    if not text:
        raise FormatError("log is empty")
    if not text.endswith("\n"):
        raise FormatError("the last line is not terminated by \\n (incomplete write or truncated file)")
    entries = []
    lines = text[:-1].split("\n")
    for i, line in enumerate(lines, 1):
        if line.endswith("\r"):
            raise FormatError("line %d: CRLF line ending (lines end with \\n only)" % i)
        if not line.strip():
            raise FormatError("line %d: blank line" % i)
        entries.append(validate_entry_fields(parse_json(line), "line %d" % i))
    return entries


ENTRY_MEMBERS = {"v", "chain_id", "seq", "ts", "prev_hash", "event", "entry_hash"}


def validate_entry_fields(obj, where):
    """Entry-level format rules of SPEC section 4 (exact member set, types, formats, limits). Returns obj."""
    if not isinstance(obj, dict):
        raise FormatError("%s: entry must be a JSON object" % where)
    if set(obj) != ENTRY_MEMBERS:
        raise FormatError("%s: fields must be exactly %s (members outside the hash are not allowed)" % (where, sorted(ENTRY_MEMBERS)))
    if obj["v"] != 1 or isinstance(obj["v"], bool):
        raise FormatError("%s: unsupported entry version %r (this verifier speaks v=1)" % (where, obj["v"]))
    if not _is_hex64(obj["chain_id"]):
        raise FormatError("%s: chain_id must be 64 lowercase hex" % where)
    if not isinstance(obj["seq"], int) or isinstance(obj["seq"], bool) or not 0 <= obj["seq"] <= MAX_SAFE_INT:
        raise FormatError("%s: seq must be an integer in 0..2**53-1" % where)
    if not _is_ts(obj["ts"]):
        raise FormatError("%s: ts must be a real UTC time written YYYY-MM-DDTHH:MM:SSZ" % where)
    if not (_is_hex64(obj["prev_hash"]) and _is_hex64(obj["entry_hash"])):
        raise FormatError("%s: prev_hash/entry_hash must be 64 lowercase hex" % where)
    if not isinstance(obj["event"], dict):
        raise FormatError("%s: event must be a JSON object" % where)
    canon(entry_body(obj))  # raises on floats, out-of-range ints, lone surrogates, excessive nesting
    return obj


def _check_entry_hashes(entries):
    bad = [e["seq"] for e in entries if compute_entry_hash(e) != e["entry_hash"]]
    return bad


def _check_chain(entries):
    problems = []
    chain_id = entries[0]["chain_id"]
    prev = ZERO_HASH
    for i, e in enumerate(entries):
        if e["seq"] != i:
            problems.append("position %d carries seq %d (gap, reorder or duplicate)" % (i, e["seq"]))
        if e["chain_id"] != chain_id:
            problems.append("seq %d belongs to a different chain_id (transplanted entry)" % e["seq"])
        if e["prev_hash"] != prev:
            problems.append("seq %d prev_hash does not match the previous entry_hash" % e["seq"])
        prev = e["entry_hash"]
    return problems


def _check_events(entries):
    by_hash = {}
    approval_ids = set()
    chain_id = entries[0]["chain_id"]
    for e in entries:
        validate_event(e["event"], e["seq"], chain_id, by_hash, approval_ids)
        by_hash[e["entry_hash"]] = (e["seq"], e["event"])
        if e["event"]["type"] == "human_approval":
            approval_ids.add(e["event"]["approval_id"])
    return by_hash


def _check_gate(entries):
    """Recorded-order policy check (SPEC 6.6) over execution attempts (phase executed or failed).

    An 'approved' human_approval authorises exactly ONE execution attempt of its request.
    A 'deny' decision is lifted only by a later human approval, never by a later decision.
    Returns (attempts that require approval, attempts checked against an earlier deny).
    """
    by_hash = {e["entry_hash"]: e for e in entries}
    approvals, decisions = {}, {}  # request entry_hash -> entries so far, in order
    used = set()  # approval_ids already consumed by an attempt
    gated = lifted = 0
    for e in entries:
        ev = e["event"]
        if ev["type"] == "human_approval":
            approvals.setdefault(ev["subject_entry_hash"], []).append(e)
            continue
        if ev["type"] == "decision":
            decisions.setdefault(ev["subject_entry_hash"], []).append(e)
            continue
        if ev["type"] != "action" or ev["phase"] == "requested":
            continue
        verb = "executed" if ev["phase"] == "executed" else "attempted (phase=failed)"
        req = by_hash[ev["request_entry_hash"]]
        rh = req["entry_hash"]
        aps, ds = approvals.get(rh, []), decisions.get(rh, [])
        denies = [d["seq"] for d in ds if d["event"]["outcome"] == "deny"]
        if denies:
            after = [a for a in aps if a["seq"] > denies[-1]]
            if not after:
                raise FormatError("seq %d %s an action after a 'deny' decision (seq %d) with no later human_approval; "
                                  "a later decision does not lift a deny" % (e["seq"], verb, denies[-1]))
            lift = after[-1]["event"]
            if lift["outcome"] != "approved":
                raise FormatError("seq %d %s an action after a 'deny' decision (seq %d) whose latest later human_approval was 'rejected'"
                                  % (e["seq"], verb, denies[-1]))
            if "expires_at" in lift and e["ts"] > lift["expires_at"]:
                raise FormatError("seq %d %s after the approval that lifted the deny expired (host clock)" % (e["seq"], verb))
            lifted += 1
        if not req["event"]["requires_approval"]:
            continue
        gated += 1
        if not aps:
            raise FormatError("seq %d %s action %r that requires approval with no earlier human_approval" % (e["seq"], verb, ev["action_id"]))
        last = aps[-1]["event"]
        if last["outcome"] != "approved":
            raise FormatError("seq %d %s after the latest human_approval was 'rejected'" % (e["seq"], verb))
        if "expires_at" in last and e["ts"] > last["expires_at"]:
            raise FormatError("seq %d %s after the approval expired (host clock)" % (e["seq"], verb))
        if last["approval_id"] in used:
            raise FormatError("seq %d %s again under approval %r, which already authorised an earlier attempt (one approval, one attempt)" % (e["seq"], verb, last["approval_id"]))
        used.add(last["approval_id"])
    return gated, lifted


def _check_approver_sigs(entries, pinned):
    chain_id = entries[0]["chain_id"]
    approvals = [e for e in entries if e["event"]["type"] == "human_approval"]
    if not approvals:
        return NOT_CHECKED, "no human_approval entries in this log"
    n_valid = n_unsigned = n_unpinned = 0
    for e in approvals:
        ev = e["event"]
        aid = ev["approver"]["id"]
        sig = ev.get("approver_signature")
        if sig is None:
            if aid in pinned:
                return FAIL, "seq %d: approver %r has a pinned key but the approval is unsigned" % (e["seq"], aid)
            n_unsigned += 1
            continue
        if aid in pinned and pinned[aid] != sig["public_key"]:
            return FAIL, "seq %d: approval signed with a key different from the pinned key for %r" % (e["seq"], aid)
        if not ed25519_verify(bytes.fromhex(sig["public_key"]), approval_message(chain_id, ev), bytes.fromhex(sig["signature"])):
            return FAIL, "seq %d: approver signature does not verify" % e["seq"]
        n_valid += 1
        if aid not in pinned:
            n_unpinned += 1
    if n_unsigned or n_unpinned:
        return NOT_CHECKED, (
            "%d signature(s) verify under the key embedded in the log, %d approval(s) unsigned; "
            "%d approver key(s) not pinned (--approver-key), so key-to-person binding is NOT established"
            % (n_valid, n_unsigned, n_unpinned)
        )
    return OK, "%d approval(s) signed; every approver key pinned by the caller" % n_valid


def _check_checkpoints(rep, entries, cps, vkeys):
    leaves = [leaf_hash(e["entry_hash"]) for e in entries]
    chain_id = entries[0]["chain_id"]
    n = len(entries)
    root_msgs, root_bad = [], []
    best_signed = 0
    sig_msgs, sig_bad = [], []
    sig_unchecked = False
    for cp in cps:
        tag = "checkpoint(size=%d)" % cp.size
        # --- root layer
        ok_root = True
        if cp.chain_id != chain_id:
            root_bad.append("%s is for a different chain (origin mismatch)" % tag)
            ok_root = False
        elif cp.size > n:
            root_bad.append("%s covers %d entries but the log has only %d (truncated or incomplete log)" % (tag, cp.size, n))
            ok_root = False
        elif merkle_root(leaves[: cp.size]) != cp.root:
            root_bad.append("%s root differs from the root recomputed over the first %d entries" % (tag, cp.size))
            ok_root = False
        else:
            root_msgs.append("%s matches the log" % tag)
        # --- signature layer
        if not vkeys:
            sig_unchecked = True
            continue
        good = False
        matched = False
        for name, kid, sig in cp.sigs:
            for vname, vpub in vkeys:
                if name == vname and kid == key_id(vname, vpub):
                    matched = True
                    if ed25519_verify(vpub, cp.text, sig):
                        good = True
                        sig_msgs.append("%s signed by trusted key %r" % (tag, vname))
                    else:
                        sig_bad.append("%s: signature by %r does not verify" % (tag, vname))
        if not matched:
            sig_bad.append("%s carries no signature from any trusted key (unknown keys are ignored per signed-note)" % tag)
        elif good and ok_root:
            best_signed = max(best_signed, cp.size)
    if root_bad:
        rep.set("checkpoint_root", FAIL, "; ".join(root_bad))
    else:
        rep.set("checkpoint_root", OK, "; ".join(root_msgs))
    if sig_bad:
        rep.set("checkpoint_signature", FAIL, "; ".join(sig_bad))
    elif sig_unchecked:
        rep.set("checkpoint_signature", NOT_CHECKED, "no trusted --vkey supplied; a key shipped next to the log must not be trusted, so signatures were not verified")
    else:
        rep.set("checkpoint_signature", OK, "; ".join(sig_msgs))
    if best_signed:
        rep.info["signed_through_seq"] = best_signed - 1
        rep.info["unsigned_tail_entries"] = n - best_signed
        if n > best_signed:
            rep.warnings.append("%d trailing entr%s after the last verified checkpoint carry no signature; they are not covered" % (n - best_signed, "y" if n - best_signed == 1 else "ies"))


# -------------------------------------------------------- timestamp files
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_BTC_TAG = bytes.fromhex("0588960d73d71901")
OTS_PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")


def _check_timestamp(rep, cps, ots_path, tsr_path, max_bytes=MAX_INPUT_BYTES):
    if not ots_path and not tsr_path:
        rep.set("timestamp", NOT_CHECKED, "no .ots/.tsr supplied; nothing here says WHEN this log existed (entry ts values are the host's own clock)")
        return
    if not cps:
        rep.set("timestamp", NOT_CHECKED, "a timestamp file needs a checkpoint to bind to; none supplied")
        return
    cp = cps[-1]
    digest = sha256(cp.text)
    msgs, bad = [], []
    state = UNAVAILABLE
    if ots_path:
        try:
            raw = _read_bytes(ots_path, max_bytes)
        except FormatError as exc:
            rep.set("timestamp", FAIL, str(exc))
            return
        if not raw.startswith(OTS_MAGIC) or len(raw) < len(OTS_MAGIC) + 2 + 32 or raw[len(OTS_MAGIC) + 1] != 0x08:
            bad.append("%s is not an OpenTimestamps proof over a SHA-256 digest" % "ots file")
        else:
            got = raw[len(OTS_MAGIC) + 2: len(OTS_MAGIC) + 34]
            if got != digest:
                bad.append("ots file stamps a different digest than SHA-256 of the last checkpoint text")
            else:
                has_btc = OTS_BTC_TAG in raw[len(OTS_MAGIC) + 34:]
                msgs.append(
                    "ots digest matches the last checkpoint; %s - Bitcoin attestation NOT verified here, run `ots verify`"
                    % ("a Bitcoin attestation tag is present" if has_btc else "only pending/other attestations visible")
                )
    if tsr_path:
        msgs.append("RFC 3161 token supplied; not verified by this verifier, run `openssl ts -verify`")
    if bad:
        rep.set("timestamp", FAIL, "; ".join(bad))
    else:
        rep.set("timestamp", state, "; ".join(msgs))


# ------------------------------------------------------------ proof mode
def _check_proof(rep, proof_path, entry_path, cps, vkeys, entries, max_bytes=MAX_INPUT_BYTES):
    try:
        pr = parse_json(_read_text(proof_path, max_bytes))
        want = {"v", "chain_id", "leaf_index", "tree_size", "entry_hash", "audit_path"}
        if not isinstance(pr, dict) or set(pr) != want or type(pr["v"]) is not int or pr["v"] != 1:
            raise FormatError("proof must be an object with exactly %s and v=1 (an integer)" % sorted(want))
        if not (_is_hex64(pr["chain_id"]) and _is_hex64(pr["entry_hash"])):
            raise FormatError("proof chain_id/entry_hash must be 64-hex")
        for k in ("leaf_index", "tree_size"):
            if type(pr[k]) is not int or not 0 <= pr[k] <= MAX_SAFE_INT:
                raise FormatError("proof %s must be an integer in 0..2**53-1" % k)
        if not (isinstance(pr["audit_path"], list) and all(_is_hex64(h) for h in pr["audit_path"])):
            raise FormatError("audit_path must be a list of 64-hex hashes")
    except (FormatError, OSError) as exc:
        rep.set("inclusion_proof", FAIL, "proof file unusable: %s" % exc)
        return
    if not cps:
        rep.set("inclusion_proof", NOT_CHECKED, "a proof is relative to a checkpoint; none supplied")
        return
    cp = cps[-1]
    if cp.chain_id != pr["chain_id"]:
        rep.set("inclusion_proof", FAIL, "proof and checkpoint are for different chains")
        return
    if cp.size != pr["tree_size"]:
        rep.set("inclusion_proof", FAIL, "proof tree_size %d != checkpoint size %d" % (pr["tree_size"], cp.size))
        return
    if entry_path:
        try:
            ent = validate_entry_fields(parse_json(_read_text(entry_path, max_bytes)), "disclosed entry")
            if ent["chain_id"] != pr["chain_id"] or ent["seq"] != pr["leaf_index"]:
                raise FormatError("entry does not match proof chain_id/leaf_index")
            if compute_entry_hash(ent) != ent.get("entry_hash") or ent["entry_hash"] != pr["entry_hash"]:
                raise FormatError("entry content does not hash to the proven entry_hash")
        except (FormatError, KeyError, OSError) as exc:
            rep.set("inclusion_proof", FAIL, "entry check failed: %s" % exc)
            return
    elif entries is not None:
        match = [e for e in entries if e["seq"] == pr["leaf_index"]]
        if not match or match[0]["entry_hash"] != pr["entry_hash"]:
            rep.set("inclusion_proof", FAIL, "proof entry_hash differs from the log entry at that index")
            return
    ok = verify_inclusion(leaf_hash(pr["entry_hash"]), pr["leaf_index"], pr["tree_size"], [bytes.fromhex(h) for h in pr["audit_path"]], cp.root)
    if not ok:
        rep.set("inclusion_proof", FAIL, "audit path does not reconstruct the checkpoint root")
    elif not checkpoint_trusted(cp, vkeys):
        rep.set("inclusion_proof", NOT_CHECKED,
                "audit path reconstructs the root of a checkpoint that no trusted --vkey signed; that size and root are "
                "unauthenticated, so inclusion is NOT established")
    else:
        extra = " (entry content hashed and matched)" if entry_path else " (entry content not supplied: proves the HASH is in the tree, not what the entry says)"
        rep.set("inclusion_proof", OK, "entry_hash at index %d is included in checkpoint of size %d, signed by a trusted key%s" % (pr["leaf_index"], pr["tree_size"], extra))


# ------------------------------------------------------------ entry point
def verify(log_path=None, checkpoints=(), vkeys=(), approver_keys=(), ots_path=None, tsr_path=None, proof_path=None, entry_path=None,
           max_bytes=MAX_INPUT_BYTES) -> Report:
    rep = Report()
    cps = []
    parsed_vkeys = []
    entries = None
    try:
        for v in vkeys:
            parsed_vkeys.append(parse_vkey(v))
    except FormatError as exc:
        raise ValueError("bad --vkey: %s" % exc)
    pinned = {}
    for spec in approver_keys:
        if "=" not in spec or not HEX64.fullmatch(spec.split("=", 1)[1]):
            raise ValueError("bad --approver-key (want ID=<64 hex>): %r" % spec)
        i, k = spec.split("=", 1)
        if is_small_order(bytes.fromhex(k)):
            raise ValueError("bad --approver-key %r: not a valid Ed25519 public key (does not decode or has small order)" % i)
        pinned[i] = k

    cp_errors = []
    for p in checkpoints:
        try:
            cps.append(parse_checkpoint(_read_bytes(p, max_bytes)))
        except FormatError as exc:
            cp_errors.append("%s: %s" % (p, exc))

    if log_path:
        try:
            entries = load_log(log_path, max_bytes)
            rep.set("format", OK, "%d entries parsed; v=1; strict JSON (no duplicate keys, no floats)" % len(entries))
            rep.info["entries"] = len(entries)
            rep.info["chain_id"] = entries[0]["chain_id"]
        except (FormatError, OSError) as exc:
            rep.set("format", FAIL, str(exc))
    else:
        rep.set("format", NOT_CHECKED, "no log supplied (proof-only mode)")

    if cp_errors:
        for layer in ("checkpoint_root", "checkpoint_signature"):
            rep.set(layer, FAIL, "; ".join(cp_errors))
        cps = []

    if entries:
        bad = _check_entry_hashes(entries)
        if bad:
            rep.set("entry_hashes", FAIL, "entry_hash does not match content at seq %s" % ", ".join(map(str, bad[:10])))
        else:
            rep.set("entry_hashes", OK, "all %d entry_hash values recompute" % len(entries))
        probs = _check_chain(entries)
        if probs:
            rep.set("chain_links", FAIL, "; ".join(probs[:5]))
        else:
            rep.set("chain_links", OK, "seq contiguous from 0, prev_hash links, one chain_id, genesis at seq 0")
        by_hash = None
        try:
            by_hash = _check_events(entries)
            rep.set("events", OK, "event schemas and cross-references valid (types: %s)" % ", ".join(sorted({e["event"]["type"] for e in entries})))
        except FormatError as exc:
            rep.set("events", FAIL, str(exc))
        if by_hash is not None:
            try:
                g, lifted = _check_gate(entries)
                if g or lifted:
                    rep.set("approval_gate", OK, "%d execution attempt(s) requiring approval each have their own earlier, unexpired 'approved' "
                            "human_approval; %d attempt(s) after a 'deny' each follow a later 'approved' human_approval "
                            "(recorded order only)" % (g, lifted))
                else:
                    rep.set("approval_gate", NOT_CHECKED, "no execution attempt that requires approval or follows a 'deny' in this log")
            except FormatError as exc:
                rep.set("approval_gate", FAIL, str(exc))
            st, detail = _check_approver_sigs(entries, pinned)
            rep.set("approver_signatures", st, detail)
        else:
            rep.set("approval_gate", NOT_CHECKED, "skipped: events layer failed")
            rep.set("approver_signatures", NOT_CHECKED, "skipped: events layer failed")
        ts = [e["ts"] for e in entries]
        if any(b < a for a, b in zip(ts, ts[1:])):
            rep.warnings.append("entry timestamps are not monotonic (host clock moved backwards, or entries were edited)")
        if cps:
            _check_checkpoints(rep, entries, cps, parsed_vkeys)
        elif not cp_errors:
            rep.set("checkpoint_root", NOT_CHECKED, "no checkpoint supplied: truncation or a full rewrite of this log cannot be detected")
            rep.set("checkpoint_signature", NOT_CHECKED, "no checkpoint supplied")
    elif log_path is None:
        for layer in ("entry_hashes", "chain_links", "events", "approval_gate", "approver_signatures"):
            rep.set(layer, NOT_CHECKED, "no log supplied")
        if cps:
            sig_msgs, sig_bad = [], []
            for cp in cps:
                matched = good = False
                for name, kid, sig in cp.sigs:
                    for vname, vpub in parsed_vkeys:
                        if name == vname and kid == key_id(vname, vpub):
                            matched = True
                            if ed25519_verify(vpub, cp.text, sig):
                                good = True
                if not parsed_vkeys:
                    sig_msgs = None
                    break
                (sig_msgs if good else sig_bad).append("checkpoint(size=%d)" % cp.size)
            if sig_msgs is None:
                rep.set("checkpoint_signature", NOT_CHECKED, "no trusted --vkey supplied")
            elif sig_bad:
                rep.set("checkpoint_signature", FAIL, "no valid signature from a trusted key on %s" % ", ".join(sig_bad))
            else:
                rep.set("checkpoint_signature", OK, "signed by trusted key: %s" % ", ".join(sig_msgs))
            rep.set("checkpoint_root", NOT_CHECKED, "no log supplied to recompute the root from")
        elif not cp_errors:
            rep.set("checkpoint_root", NOT_CHECKED, "no checkpoint supplied")
            rep.set("checkpoint_signature", NOT_CHECKED, "no checkpoint supplied")
    else:
        for layer in ("entry_hashes", "chain_links", "events", "approval_gate", "approver_signatures", "checkpoint_root", "checkpoint_signature"):
            if rep.layers[layer][0] == NOT_CHECKED and layer not in ("checkpoint_root", "checkpoint_signature"):
                rep.set(layer, NOT_CHECKED, "skipped: log did not parse")
        if cps:
            rep.set("checkpoint_root", NOT_CHECKED, "skipped: log did not parse")
            rep.set("checkpoint_signature", NOT_CHECKED, "skipped: log did not parse")

    if proof_path:
        _check_proof(rep, proof_path, entry_path, cps, parsed_vkeys, entries, max_bytes)
    else:
        rep.set("inclusion_proof", NOT_CHECKED, "no --proof supplied")

    _check_timestamp(rep, cps, ots_path, tsr_path, max_bytes)
    return rep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent_custody_verify", description="Layered verifier for agent-custody logs (stdlib only).")
    ap.add_argument("log", nargs="?", help="custody log (JSONL)")
    ap.add_argument("--checkpoint", action="append", default=[], help="C2SP signed-note checkpoint (repeatable)")
    ap.add_argument("--vkey", action="append", default=[], help="trusted checkpoint key: name+keyid+base64 (obtain out of band)")
    ap.add_argument("--approver-key", action="append", default=[], help="pin an approver key: ID=<64 hex Ed25519 public key>")
    ap.add_argument("--ots", help="OpenTimestamps proof for the last checkpoint")
    ap.add_argument("--tsr", help="RFC 3161 timestamp response for the last checkpoint")
    ap.add_argument("--proof", help="RFC 6962 inclusion proof (JSON)")
    ap.add_argument("--entry", help="full entry JSON that the proof refers to")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--require", default="", help="comma-separated layers that must be 'ok' (else exit 3)")
    ap.add_argument("--max-bytes", type=int, default=MAX_INPUT_BYTES, help="size limit per input file (default %(default)s); larger files fail the layer that reads them")
    ap.add_argument("--version", action="version", version="agent-custody-verify " + __version__)
    a = ap.parse_args(argv)
    if not a.log and not a.proof:
        ap.print_usage(sys.stderr)
        print("error: give a log file or --proof", file=sys.stderr)
        return 2
    req = [x for x in a.require.split(",") if x]
    unknown = [x for x in req if x not in LAYERS]
    if unknown:
        print("error: unknown layer(s) in --require: %s (known: %s)" % (", ".join(unknown), ", ".join(LAYERS)), file=sys.stderr)
        return 2
    try:
        rep = verify(a.log, a.checkpoint, a.vkey, a.approver_key, a.ots, a.tsr, a.proof, a.entry, a.max_bytes)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(rep.to_dict(), indent=2, sort_keys=True))
    else:
        print("agent-custody-verify %s  (spec %s)" % (__version__, SPEC_VERSION))
        print(rep.render())
    if rep.failed:
        return 1
    if any(rep.layers[l][0] != OK for l in req):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
