# Copyright 2026 Orbexs and the agent-custody contributors
# SPDX-License-Identifier: Apache-2.0
"""Known-answer and property tests for the cryptographic building blocks.

The Merkle and Ed25519 expectations come from outside this repository
(RFC 8032 test vectors; the well-known Certificate Transparency test tree)
or from a deliberately naive re-implementation, so the verifier is not
checked only against itself.
"""
import ast
import base64
import hashlib
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "verifier"))
sys.path.insert(0, os.path.join(ROOT, "writer"))
import agent_custody_verify as v  # noqa: E402
import agent_custody_write as w  # noqa: E402

# RFC 8032 section 7.1, TEST 1 and TEST 2
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]

# Certificate Transparency reference tree: leaf inputs and expected roots for sizes 1..8.
# Source: RFC 6962 reference test tree as used in google/certificate-transparency and
# transparency-dev/merkle test data (Apache-2.0).
CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def naive_mth(leaves):
    """RFC 6962 section 2.1, transcribed literally (split at largest power of two < n)."""
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = 1
    while k < n:
        k <<= 1
    k >>= 1
    return hashlib.sha256(b"\x01" + naive_mth(leaves[:k]) + naive_mth(leaves[k:])).digest()


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for seed, pub, msg, sig in RFC8032:
            seed, pub, msg, sig = (bytes.fromhex(x) for x in (seed, pub, msg, sig))
            self.assertTrue(v.ed25519_verify(pub, msg, sig))
            self.assertEqual(w.ed25519_public(seed), pub)
            self.assertEqual(w.ed25519_sign_pure(seed, msg), sig)

    def test_rejects_tampering(self):
        seed, pub, msg, sig = (bytes.fromhex(x) for x in RFC8032[1])
        self.assertFalse(v.ed25519_verify(pub, msg + b"x", sig))
        self.assertFalse(v.ed25519_verify(pub, b"", sig))
        for i in (0, 31, 32, 63):
            bad = bytearray(sig)
            bad[i] ^= 0x01
            self.assertFalse(v.ed25519_verify(pub, msg, bytes(bad)), i)
        other = w.ed25519_public(hashlib.sha256(b"x").digest())
        self.assertFalse(v.ed25519_verify(other, msg, sig))

    def test_rejects_malformed_inputs(self):
        _, pub, msg, sig = (bytes.fromhex(x) for x in RFC8032[0])
        self.assertFalse(v.ed25519_verify(pub[:31], msg, sig))
        self.assertFalse(v.ed25519_verify(pub, msg, sig[:63]))
        # s >= q (malleability) must be rejected
        s = int.from_bytes(sig[32:], "little") + v._Q
        self.assertFalse(v.ed25519_verify(pub, msg, sig[:32] + (s % 2**256).to_bytes(32, "little")))
        self.assertFalse(v.ed25519_verify(b"\xff" * 32, msg, sig))

    def test_cross_check_with_cryptography_if_installed(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest("cryptography not installed (optional cross-check)")
        for i in range(5):
            seed = hashlib.sha256(b"xcheck%d" % i).digest()
            msg = b"message %d" % i
            key = Ed25519PrivateKey.from_private_bytes(seed)
            pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(pub, w.ed25519_public(seed))
            self.assertTrue(v.ed25519_verify(pub, msg, key.sign(msg)))
            self.assertEqual(w.ed25519_sign_pure(seed, msg), key.sign(msg))


class MerkleTests(unittest.TestCase):
    def test_ct_reference_roots(self):
        leaves = [hashlib.sha256(b"\x00" + bytes.fromhex(x)).digest() for x in CT_LEAVES]
        for n, want in enumerate(CT_ROOTS, 1):
            self.assertEqual(v.merkle_root(leaves[:n]).hex(), want, n)

    def test_matches_naive_for_many_sizes(self):
        for n in range(1, 70):
            leaves = [hashlib.sha256(b"\x00" + bytes([i])).digest() for i in range(n)]
            self.assertEqual(v.merkle_root(leaves), naive_mth(leaves), n)

    def test_empty_tree_is_sha256_of_empty_string(self):
        self.assertEqual(v.merkle_root([]), hashlib.sha256(b"").digest())

    def test_inclusion_proofs_all_positions(self):
        for n in range(1, 41):
            leaves = [hashlib.sha256(b"\x00" + bytes([i])).digest() for i in range(n)]
            root = v.merkle_root(leaves)
            for i in range(n):
                path = v.merkle_inclusion_path(leaves, i)
                self.assertTrue(v.verify_inclusion(leaves[i], i, n, path, root), (n, i))
                # wrong index / size / leaf / path must all fail
                if n > 1:
                    self.assertFalse(v.verify_inclusion(leaves[i], (i + 1) % n, n, path, root) and (i + 1) % n != i)
                # NB: the same path can verify for some other `size` against the same root hash; that is inherent
                # to RFC 6962 and why a verifier must take `size` from a SIGNED checkpoint (size and root together).
                self.assertFalse(v.verify_inclusion(leaves[i], i, i, path, root))  # index >= size
                self.assertFalse(v.verify_inclusion(hashlib.sha256(b"z").digest(), i, n, path, root))
                if path:
                    bad = list(path)
                    bad[0] = hashlib.sha256(bad[0]).digest()
                    self.assertFalse(v.verify_inclusion(leaves[i], i, n, bad, root))
                    self.assertFalse(v.verify_inclusion(leaves[i], i, n, path[:-1], root))
                self.assertFalse(v.verify_inclusion(leaves[i], i, n, path + [root], root))


class CanonTests(unittest.TestCase):
    def test_known_strings(self):
        self.assertEqual(v.canon({"b": 1, "a": [True, None, -2]}), b'{"a":[true,null,-2],"b":1}')
        self.assertEqual(v.canon("café"), "\"café\"".encode())
        self.assertEqual(v.canon("a\"b\\c\n\u0001"), b'"a\\"b\\\\c\\n\\u0001"')

    def test_utf16_key_order(self):
        # U+10000 encodes as D800 DC00 in UTF-16, which sorts before U+FFFF, unlike code-point order
        self.assertEqual(v.canon({"￿": 1, "\U00010000": 2}), "{\"\U00010000\":2,\"￿\":1}".encode())

    def test_rejects_non_canonical_inputs(self):
        for bad in (1.5, 2**53, -(2**53), {"a": 1.0}, {1: 2}, "\ud800", object()):
            with self.assertRaises(v.FormatError, msg=repr(bad)):
                v.canon(bad)
        for text in ('{"a":1.0}', '{"a":NaN}', '{"a":1,"a":2}', "{"):
            with self.assertRaises(v.FormatError, msg=text):
                v.parse_json(text)

    def test_entry_hash_is_domain_separated(self):
        e = {"v": 1, "chain_id": "0" * 64, "seq": 0, "ts": "2026-01-01T00:00:00Z", "prev_hash": "0" * 64, "event": {"type": "x-t"}}
        plain = hashlib.sha256(v.canon(e)).hexdigest()
        self.assertNotEqual(v.compute_entry_hash(e), plain)
        e2 = dict(e, entry_hash="f" * 64)
        self.assertEqual(v.compute_entry_hash(e2), v.compute_entry_hash(e))  # entry_hash is not hashed into itself


class NoteTests(unittest.TestCase):
    def test_vkey_roundtrip_and_mismatch(self):
        pub = w.ed25519_public(hashlib.sha256(b"k").digest())
        name, got = v.parse_vkey(v.make_vkey("example-key", pub))
        self.assertEqual((name, got), ("example-key", pub))
        good = v.make_vkey("example-key", pub)
        with self.assertRaises(v.FormatError):
            v.parse_vkey("other-name" + good[len("example-key"):])
        for i in range(200):  # base64 may contain '+': parsing must not depend on it
            k = w.ed25519_public(hashlib.sha256(b"vk%d" % i).digest())
            self.assertEqual(v.parse_vkey(v.make_vkey("n", k)), ("n", k))
        with self.assertRaises(v.FormatError):
            v.parse_vkey("nonsense")

    def test_key_id_definition(self):
        pub = bytes(range(32))
        self.assertEqual(v.key_id("n", pub), hashlib.sha256(b"n\n\x01" + pub).digest()[:4])

    def test_checkpoint_parser_is_strict(self):
        cid = "ab" * 32
        root = base64.b64encode(b"\x00" * 32).decode()
        sig = "— k " + base64.b64encode(b"\x00" * 4 + b"\x01" * 64).decode() + "\n"
        ok = ("%s%s\n3\n%s\n\n%s" % (v.ORIGIN_PREFIX, cid, root, sig)).encode()
        cp = v.parse_checkpoint(ok)
        self.assertEqual((cp.size, cp.chain_id), (3, cid))
        self.assertEqual(cp.text, ("%s%s\n3\n%s\n" % (v.ORIGIN_PREFIX, cid, root)).encode())
        bads = [
            ok.replace(b"\n3\n", b"\n03\n"), ok.replace(b"\n3\n", b"\n0\n"), ok.replace(b"agent-custody/v1/", b"other/"),
            ok.replace(b"\n\n", b"\n"), ok.replace("—".encode(), b"-"), ok.replace(root.encode(), b"AAAA"),
            ok[: ok.index(b"\n\n") + 2], ok + b"x",
        ]
        for b in bads:
            with self.assertRaises(v.FormatError, msg=b):
                v.parse_checkpoint(b)


class HygieneOfTheVerifier(unittest.TestCase):
    SRC = os.path.join(ROOT, "verifier", "agent_custody_verify.py")

    def test_imports_only_the_standard_library(self):
        with open(self.SRC, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom):
                mods.add((n.module or "").split(".")[0])
        self.assertTrue(mods)
        self.assertLessEqual(mods, set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else mods)
        self.assertFalse(mods - {"__future__", "argparse", "base64", "binascii", "hashlib", "json", "re", "sys", "datetime",
                                         "unicodedata"})

    def test_parses_with_python_3_10_grammar(self):
        for path in (self.SRC, os.path.join(ROOT, "writer", "agent_custody_write.py")):
            with open(path, encoding="utf-8") as f:
                ast.parse(f.read(), feature_version=(3, 10))


if __name__ == "__main__":
    unittest.main()
