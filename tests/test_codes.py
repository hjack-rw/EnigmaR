"""
End-to-end tests for the sealed-code demo logic (docs/seal.py), which drives the
real enigmar engine: enigmar.FPE runs an actual Enigma (rotors/reflector/plugboard)
keyed by passphrase + per-code nonce, with an HMAC-SHA256 tag doing the sealing.

Importing seal patches the KDF to the browser-friendly sha256 stretch, exactly as
the live demo runs it, so these tests cover the shipped code path.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))       # enigmar
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "docs"))  # seal

import seal  # noqa: E402

KEY = "test-key"
CASES = [
    (42, 15, 9000, 25846),
    (0, 0, 0, 0),
    (32767, 31, 32767, 32767),
    (1, 1, 1, 1),
]


def test_round_trip_recovers_every_field():
    for cid, disc, exp, ser in CASES:
        f = seal.check(KEY, seal.mint(KEY, cid, disc, exp, ser))
        assert f is not None
        assert (f["id"], f["discount"], f["expiry"], f["serial"]) == (cid, disc, exp, ser)


def test_shape_is_grouped_base32():
    code = seal.mint(KEY, 42, 15, 9000, 1)
    assert code.count("-") == 2
    raw = code.replace("-", "")
    assert len(raw) == seal.W_CODE == 15
    assert all(c in seal.ALPH for c in raw)


def test_every_single_char_tamper_is_rejected():
    code = seal.mint(KEY, 42, 15, 9000, 25846)
    raw = code.replace("-", "")
    for i in range(len(raw)):
        for d in range(1, seal.N):
            arr = list(raw)
            arr[i] = seal.ALPH[(seal.ALPH.index(arr[i]) + d) % seal.N]
            assert seal.check(KEY, "".join(arr)) is None


def test_wrong_key_is_rejected():
    code = seal.mint(KEY, 1, 2, 3, 4)
    assert seal.check("other-key", code) is None


def test_minting_is_deterministic():
    a = seal.mint(KEY, 42, 15, 9000, 25846)
    b = seal.mint(KEY, 42, 15, 9000, 25846)
    assert a == b


def test_fresh_pad_per_nonce():
    # Same fields, different serial (nonce) -> different sealed body: no shared pad.
    a = seal.mint(KEY, 10, 5, 100, 1).replace("-", "")[seal.W_SER:]
    b = seal.mint(KEY, 10, 5, 100, 2).replace("-", "")[seal.W_SER:]
    assert a != b


def test_garbage_input_is_rejected():
    for junk in ["", "not-a-code", "AAAAA-AAAAA-AAAAA", "12345"]:
        assert seal.check(KEY, junk) is None
