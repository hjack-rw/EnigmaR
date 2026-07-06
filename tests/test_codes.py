"""
End-to-end tests for the sealed-code demo logic (docs/seal.py), which drives the
real enigmar engine: enigmar.FPE runs an actual Enigma (rotors/reflector/plugboard),
with an HMAC-SHA256 tag doing the sealing.

The demo ships two schemes and lets the page switch between them, so every case
runs under both:
  - "classic": a per-code serial rides in the clear as the nonce, tag encrypted
    beside the payload;
  - "siv": enigmar.SealedCode (RFC 5297), where the tag doubles as the nonce, so
    the serial is encrypted too.

Importing seal patches the KDF to the browser-friendly sha256 stretch, exactly as
the live demo runs it, so these tests cover the shipped code path.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))       # enigmar
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "docs"))  # seal

import seal  # noqa: E402

KEY = "test-key"
SCHEMES = ["classic", "siv"]
CASES = [
    (42, 15, 9000, 25846),
    (0, 0, 0, 0),
    (32767, 31, 32767, 32767),
    (1, 1, 1, 1),
]


@pytest.mark.parametrize("scheme", SCHEMES)
def test_round_trip_recovers_every_field(scheme):
    for cid, disc, exp, ser in CASES:
        f = seal.check(KEY, seal.mint(KEY, cid, disc, exp, ser, scheme=scheme), scheme=scheme)
        assert f is not None
        assert (f["id"], f["discount"], f["expiry"], f["serial"]) == (cid, disc, exp, ser)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_shape_is_grouped_base32(scheme):
    code = seal.mint(KEY, 42, 15, 9000, 1, scheme=scheme)
    assert code.count("-") == 2
    raw = code.replace("-", "")
    assert len(raw) == seal.W_CODE == 15
    assert all(c in seal.ALPH for c in raw)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_every_single_char_tamper_is_rejected(scheme):
    code = seal.mint(KEY, 42, 15, 9000, 25846, scheme=scheme)
    raw = code.replace("-", "")
    for i in range(len(raw)):
        for d in range(1, seal.N):
            arr = list(raw)
            arr[i] = seal.ALPH[(seal.ALPH.index(arr[i]) + d) % seal.N]
            assert seal.check(KEY, "".join(arr), scheme=scheme) is None


@pytest.mark.parametrize("scheme", SCHEMES)
def test_wrong_key_is_rejected(scheme):
    code = seal.mint(KEY, 1, 2, 3, 4, scheme=scheme)
    assert seal.check("other-key", code, scheme=scheme) is None


@pytest.mark.parametrize("scheme", SCHEMES)
def test_minting_is_deterministic(scheme):
    a = seal.mint(KEY, 42, 15, 9000, 25846, scheme=scheme)
    b = seal.mint(KEY, 42, 15, 9000, 25846, scheme=scheme)
    assert a == b


@pytest.mark.parametrize("scheme", SCHEMES)
def test_changing_the_serial_changes_the_code(scheme):
    # Different serial -> different code under both schemes (classic moves the clear
    # nonce; SIV re-tags because the serial is part of the sealed plaintext).
    a = seal.mint(KEY, 10, 5, 100, 1, scheme=scheme)
    b = seal.mint(KEY, 10, 5, 100, 2, scheme=scheme)
    assert a != b


def test_siv_encrypts_the_serial_classic_leaks_it():
    # The whole point of SIV: with the same non-serial fields, the classic codes
    # share a visible clear-nonce region only by serial, while SIV bodies differ
    # everywhere. Concretely: classic exposes the serial as the leading W_SER
    # symbols; SIV does not.
    classic = seal.mint(KEY, 10, 5, 100, 777, scheme="classic").replace("-", "")
    assert seal._dec_int(classic[:seal.W_SER]) == 777        # serial readable in the clear
    siv = seal.mint(KEY, 10, 5, 100, 777, scheme="siv").replace("-", "")
    assert seal._dec_int(siv[:seal.W_SER]) != 777            # nothing readable up front


@pytest.mark.parametrize("scheme", SCHEMES)
def test_garbage_input_is_rejected(scheme):
    for junk in ["", "not-a-code", "AAAAA-AAAAA-AAAAA", "12345"]:
        assert seal.check(KEY, junk, scheme=scheme) is None


@pytest.mark.parametrize("scheme", SCHEMES)
def test_brand_is_bound(scheme):
    code = seal.mint(KEY, 42, 15, 9000, 1, brand="SUMMER", scheme=scheme)
    assert seal.check(KEY, code, brand="SUMMER", scheme=scheme) is not None   # right brand
    assert seal.check(KEY, code, brand="summer", scheme=scheme) is not None   # case-insensitive
    assert seal.check(KEY, code, brand="HARVEST", scheme=scheme) is None      # another brand's code
    assert seal.check(KEY, code, brand="SUMER", scheme=scheme) is None        # misspelled
    assert seal.check(KEY, code, scheme=scheme) is None                       # brand omitted
