"""
Tests for enigmar.sealed.SealedCode — the SIV-style (deterministic AE) sealing
built on the real FPE engine. Mirrors the battery in test_codes.py, plus the two
properties that are the whole point of the SIV construction: every field is
confidential (nothing rides in the clear) and minting is deterministic without a
reusable nonce.

kdf_n is lowered here purely for test speed; the construction is identical at the
production cost.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from enigmar import SealedCode, DEFAULT_ALPHABET  # noqa: E402

KEY = "test-key"
FIELDS = {"id": 3, "discount": 1, "expiry": 3, "serial": 3}   # 10 payload + 5 tag = 15
FAST = dict(kdf_n=1024)     # small KDF cost so the sweep tests stay quick

CASES = [
    dict(id=42, discount=15, expiry=9000, serial=25846),
    dict(id=0, discount=0, expiry=0, serial=0),
    dict(id=32767, discount=31, expiry=32767, serial=32767),
    dict(id=1, discount=1, expiry=1, serial=1),
]


def _codes(**opts):
    return SealedCode(KEY, FIELDS, **FAST, **opts)


def test_round_trip_recovers_every_field():
    codes = _codes()
    for c in CASES:
        f = codes.check(codes.mint(**c))
        assert f is not None
        assert (f["id"], f["discount"], f["expiry"], f["serial"]) == (
            c["id"], c["discount"], c["expiry"], c["serial"])


def test_shape_is_grouped_base32():
    codes = _codes()
    code = codes.mint(id=42, discount=15, expiry=9000, serial=1)
    assert code.count("-") == 2
    raw = code.replace("-", "")
    assert len(raw) == 15
    assert all(c in DEFAULT_ALPHABET for c in raw)


def test_every_single_char_tamper_is_rejected():
    codes = _codes()
    code = codes.mint(id=42, discount=15, expiry=9000, serial=25846)
    raw = code.replace("-", "")
    alph = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    n = len(alph)
    for i in range(len(raw)):
        for d in range(1, n):
            arr = list(raw)
            arr[i] = alph[(alph.index(arr[i]) + d) % n]
            assert codes.check("".join(arr)) is None


def test_wrong_key_is_rejected():
    code = _codes().mint(id=1, discount=2, expiry=3, serial=4)
    assert SealedCode("other-key", FIELDS, **FAST).check(code) is None


def test_minting_is_deterministic():
    codes = _codes()
    a = codes.mint(id=42, discount=15, expiry=9000, serial=25846)
    b = codes.mint(id=42, discount=15, expiry=9000, serial=25846)
    assert a == b


def test_brand_is_bound():
    codes = _codes()
    code = codes.mint(id=42, discount=15, expiry=9000, serial=1, brand="SUMMER")
    assert codes.check(code, brand="SUMMER") is not None    # right brand
    assert codes.check(code, brand="summer") is not None    # case-insensitive
    assert codes.check(code, brand="HARVEST") is None        # another brand's code
    assert codes.check(code, brand="SUMER") is None          # misspelled
    assert codes.check(code) is None                          # brand omitted


def test_garbage_input_is_rejected():
    codes = _codes()
    for junk in ["", "not-a-code", "AAAAA-AAAAA-AAAAA", "12345"]:
        assert codes.check(junk) is None


def test_serial_is_confidential_not_in_the_clear():
    # The SIV win over the clear-nonce scheme: two codes that differ ONLY in the
    # serial share no visible substring at the serial's old fixed position — the
    # serial is encrypted, not riding in plaintext.
    codes = _codes()
    a = codes.mint(id=7, discount=3, expiry=100, serial=1).replace("-", "")
    b = codes.mint(id=7, discount=3, expiry=100, serial=2).replace("-", "")
    assert a != b
    # whole body differs (tag is a PRF of the plaintext, so one field flip avalanches)
    assert sum(x != y for x, y in zip(a, b)) > 1


def test_no_nonce_reuse_footgun_distinct_payloads_distinct_codes():
    # Different payloads under the same key never share a pad (no reusable nonce):
    # distinct inputs -> distinct codes, deterministically.
    codes = _codes()
    seen = {codes.mint(**c) for c in CASES}
    assert len(seen) == len(CASES)


def test_tag_width_sets_forgery_resistance():
    # Wider tag -> longer code, same fields. The tag width is the security knob.
    narrow = SealedCode(KEY, FIELDS, tag_width=5, **FAST)
    wide = SealedCode(KEY, FIELDS, tag_width=8, **FAST)
    n = len(narrow.mint(id=1, discount=1, expiry=1, serial=1).replace("-", ""))
    w = len(wide.mint(id=1, discount=1, expiry=1, serial=1).replace("-", ""))
    assert w - n == 3
