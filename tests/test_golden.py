"""Byte-level fidelity oracle.

A single frozen signature over a spread of configs — classic M3, M4 with a
static Greek rotor, a fixed-point (self-mapping) reflector, keyed notch/ring
drift, and the 256-symbol byte alphabet. Any refactor that changes output for
*any* of these — a mis-ported double-step, an off-by-one in the shift math —
flips the hash. This is what gates the hot-loop micro-opts (and a future
native port): same input vectors -> same digest -> byte-identical behaviour.

If you change the machine's semantics on purpose, re-pin GOLDEN below.
"""
import hashlib

import enigmar as E
from enigmar.machine import Enigma, Rotor, Reflector

GOLDEN = "8f52c23cf49f580a67309ba644391c24b7a0222608f1e89e956a8bc76fde9485"


def _cases():
    alph = "".join(E.ALPHABET) * 20

    # classic M3 with plugboard
    yield Enigma.configure("321", "B", positions="KDO", rings="AAA",
                           plugs="AB CD").encode(alph)

    # M4 with a static Greek rotor
    yield Enigma.configure("B321", "B", positions="AAAA", rings="AAAA").encode(alph)

    # fixed-point reflector: the machine can self-map and still decrypt
    refl = Reflector.from_pairs("AB CD EF GH IJ KL MN OP QR ST")
    yield Enigma([Rotor.named("3"), Rotor.named("2"), Rotor.named("1")],
                 refl).encode(alph)

    # keyed notch/ring drift active
    rr = [Rotor.named("1"), Rotor.named("2"), Rotor.named("3")]
    rr[2].notch_drift = 3
    rr[1].ring_drift = 5
    yield Enigma(rr, Reflector.named("C")).encode(alph)

    # 256-symbol byte alphabet: encrypt arbitrary binary
    ab = E.Alphabet.of_bytes()
    m = Enigma([Rotor(list(range(256)), ring=1), Rotor(list(range(255, -1, -1)))],
               Reflector.from_pairs([(i, 255 - i) for i in range(128)], size=256),
               alphabet=ab)
    yield m.encode(bytes(range(256)))


def _signature() -> str:
    h = hashlib.sha256()
    for out in _cases():
        h.update(out.encode() if isinstance(out, str) else bytes(out))
    return h.hexdigest()


def test_golden_signature_is_stable():
    assert _signature() == GOLDEN, (
        "machine output changed — if intentional, re-pin GOLDEN; "
        "otherwise a refactor broke byte-level fidelity"
    )
