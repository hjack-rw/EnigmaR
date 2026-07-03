"""Core mechanism: alphabet, reflectors, stepping."""
import enigmar as E

# --- basics -----------------------------------------------------------------

def test_alphabet_is_32():
    assert len(E.ALPHABET) == 32
    assert len(set(E.ALPHABET)) == 32


def test_round_trip_with_involution_reflector():
    def fresh():
        return E.Enigma.configure("321", "B", positions="KDO", rings="AAA", plugs="AB CD")
    msg = "ENIGMA.ROUND.TRIPS.OVER.THE.WHOLE.ALPHABET!?:'"
    assert fresh().encode(fresh().encode(msg)) == msg


def test_encode_is_deterministic():
    def fresh():
        return E.Enigma.configure("512", "C", positions="MNO", rings="BCD")
    msg = "REPEATABLE"
    assert fresh().encode(msg) == fresh().encode(msg)


# --- stage 1: fixed-point reflectors close the no-self-map crib -------------

def test_classic_reflector_never_self_maps():
    """Fixed-point-free reflector B: no symbol encrypts to itself (the crib)."""
    refl = E.Reflector.named("B")
    assert refl.is_involution and not refl.has_fixed_point
    msg = "".join(E.ALPHABET) * 8
    ct = E.Enigma([E.Rotor.named("3"), E.Rotor.named("2"), E.Rotor.named("1")], refl).encode(msg)
    assert not any(a == b for a, b in zip(msg, ct)), "classic Enigma must never self-map"


def test_fixed_point_reflector_can_self_map_and_still_decrypts():
    """Stage-1 hardening: a fixed-point involution decrypts AND can self-map."""
    refl = E.Reflector.from_pairs("AB CD EF GH IJ KL MN OP QR ST")
    assert refl.is_involution and refl.has_fixed_point

    def fresh():
        return E.Enigma([E.Rotor.named("3"), E.Rotor.named("2"), E.Rotor.named("1")], refl)

    msg = "".join(E.ALPHABET) * 8
    ct = fresh().encode(msg)
    assert fresh().encode(ct) == msg, "must still round-trip"
    assert any(a == b for a, b in zip(msg, ct)), "crib must be closed: some symbol self-maps"


# --- reflector construction guards ------------------------------------------

def test_reflector_rejects_non_involution_by_default():
    try:
        E.Reflector.named("Bthin")          # thin reflectors are not involutions
    except ValueError:
        pass
    else:
        raise AssertionError("non-involution reflector should be rejected by default")


def test_reflector_allows_non_involution_when_explicit():
    r = E.Reflector(E.REFLECTOR_WIRINGS["Bthin"], require_involution=False)
    assert not r.is_involution


def test_from_pairs_guards():
    for bad in [["AA"], ["ABC"], ["AB", "BC"]]:   # self-pair, wrong length, reused symbol
        try:
            E.Reflector.from_pairs(bad)
        except ValueError:
            continue
        raise AssertionError(f"from_pairs should reject {bad}")


def test_named_reflector_involution_status():
    for name in ("A", "B", "C"):
        assert E.Reflector.named(name).is_involution
    for name in ("Bthin", "Cthin"):
        assert not E.Reflector(E.REFLECTOR_WIRINGS[name], require_involution=False).is_involution


# --- stepping ---------------------------------------------------------------

def test_rotor_step_wraps():
    r = E.Rotor.named("1", position="'")     # last symbol, index 31
    r.step()
    assert r.position == 0


def test_greek_rotor_is_static_in_m4():
    m4 = E.Enigma.configure("B321", "B", positions="AAAA", rings="AAAA")
    m4.encode("".join(E.ALPHABET) * 4)
    assert m4.rotors[0].position == 0, "Greek rotor must not move"


def test_fast_rotor_advances_every_char():
    m = E.Enigma.configure("321", "B", positions="AAA", rings="AAA")
    start = m.rotors[-1].position
    m.encode_char("A")
    assert m.rotors[-1].position == (start + 1) % 32

