"""Stage 3: key-derived secret wiring."""
import enigmar as E

# --- stage 3: key-derived secret wiring -------------------------------------

def test_derive_is_deterministic():
    a = E.derive_machine("correct horse battery staple", nonce="msg-1")
    b = E.derive_machine("correct horse battery staple", nonce="msg-1")
    msg = "".join(E.ALPHABET) * 3
    assert a.encode(msg) == b.encode(msg)


def test_derive_rotors_are_valid_permutations():
    m = E.derive_machine("pw", nonce="n")
    for rotor in m.rotors:
        wiring = "".join(E.ALPHABET[i] for i in rotor.forward)
        assert sorted(wiring) == sorted(E.ALPHABET), "rotor must be a permutation"


def test_derive_reflector_is_crib_closed_involution():
    m = E.derive_machine("pw", nonce="n")
    assert m.reflector.is_involution, "must decrypt"
    assert m.reflector.has_fixed_point, "must allow self-encryption (crib closed)"


def test_derive_passphrase_changes_machine():
    msg = "".join(E.ALPHABET) * 3
    a = E.derive_machine("alpha", nonce="n").encode(msg)
    b = E.derive_machine("bravo", nonce="n").encode(msg)
    assert a != b


def test_derive_nonce_changes_machine():
    msg = "".join(E.ALPHABET) * 3
    a = E.derive_machine("pw", nonce="msg-1").encode(msg)
    b = E.derive_machine("pw", nonce="msg-2").encode(msg)
    assert a != b


def test_from_passphrase_round_trips():
    sc = E.StreamCipher.from_passphrase("hunter2", nonce="msg-1")
    msg = "MEET.AT.DAWN.BRING.THE.DOCUMENTS!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_wrong_passphrase_does_not_recover():
    ct = E.StreamCipher.from_passphrase("right", nonce="n").encrypt("SECRET.MESSAGE")
    wrong = E.StreamCipher.from_passphrase("wrong", nonce="n").decrypt(ct)
    assert wrong != "SECRET.MESSAGE"

