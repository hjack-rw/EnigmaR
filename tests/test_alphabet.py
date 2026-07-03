"""Arbitrary alphabet: byte mode + custom symbols."""
import enigmar as E

# --- arbitrary alphabet: byte mode + custom symbols -------------------------

def test_byte_mode_round_trips_arbitrary_binary():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", alphabet=E.Alphabet.of_bytes())
    data = bytes(range(256)) * 4
    ct = sc.encrypt(data)
    assert isinstance(ct, bytes) and sc.decrypt(ct) == data


def test_byte_mode_machine_is_256_wide():
    m = E.derive_machine("pw", nonce="n", alphabet=E.Alphabet.of_bytes())
    assert m.N == 256
    for r in m.rotors:
        assert sorted(r.forward) == list(range(256)), "rotor must be a 256-permutation"


def test_custom_alphabet_round_trips():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", alphabet=E.Alphabet("ACGT"))
    msg = "ACGTACGTTTAAGGCCACGT" * 3
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_channel_byte_mode_across_parties():
    ab = E.Alphabet.of_bytes()
    alice, bob = E.Channel("shared", alphabet=ab), E.Channel("shared", alphabet=ab)
    nonce, ct, tag = alice.send(b"\x00\xff\x10\x80 raw binary! \x7f")
    assert bob.receive(nonce, ct, tag) == b"\x00\xff\x10\x80 raw binary! \x7f"


def test_byte_mode_keystream_is_uniform():
    import randtest
    sc = E.StreamCipher.from_passphrase("benchmark", nonce="test", alphabet=E.Alphabet.of_bytes())
    chi = randtest.chi_square(list(sc.keystream(200_000)), 256)
    assert chi < 340, f"byte keystream biased: chi-square {chi:.1f} (255 dof, 0.01 crit ~310)"

