"""
Tests for the standalone Enigma engine (enigma.py).

Run:  python test_enigma.py      (or: pytest test_enigma.py)

Unlike the old audio-engine regression suite, these assert *properties*
(round-trip, involution, crib closure, stepping) rather than a golden hash,
because this engine is meant to change as we harden it.
"""
import enigma as E


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


# --- stage 2: keystream-combiner mode ---------------------------------------

def _stream():
    return E.StreamCipher(lambda: E.Enigma.configure("321", "B", positions="KDO", rings="AAA"))


def test_stream_round_trips():
    sc = _stream()
    msg = "".join(E.ALPHABET) * 6
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_stream_keystream_is_deterministic():
    assert _stream().keystream(50) == _stream().keystream(50)


def test_stream_can_self_map():
    """Additive combiner has no no-self-map structure: some C_i == P_i."""
    sc = _stream()
    msg = "".join(E.ALPHABET) * 6
    ct = sc.encrypt(msg)
    assert any(p == c for p, c in zip(msg, ct)), "additive stream must allow self-maps"


def test_stream_is_not_an_involution():
    """Unlike the classic machine, encrypt is not its own inverse."""
    sc = _stream()
    msg = "".join(E.ALPHABET) * 6
    assert sc.encrypt(sc.encrypt(msg)) != msg


def test_stream_two_time_pad_leaks_difference():
    """Documents WHY nonce reuse is fatal: reusing the keystream on two
    messages leaks their difference (C1 - C2 == P1 - P2)."""
    sc = _stream()
    p1 = "ATTACK.AT.DAWN"
    p2 = "RETREAT.AT.DUSK"
    n = min(len(p1), len(p2))
    p1, p2 = p1[:n], p2[:n]
    c1, c2 = sc.encrypt(p1), sc.encrypt(p2)   # SAME keystream — the mistake
    diff_cipher = [(E.IDX[a] - E.IDX[b]) % E.N for a, b in zip(c1, c2)]
    diff_plain = [(E.IDX[a] - E.IDX[b]) % E.N for a, b in zip(p1, p2)]
    assert diff_cipher == diff_plain, "keystream cancels on reuse — two-time-pad leak"


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


# --- stage 4: nonce / no-reuse discipline -----------------------------------

def test_channel_round_trips_across_parties():
    alice = E.Channel("shared-passphrase")
    bob = E.Channel("shared-passphrase")
    nonce, ct, tag = alice.send("MEET.AT.DAWN")
    assert bob.receive(nonce, ct, tag) == "MEET.AT.DAWN"


def test_channel_auto_nonce_is_fresh_each_send():
    alice = E.Channel("pw")
    n1, c1, _ = alice.send("SAME.MESSAGE")
    n2, c2, _ = alice.send("SAME.MESSAGE")
    assert n1 != n2 and c1 != c2, "same plaintext must not produce same nonce/ciphertext"


def test_channel_rejects_explicit_nonce_reuse():
    alice = E.Channel("pw")
    alice.send("FIRST", nonce="fixed")
    try:
        alice.send("SECOND", nonce="fixed")
    except ValueError:
        return
    raise AssertionError("reusing a send nonce must raise")


def test_channel_rejects_replay():
    alice, bob = E.Channel("pw"), E.Channel("pw")
    nonce, ct, tag = alice.send("HELLO")
    bob.receive(nonce, ct, tag)
    try:
        bob.receive(nonce, ct, tag)
    except ValueError:
        return
    raise AssertionError("replayed nonce must be rejected")


def test_channel_mac_rejects_tampering():
    alice, bob = E.Channel("pw"), E.Channel("pw")
    nonce, ct, tag = alice.send("MEET.AT.DAWN")
    flipped = ("X" if ct[0] != "X" else "Y") + ct[1:]   # tamper one symbol
    try:
        bob.receive(nonce, flipped, tag)
    except ValueError:
        pass
    else:
        raise AssertionError("tampered ciphertext must fail authentication")
    # a garbage tag must also be rejected
    try:
        bob.receive(nonce, ct, "00" * 32)
    except ValueError:
        return
    raise AssertionError("bad tag must fail authentication")


def test_channel_mac_rejects_wrong_key():
    alice, mallory = E.Channel("pw"), E.Channel("WRONG")
    nonce, ct, tag = alice.send("HELLO")
    try:
        mallory.receive(nonce, ct, tag)
    except ValueError:
        return
    raise AssertionError("wrong-key receiver must fail authentication, not decrypt garbage")


# --- dynamics: irregular stepping (opt-in) ----------------------------------

def test_irregular_step_round_trips():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", irregular_step=True)
    msg = "MEET.AT.DAWN.BRING.THE.DOCUMENTS!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_irregular_step_changes_output():
    msg = "".join(E.ALPHABET) * 3
    plain = E.StreamCipher.from_passphrase("pw", nonce="n").encrypt(msg)
    irreg = E.StreamCipher.from_passphrase("pw", nonce="n", irregular_step=True).encrypt(msg)
    assert plain != irreg, "irregular stepping must change the keystream"


def test_irregular_step_keystream_still_uniform():
    import randtest
    sc = E.StreamCipher.from_passphrase("benchmark", nonce="test", irregular_step=True)
    ks = [E.IDX[c] for c in sc.keystream(100_000)]
    assert randtest.chi_square(ks) < 52
    assert abs(randtest.autocorr_lag1(ks)) < 0.01


# --- dynamics: no-reflector (SIGABA-style) stream mode -----------------------

def test_reflectorless_round_trips_in_stream_mode():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", reflectorless=True)
    msg = "MEET.AT.DAWN.BRING.THE.DOCUMENTS!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_reflectorless_machine_has_no_reflector():
    m = E.derive_machine("pw", nonce="n", reflectorless=True)
    assert m.reflector is None


def test_reflectorless_differs_from_reflected():
    msg = "".join(E.ALPHABET) * 3
    reflected = E.StreamCipher.from_passphrase("pw", nonce="n").encrypt(msg)
    flat = E.StreamCipher.from_passphrase("pw", nonce="n", reflectorless=True).encrypt(msg)
    assert reflected != flat


def test_reflectorless_keystream_still_uniform():
    import randtest
    sc = E.StreamCipher.from_passphrase("benchmark", nonce="test", reflectorless=True)
    ks = [E.IDX[c] for c in sc.keystream(100_000)]
    assert randtest.chi_square(ks) < 52
    assert abs(randtest.autocorr_lag1(ks)) < 0.01


# --- dynamics: moving plugboard + reflector bank ----------------------------

def test_moving_plugboard_round_trips():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", moving_plugboard=True)
    msg = "MEET.AT.DAWN.BRING.THE.DOCUMENTS!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_moving_plugboard_changes_output():
    msg = "".join(E.ALPHABET) * 3
    static = E.StreamCipher.from_passphrase("pw", nonce="n").encrypt(msg)
    moving = E.StreamCipher.from_passphrase("pw", nonce="n", moving_plugboard=True).encrypt(msg)
    assert static != moving


def test_reflector_bank_round_trips_and_has_bank():
    m = E.derive_machine("pw", nonce="n", reflectors=3)
    assert m.reflector_bank is not None and len(m.reflector_bank) == 3
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", reflectors=3)
    msg = "MEET.AT.DAWN!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_all_dynamics_combined_round_trips():
    opts = dict(n_rotors=4, irregular_step=True, moving_plugboard=True,
                reflectors=3, reflectorless=False)
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", **opts)
    msg = "".join(E.ALPHABET) * 4
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_dynamics_keystream_still_uniform():
    import randtest
    sc = E.StreamCipher.from_passphrase("benchmark", nonce="test",
                                        irregular_step=True, moving_plugboard=True, reflectors=3)
    ks = [E.IDX[c] for c in sc.keystream(100_000)]
    assert randtest.chi_square(ks) < 52
    assert abs(randtest.autocorr_lag1(ks)) < 0.01


# --- easy interface: Config + Channel with dynamics -------------------------

def test_config_expands_to_channel():
    cfg = E.Config(n_rotors=4, irregular_step=True, moving_plugboard=True, reflectors=2)
    alice = E.Channel("shared", **vars(cfg))
    bob = E.Channel("shared", **vars(cfg))
    nonce, ct, tag = alice.send("MEET.AT.DAWN")
    assert bob.receive(nonce, ct, tag) == "MEET.AT.DAWN"


# --- dynamics: keyed rotor count --------------------------------------------

def test_keyed_rotor_count_in_range_and_round_trips():
    m = E.derive_machine("pw", nonce="n", n_rotors=(3, 8))
    assert 3 <= len(m.rotors) <= 8
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", n_rotors=(3, 8))
    msg = "MEET.AT.DAWN.BRING.THE.DOCUMENTS!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_keyed_rotor_count_is_deterministic_and_varies():
    count = lambda nn: len(E.derive_machine("pw", nonce=nn, n_rotors=(2, 12)).rotors)
    assert count("n") == count("n")                       # deterministic
    counts = {count(str(i)) for i in range(20)}
    assert len(counts) > 1, "count should vary across nonces"


def test_fixed_large_rotor_count_round_trips():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", n_rotors=7)
    msg = "".join(E.ALPHABET) * 3
    assert sc.decrypt(sc.encrypt(msg)) == msg


# --- dynamics: keyed static rotors + chaos ----------------------------------

def test_randomize_static_keeps_fast_rotor_moving_and_round_trips():
    m = E.derive_machine("pw", nonce="n", n_rotors=6, randomize_static=True)
    assert m.rotors[-1].static is False, "fast rotor must always move"
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", n_rotors=6, randomize_static=True)
    msg = "".join(E.ALPHABET) * 3
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_static_rotor_never_triggers_turnover():
    r = E.Rotor.named("1", position="U")   # 'U' is rotor 1's notch
    assert r.at_notch is True
    r.static = True
    assert r.at_notch is False, "a static rotor must not signal turnover"


def test_chaos_round_trips_and_keystream_uniform():
    import randtest
    for alpha in (None, E.Alphabet.of_bytes()):
        sc = E.StreamCipher.from_passphrase("pw", nonce="n", chaos=True, alphabet=alpha)
        if alpha is None:
            msg = "".join(E.ALPHABET) * 4
        else:
            msg = bytes(range(256)) * 2
        assert sc.decrypt(sc.encrypt(msg)) == msg
    ks = [E.IDX[c] for c in E.StreamCipher.from_passphrase(
        "benchmark", nonce="k", chaos=True).keystream(100_000)]
    assert randtest.chi_square(ks) < 52


def test_chaos_via_config():
    cfg = E.Config(chaos=True, n_rotors=(4, 9))
    alice, bob = E.Channel("s", **vars(cfg)), E.Channel("s", **vars(cfg))
    nonce, ct, tag = alice.send("MEET.AT.DAWN")
    assert bob.receive(nonce, ct, tag) == "MEET.AT.DAWN"


# --- dynamics: double-step toggle -------------------------------------------

def test_double_step_off_changes_output_and_round_trips():
    msg = "".join(E.ALPHABET) * 3
    on = E.StreamCipher.from_passphrase("pw", nonce="n").encrypt(msg)
    off_sc = E.StreamCipher.from_passphrase("pw", nonce="n", double_step=False)
    off = off_sc.encrypt(msg)
    assert on != off, "toggling the double-step must change the keystream"
    assert off_sc.decrypt(off) == msg


def test_double_step_is_per_rotor_and_applies():
    m = E.derive_machine("pw", nonce="n", double_step=False)
    assert all(r.double_step is False for r in m.rotors)
    m2 = E.derive_machine("pw", nonce="n")            # default on
    assert all(r.double_step is True for r in m2.rotors)


def test_randomize_double_step_round_trips():
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", randomize_double_step=True)
    msg = "MEET.AT.DAWN!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


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
    from collections import Counter
    sc = E.StreamCipher.from_passphrase("benchmark", nonce="test", alphabet=E.Alphabet.of_bytes())
    ks = list(sc.keystream(200_000))
    counts = Counter(ks)
    exp = len(ks) / 256
    chi = sum((counts[i] - exp) ** 2 / exp for i in range(256))
    assert chi < 340, f"byte keystream biased: chi-square {chi:.1f} (255 dof, 0.01 crit ~310)"


# --- keystream quality gate -------------------------------------------------

def test_keystream_is_uniform_and_independent():
    """Guard against a keystream that resonates with the rotor period. Aggregated
    over several seeds so a single unlucky sample (chi-square is itself random)
    can't fail or pass the gate. All deterministic, so the thresholds are stable."""
    import randtest, statistics
    chis, acs = [], []
    for i, (pw, nn) in enumerate([("benchmark", "test"), ("alpha", "1"),
                                  ("bravo", "2"), ("charlie", "3"), ("delta", "4")]):
        ks = randtest.keystream_indices(100_000, passphrase=pw, nonce=nn)
        chis.append(randtest.chi_square(ks))
        acs.append(abs(randtest.autocorr_lag1(ks)))
    # 31 dof: mean should sit near 31; require the median comfortably uniform.
    assert statistics.median(chis) < 45, f"keystream biased: chi medians {chis}"
    assert max(acs) < 0.01, f"keystream correlated: |lag-1| max {max(acs):.4f}"


# --- dynamics: keyed drift over the run -------------------------------------

def test_drift_round_trips_and_changes_keystream():
    msg = "".join(E.ALPHABET) * 4
    plain = E.StreamCipher.from_passphrase("pw", nonce="n").encrypt(msg)
    drift_sc = E.StreamCipher.from_passphrase("pw", nonce="n", drift=True)
    drifted = drift_sc.encrypt(msg)
    assert drifted != plain, "drift must change the keystream"
    assert drift_sc.decrypt(drifted) == msg


def test_drift_assigns_nonzero_strides_and_plug_stream():
    m = E.derive_machine("pw", nonce="n", n_rotors=5, drift=True)
    assert all(r.notch_drift and r.ring_drift for r in m.rotors), "drift strides must be nonzero"
    assert m.plug_stream is not None, "drift must jolt the plugboard"


def test_drift_notch_and_ring_walk_over_the_run():
    r = E.Rotor(list(range(E.N)), notches={0}, notch_drift=3, ring_drift=5)
    n0, s0 = r._ndrift, r._rdrift
    r.drift(); r.drift()
    assert r._ndrift == (n0 + 6) % E.N and r._rdrift == (s0 + 10) % E.N


def test_drift_byte_mode_keystream_uniform():
    import randtest
    sc = E.StreamCipher.from_passphrase("benchmark", nonce="k", drift=True,
                                        alphabet=E.Alphabet.of_bytes())
    from collections import Counter
    ks = list(sc.keystream(100_000))
    counts = Counter(ks)
    exp = len(ks) / 256
    chi = sum((counts[i] - exp) ** 2 / exp for i in range(256))
    assert chi < 340, f"drift keystream biased: chi-square {chi:.1f}"


def test_reflector_bank_range_is_key_picked_and_round_trips():
    m = E.derive_machine("pw", nonce="n", reflectors=(2, 5))
    assert m.reflector_bank is not None and 2 <= len(m.reflector_bank) <= 5
    sc = E.StreamCipher.from_passphrase("pw", nonce="n", reflectors=(2, 5))
    msg = "MEET.AT.DAWN!"
    assert sc.decrypt(sc.encrypt(msg)) == msg


def test_chaos_turns_on_drift():
    m = E.derive_machine("pw", nonce="n", chaos=True)
    assert m.plug_stream is not None
    assert any(r.notch_drift for r in m.rotors), "chaos must engage drift"


# --- cascade: several machines chained --------------------------------------

def test_cascade_round_trips():
    cas = E.Cascade("pw", 3, nonce="n")
    msg = "".join(E.ALPHABET) * 3
    assert cas.decrypt(cas.encrypt(msg)) == msg


def test_cascade_differs_from_single_layer():
    msg = "".join(E.ALPHABET) * 3
    one = E.Cascade("pw", 1, nonce="n").encrypt(msg)
    three = E.Cascade("pw", 3, nonce="n").encrypt(msg)
    assert one != three, "stacking layers must change the output"


def test_cascade_heterogeneous_configs_round_trip():
    stages = [dict(chaos=True), dict(reflectorless=True), dict(drift=True), {}]
    cas = E.Cascade("pw", stages, nonce="n")
    msg = "".join(E.ALPHABET) * 4
    assert cas.decrypt(cas.encrypt(msg)) == msg


def test_cascade_byte_mode_round_trips():
    ab = E.Alphabet.of_bytes()
    cas = E.Cascade("pw", 4, nonce="n", chaos=True, alphabet=ab)
    data = bytes(range(256)) * 2
    assert cas.decrypt(cas.encrypt(data)) == data


# --- keyfile: a second independent secret folded into the KDF ----------------

def test_keyfile_changes_keystream_and_round_trips():
    msg = "".join(E.ALPHABET) * 3
    plain = E.StreamCipher.from_passphrase("pw", nonce="n").encrypt(msg)
    kf = E.StreamCipher.from_passphrase("pw", nonce="n", keyfile=b"\x00\x01secret")
    withkey = kf.encrypt(msg)
    assert withkey != plain, "keyfile must change the keystream"
    assert kf.decrypt(withkey) == msg


def test_wrong_keyfile_does_not_recover():
    msg = "MEET.AT.DAWN!"
    ct = E.StreamCipher.from_passphrase("pw", nonce="n", keyfile=b"right").encrypt(msg)
    out = E.StreamCipher.from_passphrase("pw", nonce="n", keyfile=b"wrong").decrypt(ct)
    assert out != msg, "a wrong keyfile must not decrypt"


def test_channel_keyfile_round_trips_and_wrong_keyfile_fails_auth():
    a = E.Channel("pw", keyfile=b"shared-file")
    b = E.Channel("pw", keyfile=b"shared-file")
    nonce, ct, tag = a.send("HELLO.WORLD")
    assert b.receive(nonce, ct, tag) == "HELLO.WORLD"
    mallory = E.Channel("pw", keyfile=b"other-file")
    try:
        mallory.receive(nonce, ct, tag)
    except ValueError:
        return
    raise AssertionError("wrong keyfile must fail authentication")


def run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok  ", t.__name__)
    print(f"\n{len(tests)} tests passed")


if __name__ == "__main__":
    run()
