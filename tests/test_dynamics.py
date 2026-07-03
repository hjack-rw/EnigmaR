"""Opt-in keyed dynamics + cascade."""
import enigmar as E

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
    chi = randtest.chi_square(list(sc.keystream(100_000)), 256)
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

