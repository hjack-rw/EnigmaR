"""Stage 4: nonce discipline, MAC, keyfile."""
import enigmar as E

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

