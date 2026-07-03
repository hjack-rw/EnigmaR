"""Key agreement: DH handshake, authenticated 3-DH, ratchet, session."""
import enigmar as E

# --- DH handshake: agree a key over a public channel, no pre-shared secret -----

def test_handshake_agrees_and_channel_round_trips():
    a, b = E.Handshake(), E.Handshake()
    ka, kb = a.shared(b.public), b.shared(a.public)
    assert ka == kb and len(ka) == 32, "both sides must derive the same 32-byte key"
    ab = E.Alphabet.of_bytes()
    alice = E.Channel("", keyfile=ka, alphabet=ab)
    bob = E.Channel("", keyfile=kb, alphabet=ab)
    nonce, ct, tag = alice.send(b"no pre-shared secret")
    assert bob.receive(nonce, ct, tag) == b"no pre-shared secret"


def test_handshake_distinct_parties_get_distinct_keys():
    a, b, c = E.Handshake(), E.Handshake(), E.Handshake()
    assert a.shared(b.public) != a.shared(c.public), "different peers -> different keys"


def test_handshake_rejects_bad_public():
    a = E.Handshake()
    for bad in (0, 1, -1):
        try:
            a.shared(bad)
        except ValueError:
            continue
        raise AssertionError("must reject an invalid peer public key")


# --- authenticated handshake (3-DH) + ratchet ------------------------------

def test_authenticated_handshake_agrees_and_round_trips():
    id_a, id_b = E.Identity(), E.Identity()
    eph_a, eph_b = E.Handshake(), E.Handshake()
    ka = E.authenticated_key(id_a, eph_a, id_b.public, eph_b.public, initiator=True)
    kb = E.authenticated_key(id_b, eph_b, id_a.public, eph_a.public, initiator=False)
    assert ka == kb and len(ka) == 32, "authenticated key must match on both sides"
    ab = E.Alphabet.of_bytes()
    alice, bob = E.Channel("", keyfile=ka, alphabet=ab), E.Channel("", keyfile=kb, alphabet=ab)
    nonce, ct, tag = alice.send(b"authenticated + no pre-shared secret")
    assert bob.receive(nonce, ct, tag) == b"authenticated + no pre-shared secret"


def test_mitm_wrong_identity_fails():
    id_a, id_b, mallory = E.Identity(), E.Identity(), E.Identity()
    eph_a, eph_b = E.Handshake(), E.Handshake()
    honest = E.authenticated_key(id_a, eph_a, id_b.public, eph_b.public, initiator=True)
    # Bob's peer identity is spoofed (Mallory's) -> different key -> auth would fail
    spoofed = E.authenticated_key(id_b, eph_b, mallory.public, eph_a.public, initiator=False)
    assert honest != spoofed, "a wrong/spoofed identity must not yield the same key"


def test_ratchet_is_deterministic_and_keys_distinct():
    root = bytes(range(32))
    a, b = E.Ratchet(root), E.Ratchet(root)
    ka = [a.next() for _ in range(5)]
    kb = [b.next() for _ in range(5)]
    assert ka == kb, "same root -> same key sequence (both parties agree)"
    assert len(set(ka)) == 5, "every message key must be distinct"
    assert all(len(k) == 32 for k in ka)


def test_ratchet_diverges_on_different_root():
    a = E.Ratchet(b"\x00" * 32).next()
    b = E.Ratchet(b"\x01" + b"\x00" * 31).next()
    assert a != b, "different roots must give different keys"


def test_ratchet_rejects_short_root():
    try:
        E.Ratchet(b"tooshort")
    except ValueError:
        return
    raise AssertionError("ratchet must reject a too-short root")


# --- end-to-end double-ratchet session -------------------------------------

def _paired_session():
    id_a, id_b = E.Identity(), E.Identity()
    ea, eb = E.Handshake(), E.Handshake()
    ka = E.authenticated_key(id_a, ea, id_b.public, eb.public, initiator=True)
    kb = E.authenticated_key(id_b, eb, id_a.public, ea.public, initiator=False)
    return E.Session.initiator(ka, eb.public), E.Session.responder(kb, eb)


def test_session_round_trips_both_directions():
    a, b = _paired_session()
    assert b.receive(a.send(b"a->b one")) == b"a->b one"
    assert a.receive(b.send(b"b->a one")) == b"b->a one"
    assert b.receive(a.send(b"a->b two")) == b"a->b two"


def test_session_message_keys_differ_per_message():
    a, _ = _paired_session()
    assert a.send(b"same") != a.send(b"same"), "each message rides a fresh key"


def test_long_alternating_conversation():
    a, b = _paired_session()
    for i in range(6):
        assert b.receive(a.send(f"a{i}".encode())) == f"a{i}".encode()
        assert a.receive(b.send(f"b{i}".encode())) == f"b{i}".encode()


def test_dh_ratchet_advances_the_root_each_turn():
    a, b = _paired_session()
    b.receive(a.send(b"hi"))
    root = b.rk
    a.receive(b.send(b"reply"))
    b.receive(a.send(b"again"))          # b sees a's new DH -> DH ratchet -> root moves
    assert b.rk != root, "the root must advance as the conversation turns"


def test_out_of_order_and_skipped_messages():
    a, b = _paired_session()
    m0, m1, m2 = a.send(b"m0"), a.send(b"m1"), a.send(b"m2")
    assert b.receive(m2) == b"m2"        # newest arrives first
    assert b.receive(m0) == b"m0"        # older ones from cached skipped keys
    assert b.receive(m1) == b"m1"


def test_session_state_survives_serialisation():
    import json
    a, b = _paired_session()
    b.receive(a.send(b"before"))
    b2 = E.Session.from_dict(json.loads(json.dumps(b.to_dict())))
    assert b2.receive(a.send(b"after")) == b"after", "restored ratchet state must keep working"
