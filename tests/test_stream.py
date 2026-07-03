"""Stage 2: keystream-combiner mode."""
import enigmar as E

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

