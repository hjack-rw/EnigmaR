"""Format-preserving encryption helper: shape preserved, reversible, keyed."""
import enigmar as E

DIGITS = "0123456789"


def test_round_trips_and_preserves_separators():
    fpe = E.FPE("pw", DIGITS, nonce="t")
    src = "4111 1111-1111.1111"
    tok = fpe.encrypt(src)
    assert fpe.decrypt(tok) == src
    # separators stay put, in place; digits change domain-for-domain
    assert [c for c in tok if not c.isdigit()] == [" ", "-", "."]
    assert len(tok) == len(src)
    assert all(c.isdigit() for a, c in zip(src, tok) if a.isdigit())


def test_keep_prefix_is_fixed():
    fpe = E.FPE("pw", DIGITS, nonce="t", keep_prefix=6)
    src = "44051401359"
    tok = fpe.encrypt(src)
    assert tok[:6] == src[:6]          # birth-date head untouched
    assert fpe.decrypt(tok) == src


def test_checksum_recomputed_valid_by_construction():
    def luhn(payload):
        total = 0
        for i, d in enumerate(reversed([int(c) for c in payload])):
            d = d * 2 if i % 2 == 0 else d
            total += d - 9 if d > 9 else d
        return str((10 - total % 10) % 10)

    def valid(card):
        d = [int(c) for c in card]
        # recompute over all but last, compare to last
        return luhn(card[:-1]) == card[-1]

    fpe = E.FPE("pw", DIGITS, nonce="card", checksum=luhn)
    pan = "4111111111111111"
    assert valid(pan)
    tok = fpe.encrypt(pan)
    assert valid(tok)                  # output validates by construction
    assert fpe.decrypt(tok) == pan


def test_deterministic_and_key_dependent():
    a = E.FPE("pw", DIGITS, nonce="t")
    b = E.FPE("pw", DIGITS, nonce="t")
    c = E.FPE("other", DIGITS, nonce="t")
    assert a.encrypt("123456") == b.encrypt("123456")     # same key -> same map
    assert a.encrypt("123456") != c.encrypt("123456")     # different key -> different


def test_nothing_to_encrypt_raises():
    fpe = E.FPE("pw", DIGITS, nonce="t", keep_prefix=5)
    try:
        fpe.encrypt("12")             # fewer payload symbols than kept
    except ValueError:
        return
    raise AssertionError("should refuse when the encrypt window is empty")
