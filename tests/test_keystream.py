"""Keystream quality gate."""
import enigmar as E

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

