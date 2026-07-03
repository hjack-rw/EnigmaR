"""
Keystream quality gate.

The keystream's statistical quality tracks the entropy of the input driving the
machine, so it's worth measuring. These tests can only *falsify* randomness (find
a pattern) — they never *prove* it, and they are far weaker than a real battery
(NIST STS / PractRand / Dieharder). For that, dump bytes and feed one:

    python randtest.py                     # in-process report (fast, ~200k)
    python randtest.py dump ks.bin 5000000 # write N keystream bytes for a battery

Then, e.g.:  ent ks.bin   |   practrand < ks.bin   |   dieharder -a -f ks.bin
(ent is instant; PractRand wants a few MB; Dieharder wants a LOT — and generating
that many bytes in pure Python is the slow part, so pick a size to match.)
"""
import math
import sys
import zlib
import statistics
from collections import Counter

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import enigmar as E


def keystream_indices(n, passphrase="benchmark", nonce="test"):
    """Classic-alphabet keystream as a list of symbol indices."""
    sc = E.StreamCipher.from_passphrase(passphrase, nonce=nonce)
    return [E.IDX[c] for c in sc.keystream(n)]


def keystream_bytes(n, passphrase="benchmark", nonce="test"):
    """Byte-mode keystream as raw bytes."""
    sc = E.StreamCipher.from_passphrase(passphrase, nonce=nonce, alphabet=E.Alphabet.of_bytes())
    return sc.keystream(n)


# --- metrics ----------------------------------------------------------------

def chi_square(vals, k=E.N):
    counts = Counter(vals)
    expected = len(vals) / k
    return sum((counts[i] - expected) ** 2 / expected for i in range(k))


def autocorr(vals, lag=1):
    mean = statistics.fmean(vals)
    num = sum((vals[i] - mean) * (vals[i + lag] - mean) for i in range(len(vals) - lag))
    den = sum((v - mean) ** 2 for v in vals)
    return num / den if den else 0.0


def autocorr_lag1(vals):
    return autocorr(vals, 1)


def entropy_bits(vals, k):
    """Shannon entropy in bits/symbol; ideal is log2(k)."""
    counts = Counter(vals)
    n = len(vals)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def compression_ratio(data: bytes) -> float:
    """Compressed size / original. ~1.0 means incompressible (no exploitable
    structure); < 1 means a compressor found redundancy."""
    return len(zlib.compress(bytes(data), 9)) / len(data)


def monobit_fraction(data: bytes):
    """Fraction of 1-bits (ideal 0.5) and its z-score (|z| < ~3 is fine)."""
    ones = sum(bin(b).count("1") for b in data)
    nbits = len(data) * 8
    frac = ones / nbits
    z = abs(ones - nbits / 2) / (0.5 * math.sqrt(nbits))
    return frac, z


# --- reports ----------------------------------------------------------------

def report(n=100_000):
    """The gate used by the tests: classic-alphabet chi + lag-1 autocorrelation."""
    ks = keystream_indices(n)
    chi, ac = chi_square(ks), autocorr_lag1(ks)
    print(f"classic n={n}")
    print(f"  chi-square (31 dof, ideal ~31, 0.01 crit ~52): {chi:8.1f}"
          f"  -> {'uniform' if chi < 52 else 'BIASED'}")
    print(f"  lag-1 autocorrelation (ideal 0):               {ac:+8.5f}"
          f"  -> {'independent' if abs(ac) < 0.01 else 'CORRELATED'}")
    return chi, ac


def deep_report(n=200_000):
    """Stronger in-process report over a byte-mode keystream."""
    b = keystream_bytes(n)
    v = list(b)
    lags = [round(autocorr(v, l), 4) for l in (1, 2, 3, 8, 16, 32)]
    frac, z = monobit_fraction(b)
    print(f"\nbyte mode n={n}")
    print(f"  entropy:      {entropy_bits(v, 256):.4f} / 8 bits")
    print(f"  chi-square:   {chi_square(v, 256):.1f}  (255 dof, ideal ~255, 0.01 crit ~330)")
    print(f"  zlib ratio:   {compression_ratio(b):.4f}  (ideal ~1.0, incompressible)")
    print(f"  monobit:      {frac:.5f} ones  (ideal 0.5, |z|={z:.2f})")
    print(f"  autocorr @ lags 1,2,3,8,16,32: {lags}")
    print("\nnote: these falsify patterns, they do not prove randomness. For a")
    print("real verdict run a battery on dumped bytes (see the module docstring).")


def dump(path, n_bytes, passphrase="benchmark", nonce="test"):
    with open(path, "wb") as f:
        f.write(keystream_bytes(int(n_bytes), passphrase, nonce))
    print(f"wrote {n_bytes} keystream bytes to {path}")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "dump":
        dump(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else 1_000_000)
    else:
        report()
        deep_report()
