"""
Art for art's sake: max the config, count the configurations, prove it still
round-trips. Nominal config space is unbounded (~R * log2(N!)); here we pick a
big-but-runnable point and show the astronomical number is real, not a claim.

    python maxout.py

Not security — everything past 2**256 is diffusion. This is the aesthetics of the
number, and a demonstration that the engine holds together at absurd scale.
"""
import math
import os
import time

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import enigmar as E

N = 4096          # alphabet size (symbols)
R = 256           # rotors


def main() -> None:
    symbols = "".join(chr(0x4E00 + i) for i in range(N))   # N distinct CJK symbols
    alpha = E.Alphabet(symbols)

    log2_Nfact = math.lgamma(N + 1) * math.log2(math.e)     # bits per rotor wiring
    bits = (R * log2_Nfact          # R rotor wirings (dominant)
            + log2_Nfact            # plugboard permutation
            + log2_Nfact            # reflector permutation
            + 2 * R * math.log2(N))  # R positions + R ring settings
    digits = bits * math.log10(2)

    print(f"config: N={N} symbols, R={R} rotors")
    print(f"  bits per rotor wiring = log2({N}!) ~ {log2_Nfact:,.0f}")
    print(f"  distinct machines     ~ 2^{bits:,.0f}")
    print(f"                        ~ 10^{digits:,.0f}   (a {int(digits):,}-digit number)")

    t = time.time()
    sc = E.StreamCipher.from_passphrase("art", nonce="1", alphabet=alpha,
                                        n_rotors=R, chaos=True, keyfile=os.urandom(128))
    msg = symbols[1000:1040]
    ct = sc.encrypt(msg)
    ok = sc.decrypt(ct) == msg
    print(f"\nround-trip through the maxed machine: {'OK' if ok else 'FAIL'}"
          f"   [{time.time() - t:.1f}s]")


if __name__ == "__main__":
    main()
