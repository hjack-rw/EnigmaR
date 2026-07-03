"""
EnigmaR engine — umbrella module.

The code is split for size and clarity:
- machine.py — the Enigma mechanism (Rotor / Reflector / Plugboard / Enigma) and
  its runtime dynamics.
- cipher.py  — the crypto layer (key derivation, StreamCipher, Channel, Config).

This module re-exports both so `import enigma as E` still reaches everything.
See PLAN.md for the hardening arc and README.md for usage.
"""
from machine import (  # noqa: F401
    ALPHABET, N, IDX, Alphabet, CLASSIC,
    ROTOR_WIRINGS, ROTOR_NOTCHES, GREEK_ROTORS, REFLECTOR_WIRINGS,
    Rotor, Reflector, Plugboard, Enigma,
)
from cipher import (  # noqa: F401
    Config, derive_machine, StreamCipher, Cascade, Channel,
)


if __name__ == "__main__":
    # Running the engine directly runs its property tests.
    import test_enigma

    test_enigma.run()
