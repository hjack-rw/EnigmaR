"""
EnigmaR — an Enigma-style keystream cipher, trimmed to the sealed-codes core.

This is the lean `main` build: just the mechanism, the keystream cipher, and the
format-preserving-encryption layer that the codes are built on. The full engine
(Diffie-Hellman handshake, per-message ratchet, end-to-end session, the socket
chat) lives on the `engine` branch; the original 2020 BSc Flask app is on `thesis`.

- machine — the Enigma mechanism (Rotor / Reflector / Plugboard / Enigma) + dynamics
- cipher  — the crypto layer (key derivation, StreamCipher, Cascade, Channel, Config)
- fpe     — format-preserving encryption (FPE) over a character domain

`import enigmar as E` reaches it all. See README.md for the story, DESIGN.md for rationale.
"""
from .machine import (  # noqa: F401
    ALPHABET, N, IDX, Alphabet, CLASSIC,
    ROTOR_WIRINGS, ROTOR_NOTCHES, GREEK_ROTORS, REFLECTOR_WIRINGS,
    Rotor, Reflector, Plugboard, Enigma,
)
from .cipher import (  # noqa: F401
    Config, derive_machine, StreamCipher, Cascade, Channel,
)
from .fpe import FPE  # noqa: F401
