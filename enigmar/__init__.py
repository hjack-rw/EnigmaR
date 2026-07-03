"""
EnigmaR — an Enigma-style keystream cipher engine (package umbrella).

The library is split by layer; this package re-exports everything, so
`import enigmar as E` reaches it all:

- machine  — the Enigma mechanism (Rotor / Reflector / Plugboard / Enigma) + dynamics
- cipher   — the crypto layer (key derivation, StreamCipher, Cascade, Channel, Config)
- kex      — Diffie-Hellman handshake (Handshake / Identity / authenticated_key)
- ratchet  — per-message key ratchet (forward secrecy)
- session  — end-to-end send/receive session (Session), with a DH ratchet

Entry points live at the repo root: test_enigma.py (tests), randtest.py (keystream
gate), cli.py, demo.py, maxout.py. See README.md for usage, DESIGN.md for rationale.
"""
from .machine import (  # noqa: F401
    ALPHABET, N, IDX, Alphabet, CLASSIC,
    ROTOR_WIRINGS, ROTOR_NOTCHES, GREEK_ROTORS, REFLECTOR_WIRINGS,
    Rotor, Reflector, Plugboard, Enigma,
)
from .cipher import (  # noqa: F401
    Config, derive_machine, StreamCipher, Cascade, Channel,
)
from .kex import Handshake, Identity, authenticated_key  # noqa: F401
from .ratchet import Ratchet  # noqa: F401
from .session import Session  # noqa: F401
