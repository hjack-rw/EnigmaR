"""
Crypto layer over the Enigma machine: key derivation, the keystream cipher,
and a nonce-disciplined channel. Pure stdlib (hashlib + secrets).

Works over any alphabet — pass `alphabet=Alphabet.of_bytes()` to encrypt
arbitrary binary, or a custom `Alphabet("…")` for a custom symbol set. Defaults
to the 32-symbol classic alphabet.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .machine import (
    CLASSIC, Reflector, Plugboard, Rotor, Enigma, _byte_stream, _below, _ints,
)

# scrypt cost. The only remaining attack on the engine is guessing the passphrase,
# so this is the number that must hurt: 2**16 (~64 MB, ~tens of ms) per guess.
# Raise it as hardware improves; expose it as kdf_n for callers who want more.
_SCRYPT_N = 2 ** 16
_SCRYPT_R = 8
_SCRYPT_P = 1

# The whole machine is a deterministic function of the seed, so the seed's length
# is the hard ceiling on how many distinct machines can ever exist (pigeonhole):
# a 128-byte seed caps it at 2**1024, well past any real passphrase's entropy, so
# the mechanism is never the bottleneck — the passphrase is.
_SEED_DKLEN = 128


def _scrypt(passphrase, salt: bytes, *, n: int = _SCRYPT_N, dklen: int = 64) -> bytes:
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()
    # scrypt needs ~128*r*n bytes; OpenSSL caps at 32 MB by default, so lift the
    # ceiling to fit the chosen cost (with headroom) instead of erroring out.
    maxmem = 130 * _SCRYPT_R * n
    return hashlib.scrypt(passphrase, salt=salt, n=n, r=_SCRYPT_R, p=_SCRYPT_P,
                          dklen=dklen, maxmem=maxmem)


@dataclass
class Config:
    """The knobs, in one place. Pass a Config's fields as keywords via
    `**vars(cfg)`, or just pass the keywords directly."""
    alphabet: object = None         # None -> classic 32; Alphabet.of_bytes() etc.
    n_rotors: object = 3            # int, or (lo, hi) for a key-picked count
    irregular_step: bool = False    # SIGABA-style keyed stepping
    moving_plugboard: bool = False  # plugboard rotates each symbol
    reflectors: object = 1          # int, or (lo, hi) for a key-picked bank size
    reflectorless: bool = False     # drop the reflector (keystream use only)
    double_step: bool = True        # historical double-step anomaly (all rotors)
    randomize_double_step: bool = False  # instead pick it per rotor from the key
    randomize_static: bool = False  # any rotor keyed-static (fast rotor still moves)
    drift: bool = False             # notch/ring/plugboard walk over the run (keyed)
    chaos: bool = False             # turn every keyed dynamic on at once


# --- derivation helpers (build integer permutations of size N) --------------

def _shuffle(seq, stream) -> list:
    """Fisher-Yates shuffle driven by the byte stream."""
    a = list(seq)
    for i in range(len(a) - 1, 0, -1):
        j = _below(stream, i + 1)
        a[i], a[j] = a[j], a[i]
    return a


def _consecutive_pairs(perm, count):
    return [(perm[2 * i], perm[2 * i + 1]) for i in range(count)]


def _derive_rotor(stream, N, double_step=True, static=False, drift=False) -> Rotor:
    forward = _shuffle(range(N), stream)

    def stride():                                        # keyed nonzero walk, or frozen
        return 1 + _below(stream, N - 1) if drift and N > 1 else 0

    notch_drift, ring_drift = stride(), stride()         # notch first, then ring
    return Rotor(forward, notches={_below(stream, N)},
                 ring=_below(stream, N), position=_below(stream, N),
                 double_step=double_step, static=static,
                 notch_drift=notch_drift, ring_drift=ring_drift)


def _derive_involution(stream, N) -> Reflector:
    """A fixed-point involution: leave a few symbols unpaired so a symbol can
    encrypt to itself (crib closed)."""
    perm = _shuffle(range(N), stream)
    n_fixed = 2 + _below(stream, max(1, N // 8))
    if (N - n_fixed) % 2:
        n_fixed += 1
    return Reflector.from_pairs(_consecutive_pairs(perm, (N - n_fixed) // 2), N)


def _derive_plugboard(stream, N) -> Plugboard:
    perm = _shuffle(range(N), stream)
    return Plugboard(_consecutive_pairs(perm, _below(stream, max(1, N // 4))), size=N)


def _derive_reflection(stream, N, reflectorless, reflectors):
    """Return (reflector, reflector_bank, plugboard)."""
    if reflectorless:
        return None, None, _derive_plugboard(stream, N)
    if reflectors > 1:
        bank = [_derive_involution(stream, N) for _ in range(reflectors)]
        return None, bank, _derive_plugboard(stream, N)
    return _derive_involution(stream, N), None, _derive_plugboard(stream, N)


def _combine_secret(passphrase, keyfile) -> bytes:
    """Fold a second secret (keyfile) into the passphrase before the KDF. Two
    independent secrets → their entropies add (both stretched by scrypt). Length-
    prefixed so ('ab','c') and ('a','bc') can't collide. Empty keyfile = no-op."""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()
    if not keyfile:
        return passphrase
    if isinstance(keyfile, str):
        keyfile = keyfile.encode()
    return len(passphrase).to_bytes(4, "big") + passphrase + keyfile


def derive_machine(passphrase, *, nonce=b"", alphabet=None, n_rotors=3,
                   irregular_step: bool = False, moving_plugboard: bool = False,
                   reflectors: int = 1, reflectorless: bool = False,
                   double_step: bool = True, randomize_double_step: bool = False,
                   randomize_static: bool = False, drift: bool = False, chaos: bool = False,
                   keyfile: bytes = b"", kdf_n: int = _SCRYPT_N,
                   salt: bytes = b"enigmar-stage3") -> Enigma:
    """Derive a full Enigma from a passphrase. Same (passphrase, nonce, options)
    always yields the same machine. Works over any alphabet.

    n_rotors is an int, or a (lo, hi) range from which the count is picked by the
    key (so both ends agree). reflectors is likewise an int or a (lo, hi) range.
    double_step / randomize_double_step control the double-step anomaly.
    randomize_static makes any rotor keyed-static (the fast rotor always moves).
    drift makes the notch, ring window, and plugboard walk over the run (keyed, so
    both sides stay in lockstep). chaos turns every keyed dynamic on at once.
    keyfile is an optional second secret (bytes/str) mixed into the KDF — the one
    knob that adds real key entropy, since it is independent secret material.
    """
    alphabet = alphabet or CLASSIC
    N = alphabet.N
    secret = _combine_secret(passphrase, keyfile)
    if isinstance(nonce, str):
        nonce = nonce.encode()

    seed = _scrypt(secret, salt + nonce, n=kdf_n, dklen=_SEED_DKLEN)
    stream = _byte_stream(seed)

    if chaos:
        irregular_step = moving_plugboard = randomize_double_step = True
        randomize_static = drift = True
        if n_rotors == 3:
            n_rotors = (3, 12)
        if reflectors == 1:
            reflectors = (1, 4)                          # keyed bank size 1..4

    def pick(value):                                     # int stays; (lo, hi) -> keyed
        if isinstance(value, (tuple, list)):
            lo, hi = value
            return lo + _below(stream, hi - lo + 1)
        return value

    n_rotors = pick(n_rotors)                            # count, then bank size
    if n_rotors < 2:
        raise ValueError("n_rotors must be >= 2")
    reflectors = pick(reflectors)

    def rotor_ds():
        return bool(_below(stream, 2)) if randomize_double_step else double_step

    def rotor_static():
        return bool(_below(stream, 2)) if randomize_static else False

    rotors = [_derive_rotor(stream, N, rotor_ds(), rotor_static(), drift) for _ in range(n_rotors)]
    rotors[-1].static = False                            # the fast rotor must move
    reflector, bank, plugboard = _derive_reflection(stream, N, reflectorless, reflectors)

    def substream(tag):
        return _byte_stream(hashlib.sha256(seed + tag).digest())

    return Enigma(
        rotors, reflector, plugboard,
        step_stream=substream(b"step") if irregular_step else None,
        plug_shift=(_below(stream, max(1, N // 2)) * 2 + 1) if moving_plugboard else 0,
        reflector_bank=bank,
        refl_stream=substream(b"refl") if bank else None,
        plug_stream=substream(b"plug") if drift else None,
        alphabet=alphabet,
    )


# --- keystream cipher -------------------------------------------------------

class StreamCipher:
    """Run an Enigma as a keystream generator and combine by modular add.

    A reversible symmetric cipher — deterministic by design (it must reproduce
    the keystream to decrypt). The goal is cost, not impossibility.

        encrypt:  C_i = (P_i + K_i) mod N
        decrypt:  P_i = (C_i - K_i) mod N

    An additive combiner has none of the reflecting-substitution structure — no
    "a symbol never encrypts to itself" property, no reciprocal pairing.

    - Deterministic in the config, so a (key, nonce) pair must NEVER be reused:
      two messages under one keystream satisfy C1 - C2 == P1 - P2 (two-time-pad).
      Enforced by Channel.
    - Statistical quality tracks the entropy of the input driving the machine, so
      it is fed the config-fingerprint byte stream (uniform; randtest.py gates it).
    """

    def __init__(self, machine_factory):
        self._make = machine_factory

    @classmethod
    def from_passphrase(cls, passphrase, *, nonce=b"", **opts) -> "StreamCipher":
        """Derive the whole secret machine from a passphrase (never transmitted)
        and run it as a keystream cipher. `opts` are any derive_machine options
        (alphabet, n_rotors, irregular_step, moving_plugboard, reflectors,
        reflectorless)."""
        return cls(lambda: derive_machine(passphrase, nonce=nonce, **opts))

    def keystream(self, n: int):
        m = self._make()
        feed = _byte_stream(m.fingerprint())
        return m.alphabet.decode([m.encode_index(_below(feed, m.N)) for _ in range(n)])

    def _combine(self, data, sign: int):
        # High-entropy input (config-fingerprint byte stream), not a periodic
        # counter: a period-N counter resonates with the fast rotor (also period
        # N) and biases/correlates the keystream (measured; see randtest.py).
        m = self._make()
        feed = _byte_stream(m.fingerprint())
        ints = m.alphabet.encode(data)
        out = [(i + sign * m.encode_index(_below(feed, m.N))) % m.N for i in ints]
        return m.alphabet.decode(out)

    def encrypt(self, plaintext):
        return self._combine(plaintext, +1)

    def decrypt(self, ciphertext):
        return self._combine(ciphertext, -1)


# --- cascade: chain several machines in series ------------------------------

def _layer_nonce(nonce, i: int) -> bytes:
    b = nonce.encode() if isinstance(nonce, str) else bytes(nonce)
    return b + b"|layer" + str(i).encode()


class Cascade:
    """Chain several StreamCiphers — "x enigmas of different configs" wired in
    series. Encryption runs the layers in order; decryption unwinds them in
    reverse. Every layer is an additive keystream over the same alphabet, so the
    stack stays reversible no matter how the individual machines differ.

    Each layer gets its own derivation tag, so even identical options yield
    distinct machines. `stages` is either an int (that many layers, each built
    from `**opts`) or a list of per-layer option dicts (genuinely different
    configs — one reflectorless, one chaos, one plain, whatever).

        Cascade("pw", 3, chaos=True)                      # 3 chaos machines
        Cascade("pw", [dict(chaos=True), dict(reflectorless=True), {}])

    Same nonce discipline as StreamCipher: deterministic in (passphrase, nonce),
    so never reuse a nonce for two messages. Wrap in a Channel-style loop for that.
    """

    def __init__(self, passphrase, stages, *, nonce=b"", **opts):
        if isinstance(stages, int):
            stages = [dict(opts) for _ in range(stages)]
        if not stages:
            raise ValueError("a cascade needs at least one layer")
        self._layers = [
            StreamCipher.from_passphrase(passphrase, nonce=_layer_nonce(nonce, i), **st)
            for i, st in enumerate(stages)
        ]

    def encrypt(self, data):
        for layer in self._layers:
            data = layer.encrypt(data)
        return data

    def decrypt(self, data):
        for layer in reversed(self._layers):
            data = layer.decrypt(data)
        return data


# --- nonce-disciplined channel (the easy interface) -------------------------

class Channel:
    """Configure once, send/receive, never reuse a nonce.

        alice = Channel("passphrase", irregular_step=True, moving_plugboard=True)
        nonce, ct = alice.send("MEET.AT.DAWN")   # nonce public, passphrase secret
        bob.receive(nonce, ct)

    Any derive_machine option passes through as a keyword (including `alphabet`
    for byte mode or a custom symbol set). `send` mints a fresh 128-bit nonce and
    refuses an explicit repeat; `receive` rejects replays.

    Authenticated (encrypt-then-MAC): `send` returns a tag alongside the
    ciphertext, `receive` verifies it before decrypting and raises on any
    tampering. A stream cipher alone is malleable — a flipped ciphertext symbol is
    a controlled change to the plaintext; the MAC closes that. The MAC key is
    derived from the passphrase under a separate salt, independent of the machine.
    """

    def __init__(self, passphrase, *, kdf_n: int = _SCRYPT_N, keyfile: bytes = b"", **opts):
        self._pass = passphrase
        self._opts = dict(opts, kdf_n=kdf_n, keyfile=keyfile)
        self._alphabet = opts.get("alphabet") or CLASSIC
        # MAC key also binds the keyfile, so a wrong keyfile fails authentication too.
        self._mackey = _scrypt(_combine_secret(passphrase, keyfile), b"enigmar-mac",
                               n=kdf_n, dklen=32)
        self._used: set[str] = set()
        self._seen: set[str] = set()

    def _cipher(self, nonce: str) -> StreamCipher:
        return StreamCipher.from_passphrase(self._pass, nonce=nonce, **self._opts)

    def _tag(self, nonce: str, ciphertext) -> str:
        """HMAC-SHA256 over nonce ‖ ciphertext. Ciphertext is serialised through
        the alphabet's indices so text and byte modes hash unambiguously."""
        mac = hmac.new(self._mackey, digestmod="sha256")
        mac.update(nonce.encode())
        mac.update(_ints(self._alphabet.encode(ciphertext)))
        return mac.hexdigest()

    def send(self, plaintext, *, nonce: str | None = None):
        """Return (nonce, ciphertext, tag). nonce and tag are public; the
        passphrase is secret. Encrypt-then-MAC."""
        if nonce is None:
            nonce = secrets.token_hex(16)     # 128-bit
        if nonce in self._used:
            raise ValueError("nonce reuse — a nonce must never be reused for sending")
        self._used.add(nonce)
        ciphertext = self._cipher(nonce).encrypt(plaintext)
        return nonce, ciphertext, self._tag(nonce, ciphertext)

    def receive(self, nonce: str, ciphertext, tag: str, *, allow_replay: bool = False):
        """Verify the tag, then decrypt. Raises on tampering or replay."""
        if not hmac.compare_digest(self._tag(nonce, ciphertext), tag):
            raise ValueError("authentication failed — ciphertext/nonce tampered or wrong key")
        if not allow_replay and nonce in self._seen:
            raise ValueError("nonce replay — this nonce was already accepted")
        self._seen.add(nonce)
        return self._cipher(nonce).decrypt(ciphertext)
