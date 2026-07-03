"""
The Enigma machine — core mechanism, no key derivation or crypto layer.

The engine works over an arbitrary alphabet, not a hardcoded 32 symbols:
- `Alphabet("ABC…")` — any set of text symbols.
- `Alphabet.of_bytes()` — all 256 byte values, i.e. encrypt arbitrary binary.
The 32-symbol classic alphabet (`CLASSIC`) is the default so the historical
named rotors/reflectors and the old API keep working.

Everything is `mod N` over `range(N)`; the alphabet is just a codec at the edge.
Explicit Rotor / Reflector / Plugboard objects; a persistent Enigma steps once
per symbol. Canonical double-stepping (M3 / M4) plus opt-in runtime dynamics:
irregular stepping, a moving plugboard, a switching reflector bank, and a
reflectorless (SIGABA-style) path. The crypto layer lives in cipher.py.
"""
from __future__ import annotations

import hashlib


class Alphabet:
    """A codec between user data and integer symbol indices in range(N)."""

    def __init__(self, symbols, *, kind: str = "text"):
        self.kind = kind
        if kind == "text":
            self.symbols = symbols                       # a string
            self.N = len(symbols)
            self.index = {c: i for i, c in enumerate(symbols)}
        else:                                            # "bytes": symbols is N
            self.N = symbols

    @classmethod
    def of_bytes(cls, n: int = 256) -> "Alphabet":
        """Byte alphabet: symbols are the integers 0..n-1. n=256 encrypts any
        binary; smaller n restricts to a byte range."""
        return cls(n, kind="bytes")

    def encode(self, data) -> list[int]:
        if self.kind == "text":
            return [self.index[c] for c in data]
        return list(data)                                # bytes/bytearray -> ints

    def decode(self, ints) -> object:
        if self.kind == "text":
            return "".join(self.symbols[i] for i in ints)
        return bytes(ints)

    def to_index(self, sym) -> int:
        return self.index[sym] if self.kind == "text" else sym

    def from_index(self, i: int):
        return self.symbols[i] if self.kind == "text" else i


CLASSIC = Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ.,!?:'")   # 32 symbols (2**5)

# Back-compat module constants (the classic default).
ALPHABET = CLASSIC.symbols
N = CLASSIC.N
IDX = CLASSIC.index


def _to_index(value, size: int) -> int:
    """Accept a classic symbol ('K'), an index (10), or '-'/'' meaning 0."""
    if isinstance(value, int):
        return value % size
    if value in ("", "-", None):
        return 0
    return CLASSIC.index[value]


def _ints(seq) -> bytes:
    """Serialize a sequence of small ints to bytes (2 per int) for hashing."""
    return b"".join(i.to_bytes(2, "big") for i in seq)


# --- Deterministic byte stream (shared by dynamics and key derivation) ------

def _byte_stream(seed: bytes):
    """Endless deterministic byte stream from a seed (SHA-256 in counter mode).
    Cross-platform reproducible, unlike random.Random."""
    counter = 0
    while True:
        block = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        yield from block
        counter += 1


def _below(stream, k: int) -> int:
    """A value in [0, k) from the stream. Rejection-sampled to stay unbiased."""
    span = 256 ** 2
    limit = span - (span % k)
    while True:
        v = next(stream) << 8 | next(stream)
        if v < limit:
            return v % k


# --- Classic wirings (only meaningful at N=32) ------------------------------

ROTOR_WIRINGS = {
    "1": "ZPRMD'HLKEU,GYOJI:TCNA.?FWVS!QBX",
    "2": "?HJXWVTN.LAKZF!SE:,BG'DUYQPMCORI",
    "3": "AP?NTI'.WV,RJLHXDKEZBMY!CQGS:FUO",
    "4": "BL.I:UNHQXDMTP!',AKFSGVJWO?ZYRCE",
    "5": "NYFQMPG'JUEDIHK.:BOVTW!S?,LRCAXZ",
    "6": "MY!XRWONDTSKV?IZJQUPAEBH,':.LCGF",
    "7": "R:IGZJT,FWMHBYES'UKDCXNV.LQ!AP?O",
    "8": "NWRTKMVYOEPIUDHBFQZ?!L,:CGJSAX.'",
    "B": "TYGK.H?!PFZSINXJULRVODMC',AEB:QW",
    "G": "RHCM'SPFBE,DNUIXK!A.LJTVYQZ?O:WG",
}

ROTOR_NOTCHES = {
    "1": "U", "2": "F", "3": ".", "4": "L", "5": "'",
    "6": "P'", "7": "P'", "8": "P'",
    "B": "", "G": "",
}

GREEK_ROTORS = {"B", "G"}

REFLECTOR_WIRINGS = {
    "A":     "UHYPG'EBKLIJOVMDTZ.QANXWCRS!,:?F",
    "B":     "'!UIX?MYDKJ:GZS,VTORCQ.EHNWPBFLA",
    "C":     "OZEHCGFDQR:P'XALIJW,!YSNVB?TU.KM",
    "Bthin": "WBOPC:I'KZFQ?,REDVXLGUA.!NMJYHST",
    "Cthin": "IQ'FCPSMK!WXGVRDBET?OYAUJH:.LZ,N",
}


# --- Components (operate on integer indices, size N inferred from wiring) ----

class Rotor:
    """A permutation of range(N) with a ring setting and a live position.
    `forward` is a classic wiring string or an integer permutation list."""

    def __init__(self, forward, notches=(), ring=0, position=0, static: bool = False,
                 double_step: bool = True, notch_drift: int = 0, ring_drift: int = 0):
        if isinstance(forward, str):
            forward = [CLASSIC.index[c] for c in forward]
        self.forward = list(forward)
        self.N = len(self.forward)
        self.backward = [0] * self.N
        for i, o in enumerate(self.forward):
            self.backward[o] = i
        if isinstance(notches, str):
            self.notches = {CLASSIC.index[c] for c in notches}
        else:
            self.notches = set(notches)
        self.ring = _to_index(ring, self.N)
        self.position = _to_index(position, self.N)
        self.static = static
        # When False, this rotor skips the Enigma double-step anomaly (it won't
        # self-advance at its own notch). Per-rotor, non-historical, opt-in.
        self.double_step = double_step
        # Keyed drift: the notch (turnover point) and the ring (wiring window)
        # walk over the run, a stride per symbol, so neither setting stays frozen.
        # Live accumulators; reset with the machine, deterministic for both sides.
        self.notch_drift = notch_drift % self.N
        self.ring_drift = ring_drift % self.N
        self._ndrift = 0
        self._rdrift = 0

    @classmethod
    def named(cls, name: str, ring=0, position=0) -> "Rotor":
        return cls(ROTOR_WIRINGS[name], ROTOR_NOTCHES.get(name, ""),
                   ring=ring, position=position, static=name in GREEK_ROTORS)

    @property
    def at_notch(self) -> bool:
        # A static rotor never triggers turnover (else, parked on its notch, it
        # would carry its neighbour every step). Matches the historical Greek rotor.
        # The notch drifts by _ndrift, so the turnover point walks over the run.
        return not self.static and ((self.position - self._ndrift) % self.N) in self.notches

    def step(self) -> None:
        if not self.static:
            self.position = (self.position + 1) % self.N

    def drift(self) -> None:
        """Advance the keyed notch/ring drift one stride. Called once per symbol
        (after turnover is read) so the turnover point and wiring window wander.
        Deterministic, so encrypt and decrypt stay in lockstep."""
        if self.notch_drift:
            self._ndrift = (self._ndrift + self.notch_drift) % self.N
        if self.ring_drift:
            self._rdrift = (self._rdrift + self.ring_drift) % self.N

    def _shift(self) -> int:
        return (self.position - self.ring - self._rdrift) % self.N

    def forward_through(self, c: int) -> int:
        s = self._shift()
        return (self.forward[(c + s) % self.N] - s) % self.N

    def backward_through(self, c: int) -> int:
        s = self._shift()
        return (self.backward[(c + s) % self.N] - s) % self.N


class Reflector:
    """A fixed permutation used as the machine's turning point.

    - **Involution** (map[map[i]] == i): required by default so the machine
      decrypts by re-running the same setup.
    - **Fixed points** (map[i] == i): a symbol reflecting to itself lets the
      whole machine encrypt a symbol to itself, closing the historical "a letter
      never encrypts to itself" crib. An involution with fixed points is still an
      involution, so it stays decryptable.

    `mapping` is a classic wiring string or an integer permutation list.
    """

    def __init__(self, mapping, *, require_involution: bool = True):
        if isinstance(mapping, str):
            mapping = [CLASSIC.index[c] for c in mapping]
        self.map = list(mapping)
        self.N = len(self.map)
        if require_involution and not self.is_involution:
            raise ValueError(
                "reflector wiring is not an involution — the machine would not "
                "decrypt. Pass require_involution=False only if you know why."
            )

    @classmethod
    def named(cls, name: str) -> "Reflector":
        return cls(REFLECTOR_WIRINGS[name])

    @classmethod
    def from_pairs(cls, pairs, size: int = None, *, allow_fixed_points: bool = True) -> "Reflector":
        """Build a guaranteed involution. `pairs` may be classic char pairs
        ('AB CD' or ['AB','CD']) or integer index pairs [(a,b), ...]. Symbols not
        named become fixed points. `size` defaults to the classic alphabet."""
        size = size or CLASSIC.N
        if isinstance(pairs, str):
            pairs = pairs.split()
        mapping = list(range(size))
        used: set[int] = set()
        for pair in pairs:
            if len(pair) != 2:
                raise ValueError(f"each pair needs exactly 2 symbols, got {pair!r}")
            a, b = (CLASSIC.index[pair[0]], CLASSIC.index[pair[1]]) if isinstance(pair, str) else pair
            if a == b:
                raise ValueError(f"cannot pair a symbol with itself: {pair!r}")
            if a in used or b in used:
                raise ValueError(f"symbol reused across pairs: {pair!r}")
            used |= {a, b}
            mapping[a], mapping[b] = b, a
        refl = cls(mapping)
        if not allow_fixed_points and refl.has_fixed_point:
            raise ValueError("wiring leaves fixed points but allow_fixed_points=False")
        return refl

    @property
    def is_involution(self) -> bool:
        return all(self.map[self.map[i]] == i for i in range(self.N))

    @property
    def has_fixed_point(self) -> bool:
        return any(self.map[i] == i for i in range(self.N))

    @property
    def fixed_points(self) -> list[int]:
        return [i for i in range(self.N) if self.map[i] == i]

    def reflect(self, c: int) -> int:
        return self.map[c]


class Plugboard:
    """Symmetric swaps. `pairs` may be classic char pairs ('AB CD') or integer
    index pairs [(a, b), ...]. `size` defaults to the classic alphabet."""

    def __init__(self, pairs=(), size: int = None):
        self.N = size or CLASSIC.N
        self.map = list(range(self.N))
        if isinstance(pairs, str):
            pairs = pairs.split()
        for pair in pairs:
            a, b = (CLASSIC.index[pair[0]], CLASSIC.index[pair[1]]) if isinstance(pair, str) else pair
            self.map[a], self.map[b] = b, a

    def swap(self, c: int) -> int:
        return self.map[c]


# --- Machine ----------------------------------------------------------------

class Enigma:
    """Rotors are given left-to-right; the rightmost is the fast rotor.

    Opt-in runtime dynamics (all keyed, all reproducible for encrypt/decrypt):
    - step_stream: SIGABA-style irregular stepping (which rotors take an extra
      step). None -> canonical stepping.
    - plug_shift: rotate the plugboard by this stride each symbol (0 -> static).
    - reflector_bank + refl_stream: switch among several reflectors on a keyed
      schedule.
    - reflector=None with no bank: forward-only path (SIGABA had no reflector).
      NOT an involution -> keystream use only; classic .encode won't self-invert.
    """

    def __init__(self, rotors, reflector: Reflector | None, plugboard: Plugboard | None = None,
                 step_stream=None, plug_shift: int = 0, reflector_bank=None, refl_stream=None,
                 plug_stream=None, alphabet: Alphabet = CLASSIC):
        if len(rotors) < 2:
            raise ValueError("this machine needs at least 2 rotors")
        self.alphabet = alphabet
        self.N = alphabet.N
        self.rotors = list(rotors)
        self.reflector = reflector
        self.plugboard = plugboard or Plugboard(size=self.N)
        self.step_stream = step_stream
        self.plug_shift = plug_shift % self.N
        self._plug_offset = 0
        # A keyed byte stream jolting the plugboard offset irregularly each symbol
        # (vs plug_shift's fixed stride): the plug wiring is re-seated on an
        # unpredictable schedule instead of marching. None -> no jolt.
        self.plug_stream = plug_stream
        self.reflector_bank = reflector_bank
        self.refl_stream = refl_stream
        # Hot-loop fast-path flags (config is fixed for a machine's lifetime):
        # skip the per-symbol plugboard-offset math and drift walk when unused.
        self._simple_plug = not self.plug_shift and self.plug_stream is None
        self._any_drift = any(r.notch_drift or r.ring_drift for r in self.rotors)
        self._nrotors = len(self.rotors)
        self._simple_reflector = self.reflector_bank is None

    @classmethod
    def configure(cls, rotor_names, reflector_name, positions="", rings="", plugs=""):
        rotors = []
        for i, name in enumerate(rotor_names):
            rotors.append(Rotor.named(name, ring=_ring(rings, i), position=_ring(positions, i)))
        return cls(rotors, Reflector.named(reflector_name), Plugboard(plugs))

    def _advance(self) -> None:
        """Canonical double-stepping, generalised. Notches read BEFORE any rotor
        moves; static (Greek) rotors never move."""
        rotors = self.rotors
        n = self._nrotors
        # Inline of Rotor.at_notch to avoid n property dispatches per symbol.
        notch = [(not r.static) and (((r.position - r._ndrift) % r.N) in r.notches)
                 for r in rotors]
        will_step = [False] * n
        will_step[-1] = True
        for i in range(n - 1):
            if notch[i + 1]:
                will_step[i] = True
        for i in range(1, n - 1):
            if notch[i] and rotors[i].double_step:        # double-step anomaly (per-rotor)
                will_step[i] = True
        for r, do in zip(rotors, will_step):
            if do:
                r.step()

        # Irregular stepping, SIGABA-style: a keyed byte decides WHICH rotors take
        # an extra step this tick. Keyed only (not plaintext), so it still decrypts
        # and internal positions can't be read off the message index.
        if self.step_stream is not None:
            gate = next(self.step_stream)
            for i, r in enumerate(self.rotors):
                if not r.static and (gate >> i) & 1:
                    r.step()

        if self.plug_shift:
            self._plug_offset = (self._plug_offset + self.plug_shift) % self.N
        if self.plug_stream is not None:                  # keyed irregular re-seat
            self._plug_offset = (self._plug_offset + next(self.plug_stream)) % self.N
        if self._any_drift:                               # keyed notch/ring drift
            for r in self.rotors:
                r.drift()

    def _plug(self, c: int) -> int:
        """Plugboard swap at the current rotation offset. Conjugating an
        involution by a rotation keeps it an involution, so it stays reversible."""
        if not self.plug_shift and self.plug_stream is None:
            return self.plugboard.swap(c)
        off = self._plug_offset
        return (self.plugboard.map[(c - off) % self.N] + off) % self.N

    def _active_reflector(self) -> Reflector | None:
        if self.reflector_bank is not None:
            return self.reflector_bank[_below(self.refl_stream, len(self.reflector_bank))]
        return self.reflector

    def encode_index(self, i: int) -> int:
        """The core transform on an integer symbol in range(N).

        The rotor passes are inlined here (rather than calling the Rotor
        methods) so the shift is computed once per rotor per symbol instead of
        recomputed on each forward/backward hop, and the whole path stays in
        local variables. Output is identical to Rotor.forward_through/backward_through.
        """
        self._advance()
        N = self.N
        rotors = self.rotors
        n = self._nrotors
        pmap = self.plugboard.map
        simple = self._simple_plug
        c = pmap[i] if simple else self._plug(i)
        # Position is fixed for this symbol, so each rotor's shift is constant.
        shifts = [(r.position - r.ring - r._rdrift) % N for r in rotors]
        reflector = self.reflector if self._simple_reflector else self._active_reflector()
        for k in range(n - 1, -1, -1):                    # forward: fast rotor first
            r, s = rotors[k], shifts[k]
            c = (r.forward[(c + s) % N] - s) % N
        if reflector is not None:
            c = reflector.map[c]
            for k in range(n):                            # backward: slow rotor first
                r, s = rotors[k], shifts[k]
                c = (r.backward[(c + s) % N] - s) % N
        return pmap[c] if simple else self._plug(c)

    def encode_char(self, sym):
        return self.alphabet.from_index(self.encode_index(self.alphabet.to_index(sym)))

    def encode(self, data):
        return self.alphabet.decode([self.encode_index(i) for i in self.alphabet.encode(data)])

    def fingerprint(self) -> bytes:
        """Deterministic hash of the full config (before stepping). Same config
        -> same fingerprint, seeding a reproducible keystream input driver."""
        h = hashlib.sha256()
        h.update(self.N.to_bytes(2, "big"))
        for r in self.rotors:
            h.update(_ints(r.forward))
            h.update(_ints([r.ring, r.position, int(r.static), int(r.double_step),
                            r.notch_drift, r.ring_drift]))
            h.update(_ints(sorted(r.notches)))
        h.update(_ints([self.plug_shift, int(self.plug_stream is not None)]))
        h.update(_ints(self.plugboard.map))
        for refl in (self.reflector_bank or ([self.reflector] if self.reflector else [])):
            h.update(_ints(refl.map))
        return h.digest()


def _ring(seq, i, default=0):
    """Index into a positions/rings string, tolerating '-' separators and gaps."""
    seq = (seq or "").replace("-", "")
    return seq[i] if i < len(seq) else default
