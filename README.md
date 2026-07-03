# EnigmaR — engine

A standalone Enigma-style keystream cipher over an **arbitrary alphabet** (32-symbol
classic by default, byte mode for any binary, or a custom symbol set), extended and
hardened well past the museum machine — pure standard library, no dependencies.

The library is the `enigmar/` package: `machine` (the mechanism), `cipher` (key
derivation, keystream cipher, channel), `kex` (Diffie-Hellman handshake), `ratchet`
and `session` (per-message keys + end-to-end sessions). `import enigmar` reaches it all.

## Easy interface

Configure once, send/receive; nonce reuse handled for you and every message is
authenticated (encrypt-then-MAC):

```python
from enigmar import Channel, Config

cfg = Config(n_rotors=4, irregular_step=True, moving_plugboard=True, reflectors=3)
alice = Channel("shared-passphrase", **vars(cfg))
bob   = Channel("shared-passphrase", **vars(cfg))

nonce, ct, tag = alice.send("MEET.AT.DAWN")     # nonce/tag public, passphrase secret
assert bob.receive(nonce, ct, tag) == "MEET.AT.DAWN"   # raises if tampered
```

Dynamics (all opt-in, all keyed off the passphrase):

| option | effect |
|---|---|
| `alphabet` | any symbol set — `Alphabet.of_bytes()` encrypts arbitrary binary, `Alphabet("ACGT")` a custom set (default: 32-symbol classic) |
| `n_rotors` | rotor count — an int, or `(lo, hi)` for a key-picked count (≥ 2, no upper cap) |
| `irregular_step` | SIGABA-style keyed stepping — which rotors advance is unpredictable |
| `moving_plugboard` | plugboard rotates each symbol |
| `reflectors=k` | switch among a keyed bank of reflectors — an int, or `(lo, hi)` for a key-picked bank size |
| `reflectorless` | drop the reflector (no reciprocity / no self-map crib) |
| `double_step` | toggle the historical double-step anomaly (all rotors) |
| `randomize_double_step` | pick the double-step per rotor from the key |
| `randomize_static` | any rotor may be keyed-static (the fast rotor always moves) |
| `drift` | the notch, ring window, and plugboard **walk over the run** — no setting stays frozen |
| `keyfile` | a second independent secret (bytes/str) mixed into the KDF — the one knob that adds real key entropy |
| `chaos` | turn **every** keyed dynamic on at once |

```python
# maximum entropy in the config: everything the key can vary, varies
ch = Channel("passphrase", chaos=True)
```

Cascade — chain several machines of different configs in series (each its own keyed
Enigma; the stack stays reversible because every layer is an additive keystream):

```python
from enigmar import Cascade
cas = Cascade("passphrase", [dict(chaos=True), dict(reflectorless=True), dict(drift=True)])
ct = cas.encrypt("MEET.AT.DAWN")            # decrypt unwinds the layers in reverse
```

Byte mode — the same engine on any binary:

```python
from enigmar import Channel, Alphabet
ch = Channel("passphrase", alphabet=Alphabet.of_bytes())
nonce, ct, tag = ch.send(b"\x00\xff any bytes at all")   # ct is bytes
```

The alphabet is a codec at the edge; everything inside is `mod N` over `range(N)`,
so nothing about the mechanism is tied to 32 symbols.

## The machine

- 3 or 4 rotors, ring settings, plugboard, reflector, standard double-stepping.
- 4-rotor (M4) mode: the leftmost Greek rotor is static.
- Rotor and reflector wirings carried over from the original project.

```python
from enigmar import Enigma, Rotor, Reflector

m = Enigma.configure("321", "B", positions="KDO", rings="AAA", plugs="AB CD")
ct = m.encode("HELLO.WORLD")
```

## Security

The engine closes each classic-Enigma break (self-map crib, reciprocity, known wiring,
regular stepping) and adds modern hygiene: a scrypt KDF, nonce discipline, encrypt-then-MAC
authentication, an optional `keyfile`, an authenticated Diffie-Hellman handshake, and a
per-message ratchet. The bar is **cost, not impossibility** — and effective security equals
the entropy you inject, not the size of the (unbounded) config space: a memorised passphrase
holds ~40–60 bits, a random `keyfile=os.urandom(128)` injects 1024. Homemade and unreviewed;
for high-stakes secrets use a vetted cipher (AES-GCM / ChaCha20-Poly1305).

The **why** — each mechanism, the measured keystream numbers, the key-space accounting, and
the honest boundaries — lives in **[DESIGN.md](DESIGN.md)**.

*For art's sake, `python demos/maxout.py` builds a 4096-symbol, 256-rotor machine
(≈ 2^11,000,000 configurations, a 3.4-million-digit number) and round-trips a message.*

## Command line

```bash
echo -n "secret" | python cli.py encrypt -p hunter2 > msg.er   # authenticated blob
python cli.py decrypt -p hunter2 < msg.er                      # verifies, then prints
python cli.py rng -p hunter2 -n 32                             # reproducible random bytes
```

Passphrase via `-p`, the `ENIGMAR_PASS` env var, or an interactive prompt; `--keyfile FILE`
adds a second secret, `--chaos` turns on every keyed dynamic. Byte mode, encrypt-then-MAC.

`cli.py chat` runs a **double-ratchet session** across processes (persisted state files):
`identity` → `prekey` (responder) → `start` (initiator) → `accept`, then `send` / `recv` —
each message rides a fresh key, the DH ratchet turns automatically, out-of-order is handled.

## Sharing a key — Diffie–Hellman handshake

Agree a key over a public channel with **nothing pre-shared**, then use it as the keyfile:

```python
from enigmar import Handshake, Channel, Alphabet
a, b = Handshake(), Handshake()
ka, kb = a.shared(b.public), b.shared(a.public)   # only a.public / b.public go on the wire
ch = Channel("", keyfile=ka, alphabet=Alphabet.of_bytes())   # kb identical on the other side
```

The shared secret is `g^(ab) mod p` over a 2048-bit MODP group — an eavesdropper sees the
public halves and still can't compute it.

**Authenticated** (3-DH / mini-X3DH): give each side a long-term `Identity` and pin the
peer's identity public key out of band; the session key then mixes the ephemeral DH with
two identity-bound DHs, so a man-in-the-middle who lacks an identity private key derives a
different key and fails the MAC:

```python
from enigmar import Identity, Handshake, authenticated_key, Ratchet, Channel, Alphabet
id_a, id_b = Identity(), Identity()          # long-term; pin .public out of band
ea, eb = Handshake(), Handshake()            # per-session ephemerals
ka = authenticated_key(id_a, ea, id_b.public, eb.public, initiator=True)
kb = authenticated_key(id_b, eb, id_a.public, ea.public, initiator=False)   # ka == kb
```

**Per-message keys** — feed the shared key to a `Ratchet` so every message rides its own
key; the chain only moves forward, so deleting state keeps past messages locked (forward
secrecy):

```python
r = Ratchet(ka)                              # same root on both sides
key0, key1 = r.next(), r.next()              # fresh 32-byte key per message
```

Together this is the Signal shape: `DH (bits) → ratchet (forward secrecy) → engine (cipher)`.
*Still homemade and unreviewed — for real secrets prefer X25519/libsodium.*

## Layout

```
enigmar/   machine, cipher, kex, ratchet, session  (the library package)
tests/     pytest suite, split by topic + randtest.py (keystream metrics)
demos/     demo.py, maxout.py                       (runnable showcases)
cli.py     command-line entry point
```

## Run

```bash
pytest                    # the property-test suite (tests/)
python tests/randtest.py  # keystream uniformity / independence gate + report
python demos/demo.py      # showcase
```

No dependencies — pure standard library (pytest only to run the suite).
