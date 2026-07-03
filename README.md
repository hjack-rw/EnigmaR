# EnigmaR — engine

A standalone Enigma-style cipher engine over a **32-symbol alphabet**
(`A–Z . , ! ? : '`), extended and hardened well past the museum machine.

This branch (`enigma-engine`) is the engine only — decoupled from audio and Flask.
The original audio app (WAV encryption with multiple ciphers) lives on `main`.

Modules: `machine.py` (the mechanism), `cipher.py` (key derivation, keystream
cipher, channel), `enigma.py` (umbrella re-export).

## Easy interface

Configure once, send/receive; nonce reuse handled for you and every message is
authenticated (encrypt-then-MAC):

```python
from enigma import Channel, Config

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
from enigma import Cascade
cas = Cascade("passphrase", [dict(chaos=True), dict(reflectorless=True), dict(drift=True)])
ct = cas.encrypt("MEET.AT.DAWN")            # decrypt unwinds the layers in reverse
```

Byte mode — the same engine on any binary:

```python
from enigma import Channel, Alphabet
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
from enigma import Enigma, Rotor, Reflector

m = Enigma.configure("321", "B", positions="KDO", rings="AAA", plugs="AB CD")
ct = m.encode("HELLO.WORLD")
```

## How it's secured

Each classic-Enigma break is closed, not just patched over:

- **Fixed-point reflectors** — `Reflector.from_pairs(...)` builds a decryptable
  involution that *can* map a symbol to itself, so the "a letter never encrypts to
  itself" crib is gone.
- **Keystream mode** (`StreamCipher`) — the rotors drive a keystream combined by
  modular add, so encryption isn't a reflecting substitution: no reciprocal pairing,
  no self-map structure. The keystream is fed the machine's config-fingerprint byte
  stream and measures uniform and independent (`randtest.py`).
- **Key-derived secret wiring** — a passphrase, stretched with stdlib scrypt, derives
  the entire secret machine. The wiring is re-derived on both ends and never
  transmitted, so there is no codebook/key-list to capture and known wiring buys an
  attacker nothing.
- **Unpredictable stepping** (SIGABA-style) — a keyed schedule decides which rotors
  advance, so internal positions can't be read off the message index.
- **Nonce discipline** (`Channel`) — a fresh 128-bit nonce per message, reuse and
  replay rejected, so no two messages ever share a keystream.
- **Authentication** (`Channel`, encrypt-then-MAC) — every message carries an
  HMAC-SHA256 tag under a separate key-derived MAC key, verified before decryption.
  A stream cipher alone is malleable; the MAC turns silent tampering into a hard error.

The bar is **cost, not impossibility**: a reversible symmetric cipher, deterministic
by design, judged like any cipher on how uneconomical it is to break. It has no
adversarial-cryptanalysis track record the way AES/ChaCha do — for high-stakes secrets
those remain the right choice. See [DESIGN.md](DESIGN.md) for the reasoning behind each
mechanism.

## Measured

Keystream quality, byte mode, 200 000 samples (`python randtest.py`). These tests can
only *falsify* randomness — they don't prove it — but the engine passes every one:

| metric | keystream | cipher of all-zeros* | ideal |
|---|---|---|---|
| Shannon entropy | **7.9991 / 8** bits | 7.999 / 8 | 8.0 |
| chi-square (256 bins) | 257 | 243 | ~255 (0.01 crit ~330) |
| zlib compression | **1.0004×** | 1.0004× | 1.0 (incompressible) |
| monobit \|z\| | 0.86 | 0.04 | < 3 |
| autocorrelation @ lags 1–64 | all ≈ ±0.002 | all ≈ ±0.006 | 0 |

*\*Encrypting an all-zeros input — maximally structured — still yields output
indistinguishable from random. That is the exact case the original audio engine leaked;
here the additive keystream erases it.* Holds under `chaos=True` and through a `Cascade`.

## Key space — three numbers, only one is security

| | size | what it is |
|---|---|---|
| nominal config space | **unbounded** | ≈ `R · log2(N!)` bits (R rotors, N symbols) — no cap; grows without limit as you add rotors or enlarge the alphabet. Diffusion, not security |
| reachable machines | **2^(8·seedlen)** | hard ceiling: the machine is a deterministic function of the KDF seed (pigeonhole). Default 128-byte seed → 2¹⁰²⁴; scale the seed to raise it |
| effective security | **= entropy you inject** | the only number that counts — an attacker guesses the *key*, not the machine |

A deterministic function of the key spreads its entropy across an astronomical
configuration; it cannot add any. The huge config space is diffusion. What makes a guess
expensive is scrypt (`N=2**16`, ~64 MB/guess); what caps security is the entropy you feed
in. A memorised passphrase holds ~40–60 bits; a random **`keyfile=os.urandom(128)`** injects
1024 bits, lifting the floor to meet the seed ceiling — the one knob that adds real bits.
Past 2²⁵⁶ it is all diffusion anyway (2²⁵⁶ is beyond any physical brute force forever).

*For art's sake, `python maxout.py` builds a 4096-symbol, 256-rotor machine — ≈ 2^11,000,000
distinct configurations (a 3.4-million-digit number) — and round-trips a message through it.*

## Command line

```bash
echo -n "secret" | python cli.py encrypt -p hunter2 > msg.er   # authenticated blob
python cli.py decrypt -p hunter2 < msg.er                      # verifies, then prints
python cli.py rng -p hunter2 -n 32                             # reproducible random bytes
```

Passphrase via `-p`, the `ENIGMAR_PASS` env var, or an interactive prompt; `--keyfile FILE`
adds a second secret, `--chaos` turns on every keyed dynamic. Byte mode, encrypt-then-MAC.

## Run

```bash
python enigma.py          # runs the property tests
python test_enigma.py     # property tests (or: pytest test_enigma.py)
python randtest.py        # keystream uniformity / independence gate
```

No dependencies — pure standard library.
