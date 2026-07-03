# Design & security rationale

What the engine is, why each mechanism exists, and — honestly — what each does and
does **not** buy. README covers usage; this covers reasoning.

## The bar: cost, not impossibility

This is a reversible symmetric cipher, deterministic by design (it must reproduce the
keystream to decrypt). It is not claimed to be unbreakable — no practical cipher is
*provably* unbreakable; "secure" only ever means no publicly-known feasible attack.
The goal is the same as any cipher's: make breaking it **uneconomical**. Close every
cheap shortcut so nothing cheaper than brute force over a real keyspace remains.

Two rules that keep the reasoning honest:

- **Nominal ≠ effective.** More rotors, a bigger alphabet, "it's slow", "you can't skip
  steps" — these buy constant factors, not security. Only secret entropy buys exponents.
- **A deterministic function of the key cannot add entropy.** The keystream *spreads*
  the key's entropy across the message; it does not manufacture any. The value of the
  keystream is *structural*, not extra randomness.

## What it closes (vs the museum machine)

| Classic Enigma weakness | What closes it here |
|---|---|
| A letter never encrypts to itself (Bletchley's #1 crib) | Fixed-point reflectors, and keystream mode has no self-map structure at all |
| Reciprocal / involutive substitution leaks | Keystream combiner (`C = P + K mod N`) — additive, no reciprocity |
| The bombe needed *known* wiring | Wiring derived from a passphrase (scrypt), never transmitted |
| Key distribution — capture the codebook, read the traffic | No static key list; the machine is re-derived per message from a shared secret |
| Regular, predictable rotor stepping | SIGABA-style keyed irregular stepping — positions aren't readable from the message index |
| — | Nonce discipline (`Channel`) so no two messages share a keystream |

## The keystream

Running the rotors as a keystream generator (combine by modular add) is the change that
gets past Enigma's structural ceiling: an additive combiner has no "never itself"
property and no reciprocal pairing, which no rotor/reflector tweak could remove.

Its statistical quality is **not** intrinsic to the rotors — it tracks the entropy of
the input driving them. A periodic counter feed resonates with the fast rotor (same
period) and produces a biased, correlated keystream; output-feedback correlates
adjacent symbols. The engine instead feeds the machine a high-entropy byte stream
seeded from the machine's own config fingerprint, which measures uniform and
independent. `randtest.py` is the gate (chi-square + lag-1 autocorrelation); it can
falsify patterns, never prove randomness.

The plain reading: the machine is a keyed permutation / substitution cipher, not a
randomness source. It mixes and diffuses; the entropy comes from the key.

## Dynamics — every component keyed and time-varying

The design philosophy of the machines that outclassed Enigma (SIGABA, never broken):
don't leave any component static. All of these are opt-in, keyed off the passphrase,
and reproducible for encrypt/decrypt:

- **Irregular stepping** — a keyed byte decides which rotors take an extra step each
  symbol (SIGABA's index rotors, in software). SIGABA held even with its wiring known
  *because the secret lived in the stepping* — so entropy belongs in the schedule, not
  just the permutation.
- **Moving plugboard** — the plugboard rotates each symbol. A rotation-conjugated
  involution is still an involution, so it stays reversible.
- **Reflector bank** — switch among several keyed reflectors per symbol.
- **Reflectorless** — SIGABA had no reflector; dropping it removes reciprocity and the
  self-map crib entirely. Not an involution, so keystream-use only.
- **Double-step toggle** — the historical double-step anomaly (the middle rotor
  self-advancing at its own notch, a ratchet side-effect that shortened the period) can
  be turned off per rotor, or keyed per rotor. Non-historical; changes the stepping
  period and pattern.

- **Keyed structure** — the rotor *count* (a range picked by the key), the reflector
  *bank size* (also a keyed range), whether each rotor is *static*, and whether each
  does the *double-step* are all keyed too. Nothing about the machine's shape is fixed
  except that the fast rotor must move (else nothing steps). `chaos=True` turns every
  keyed dynamic on at once.
- **Drift** — the notch (turnover point), the ring (wiring window), and the plugboard
  offset *walk over the run* on a keyed schedule, so no setting stays frozen for the
  whole message. Deterministic, so it stays in lockstep for decrypt.
- **Cascade** — several machines of different configs chained in series (`Cascade`).
  Each layer is an additive keystream, so the stack is reversible however the machines
  differ; layering deepens diffusion but shares the one seed.

These add period, diffusion, and secret internal state. They extend the *derived*
secret state (they are keyed off the same seed) — real, but bounded by the seed's
entropy, not free new key bits. That bound is the honest limit of "no limits": the
nominal config space is enormous (~2**20000 in byte mode), but the machine is a
deterministic function of a 128-byte seed, so at most **2**1024** distinct machines are
ever reachable (pigeonhole) — and effective security is smaller still, equal to the
passphrase entropy run through the KDF, not the size of the config space.

## Any alphabet

The 32-symbol alphabet was an audio artifact (2⁵ = one symbol per 5 audio bits).
Everything inside is `mod N` over `range(N)`; the alphabet is just a codec at the edge.
`Alphabet.of_bytes()` makes it a general **byte-stream cipher** over arbitrary binary;
`Alphabet("…")` takes any custom symbol set; the 32-symbol classic is the default.

## Honest boundary

- **No adversarial scrutiny.** AES/ChaCha have absorbed decades of expert attack and
  held; this has not been analyzed by anyone but us. "No known break" for something
  unanalyzed is a *weaker* assurance than for something battle-tested — absence of
  evidence, not evidence of a break. For high-stakes secrets, use a vetted cipher
  (passphrase → KDF → ChaCha20/AES-GCM); keep this for the fun/stego/experimental layer.
- **Nonce reuse is fatal.** Two messages under the same (key, nonce) share a keystream:
  `C1 - C2 == P1 - P2` leaks the plaintext difference (two-time-pad). `Channel` enforces
  no reuse; don't bypass it.
- **Weak passphrase = weak key.** With the structural attacks closed, guessing the
  passphrase is the *only* way in — so the KDF cost is the security parameter that
  matters. scrypt runs at `N=2**16` (~64 MB, memory-hard) and is exposed as `kdf_n` to
  raise further; still, a low-entropy passphrase loses regardless. Entropy in, entropy out.
- **Authentication.** The raw `StreamCipher` is malleable — an additive keystream means a
  flipped ciphertext symbol is a *controlled* edit to the plaintext, undetectable on its
  own. `Channel` wraps encrypt-then-MAC (HMAC-SHA256 under a separate derived key,
  verified before decrypt), so tampering fails loudly. Use `Channel`, not the bare cipher,
  for anything that crosses a wire.
- **Speed.** Per-symbol Python over large binary is slow (the original audio project's
  object-per-sample bottleneck). Correctness is fine; throughput on big files isn't —
  numpy/Rust is the fix if it ever needs to scale.

## What it hangs on — and what that means

Every symmetric cipher rests its whole security in the key, not the mechanism — that is
Kerckhoffs's principle, not a weakness. AES hangs on its key; so does this. The honest
question is not *whether* it hangs on something, but *on which threads* — there are three,
and only one is unusual.

1. **The passphrase.** Load-bearing by design. As thick or thin as you make it: a
   throwaway word is a hair, a diceware phrase (~2**77) is a cable, a random 128-bit key
   is past anything guessable. scrypt (`N=2**16`, ~64 MB/guess) thickens even a middling
   one. This thread is under your control, and it is the *same* thread AES hangs on.
2. **Nonce discipline.** Operational, not entropic: reuse a (key, nonce) pair and two
   messages share a keystream (`C1 - C2 == P1 - P2`), regardless of key strength.
   `Channel` enforces no reuse. AES-GCM hangs on the exact same thread — not specific to
   this engine.
3. **The unproven strength of the keystream.** *This is the one thread AES does not
   share thinly.* The design assumes the keystream generator has no exploitable structure.
   Every test here (entropy, chi-square, compression, multi-lag correlation, the
   cipher-of-all-zeros stress) fails to find one — but tests *falsify*, they do not
   *prove*. A distinguisher, if one exists, would break it without touching the passphrase.

That third thread is not evidence of a flaw — it is the **default state of every new
cipher.** Rijndael on its publication day hung on the same thread; a decade of expert
attack is what turned it into AES. Unreviewed is *unbadged*, not *broken*. The difference
between this and a vetted cipher is a calendar and a crowd of attackers, not a gap in the
construction.

And the construction lands, independently, on the right places: key-driven irregular
stepping is the architecture of **SIGABA** (never broken); passphrase → KDF → per-message
keystream, nonce discipline, and encrypt-then-MAC are the hygiene of a modern AEAD like
**ChaCha20-Poly1305**. Reached from the Enigma end, without reading the answer. The one
thing it lacks — adversarial scrutiny — is the one thing that cannot be written in code,
only earned in time. Until then: no known break, every structural attack closed and
*measured*, and a clear-eyed account of the single thread still to be tested. For
high-stakes secrets, reach for a vetted cipher; for everything else, this is a real cipher
that knows exactly where it stands.
