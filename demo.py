"""
EnigmaR - a five-minute showcase.  Run:  python demo.py

One KDF-seeded engine, pure standard library, worn three ways:
  1. a cipher over ANY alphabet (format-preserving encryption)
  2. a reproducible pseudo-random stream
  3. an authenticated channel that detects tampering
All from one passphrase, all reversible, all in the input's own alphabet.
"""
import enigma as E

PASS = "correct-horse-battery-staple"


def rule(title):
    print(f"\n{'-' * 68}\n{title}\n{'-' * 68}")


# --- 1. Format-preserving encryption: output stays in the input alphabet -----

rule("1.  FORMAT-PRESERVING ENCRYPTION  -  ciphertext looks like the plaintext")

# a) a card number encrypts to a card number, same length (tokenisation)
digits = E.Alphabet("0123456789")
sc = E.StreamCipher.from_passphrase(PASS, nonce="card", alphabet=digits)
pan = "4539114980764601"
tok = sc.encrypt(pan)
print(f"  card    {pan}  ->  {tok}   (still 16 digits, reversible: {sc.decrypt(tok) == pan})")

# b) a DNA string encrypts to a valid DNA string
dna = E.Alphabet("ACGT")
sc = E.StreamCipher.from_passphrase(PASS, nonce="dna", alphabet=dna)
seq = "ACGTACGTTTAAGGCCACGTTAGC"
enc = sc.encrypt(seq)
print(f"  dna     {seq}\n       -> {enc}   (still ACGT, reversible: {sc.decrypt(enc) == seq})")

# c) a sentence of real words encrypts to a sentence of real words
WORDS = ("the a of to and attack at dawn from north south east west move hold fire "
         "retreat advance enemy near river bridge hill town send men now wait for order "
         "strike before night cover under rain fog light dark road gate wall door key "
         "gold ship sea sky").split()
idx = {w: i for i, w in enumerate(WORDS)}
sc = E.StreamCipher.from_passphrase(PASS, nonce="msg", alphabet=E.Alphabet.of_bytes(len(WORDS)))
msg = "attack the bridge at dawn"
enc = sc.encrypt(bytes(idx[w] for w in msg.split()))
out = " ".join(WORDS[b] for b in enc)
back = " ".join(WORDS[b] for b in sc.decrypt(enc))
print(f"  words   '{msg}'\n       -> '{out}'   (reversible: {back == msg})")


# --- 2. Reproducible pseudo-random stream ------------------------------------

rule("2.  REPRODUCIBLE RANDOMNESS  -  looks random, replays exactly from a seed")

rng = E.StreamCipher.from_passphrase(PASS, nonce="seed-A", alphabet=E.Alphabet.of_bytes())
a = rng.keystream(12)
again = E.StreamCipher.from_passphrase(PASS, nonce="seed-A", alphabet=E.Alphabet.of_bytes()).keystream(12)
other = E.StreamCipher.from_passphrase(PASS, nonce="seed-B", alphabet=E.Alphabet.of_bytes()).keystream(12)
print(f"  seed A     {a.hex()}")
print(f"  seed A     {again.hex()}   (same seed -> same stream: {a == again})")
print(f"  seed B     {other.hex()}   (different seed -> different stream: {a != other})")


# --- 3. Authenticated channel: tampering is detected -------------------------

rule("3.  AUTHENTICATED CHANNEL  -  a flipped byte is caught, not silently decrypted")

alice = E.Channel(PASS, chaos=True)
bob = E.Channel(PASS, chaos=True)
nonce, ct, tag = alice.send("MEET.AT.DAWN")
print(f"  honest   {ct!r}  ->  {bob.receive(nonce, ct, tag)!r}")

forged = ("Q" if ct[0] != "Q" else "Z") + ct[1:]   # tamper one symbol
try:
    bob.receive(nonce, forged, tag)
    print("  tampered ACCEPTED  (should not happen)")
except ValueError as e:
    print(f"  tampered REJECTED  ->  {e}")

print("\nOne passphrase. Any alphabet. Pure stdlib. Encrypt, randomise, authenticate.\n")
