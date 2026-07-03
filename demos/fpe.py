"""
Format-preserving encryption toys — the one thing the engine does that a generic
cipher doesn't: ciphertext stays in the input's own shape. Run: python demos/fpe.py

Not security — a showcase. Each is a keyed, reversible mapping over a constrained
domain (a card stays a valid card, a PESEL stays a valid PESEL, an IP stays an IP).
The reusable machinery lives in `enigmar.FPE`; each field below is a few lines of
config on top of it. For checksummed fields the check digit is marked derived, so
FPE recomputes it after encryption and the output is valid by construction.
"""
import os as _os
import sys as _sys

# Windows consoles default to cp1252; force UTF-8 so the melody glyphs print.
if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import enigmar as E

PASS = "hunter2"
DIGITS = "0123456789"


# --- checksums --------------------------------------------------------------

def _luhn_check(payload):
    """Luhn check digit for a list of int digits (the number without its check)."""
    total = 0
    for i, d in enumerate(reversed(payload)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def luhn_valid(card):
    d = [int(c) for c in card if c.isdigit()]
    return _luhn_check(d[:-1]) == d[-1]


def _pesel_check(d10):
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return (10 - sum(a * b for a, b in zip(d10, weights)) % 10) % 10


def pesel_valid(pesel):
    d = [int(c) for c in pesel]
    return len(d) == 11 and _pesel_check(d[:10]) == d[10]


def _luhn_str(digits):     # FPE checksum hook: list[str] -> str
    return str(_luhn_check([int(c) for c in digits]))


def _pesel_str(digits):
    return str(_pesel_check([int(c) for c in digits]))


# --- the fields, each a few lines of FPE config -----------------------------

# CARD -> CARD: 15 free digits encrypted, 16th is the recomputed Luhn digit.
card = E.FPE(PASS, DIGITS, nonce="card", checksum=_luhn_str)

# PESEL -> PESEL: keep the 6-digit birth date, re-key the 4-digit serial, and
# recompute the trailing checksum over the first 10 digits.
pesel = E.FPE(PASS, DIGITS, nonce="pesel", keep_prefix=6, checksum=_pesel_str)

# PHONE (E.164) -> PHONE: '+' and country code stay, national digits re-keyed.
# keep_prefix counts payload (digit) symbols, so +48 keeps 2 digits fixed.
phone = E.FPE(PASS, DIGITS, nonce="phone", keep_prefix=2)

# IPv4 -> IPv4, per octet: each octet is a number in 0..255, encrypted in that
# domain (not digit-by-digit), so every octet stays a valid octet. This one is
# not the char-FPE helper — the domain is 0..255, so it's a byte-alphabet cipher
# run once per octet. Shows FPE is about the domain, not the digit count.
_OCTET = E.StreamCipher.from_passphrase(PASS, nonce="octet", alphabet=E.Alphabet.of_bytes())


def _octet(o, *, decrypt=False):
    out = _OCTET.decrypt(bytes([int(o)])) if decrypt else _OCTET.encrypt(bytes([int(o)]))
    return str(out[0])


def ipv4(addr, *, decrypt=False):
    return ".".join(_octet(o, decrypt=decrypt) for o in addr.split("."))


# UUID -> UUID: hex digits re-keyed, dashes and the version nibble kept.
UUID_HEX = "0123456789abcdef"
uuid = E.FPE(PASS, UUID_HEX, nonce="uuid")


# --- sentence -> sentence (real words in, real words out) --------------------
# FPE over a *vocabulary* rather than characters: the alphabet is the word list.

_WORDS = ("the a of to and attack at dawn from north south east west move hold fire "
          "retreat advance enemy near river bridge hill town send men now wait for order "
          "strike before night cover under rain fog light dark road gate wall door key "
          "gold ship sea sky").split()


def sentence_map(text, nonce="msg", *, decrypt=False):
    idx = {w: i for i, w in enumerate(_WORDS)}
    sc = E.StreamCipher.from_passphrase(PASS, nonce=nonce, alphabet=E.Alphabet.of_bytes(len(_WORDS)))
    codes = bytes(idx[w] for w in text.split())
    out = sc.decrypt(codes) if decrypt else sc.encrypt(codes)
    return " ".join(_WORDS[b] for b in out)


# --- passphrase -> melody (generative, reproducible; not FPE) ----------------

def melody(passphrase, bars=8, nonce="tune"):
    scale = ["C", "D", "E", "G", "A"]                # C major pentatonic
    lengths = ["♩", "♪", "♩.", "𝅗𝅥"]
    ks = E.StreamCipher.from_passphrase(passphrase, nonce=nonce,
                                        alphabet=E.Alphabet.of_bytes()).keystream(2 * bars)
    return " ".join(f"{scale[ks[2*i] % 5]}{lengths[ks[2*i+1] % 4]}" for i in range(bars))


def _rule(t):
    print(f"\n{'-' * 68}\n{t}\n{'-' * 68}")


if __name__ == "__main__":
    _rule("1.  CARD -> CARD   (stays a Luhn-valid 16-digit number)")
    pan = "4111 1111 1111 1111"                       # a Luhn-valid test card (spaced)
    tok = card.encrypt(pan)
    print(f"  {pan}  ->  {tok}")
    print(f"  input valid: {luhn_valid(pan)} | output valid: {luhn_valid(tok)} | "
          f"reverses: {card.decrypt(tok) == pan}")

    _rule("2.  PESEL -> PESEL   (valid date kept, valid checksum)")
    p = "44051401359"                                 # a classic valid PESEL
    ptok = pesel.encrypt(p)
    print(f"  {p}  ->  {ptok}")
    print(f"  input valid: {pesel_valid(p)} | output valid: {pesel_valid(ptok)} | "
          f"reverses: {pesel.decrypt(ptok) == p}")

    _rule("3.  PHONE -> PHONE   ('+48' country code kept)")
    ph = "+48 123 456 789"
    ptok = phone.encrypt(ph)
    print(f"  {ph}  ->  {ptok}")
    print(f"  prefix kept: {ptok.startswith('+48')} | reverses: {phone.decrypt(ptok) == ph}")

    _rule("4.  IPv4 -> IPv4   (every octet stays 0..255)")
    ip = "192.168.1.254"
    itok = ipv4(ip)
    octs_ok = all(0 <= int(o) <= 255 for o in itok.split("."))
    print(f"  {ip}  ->  {itok}")
    print(f"  valid octets: {octs_ok} | reverses: {ipv4(itok, decrypt=True) == ip}")

    _rule("5.  UUID -> UUID   (hex re-keyed, dashes kept)")
    uid = "550e8400-e29b-41d4-a716-446655440000"
    utok = uuid.encrypt(uid)
    print(f"  {uid}  ->  {utok}")
    print(f"  shape kept: {len(utok) == len(uid) and utok.count('-') == 4} | "
          f"reverses: {uuid.decrypt(utok) == uid}")

    _rule("6.  SENTENCE -> SENTENCE   (real words in, real words out)")
    msg = "attack the bridge at dawn"
    enc = sentence_map(msg)
    print(f"  '{msg}'\n    ->  '{enc}'\n    ->  '{sentence_map(enc, decrypt=True)}'")

    _rule("7.  PASSPHRASE -> MELODY   (reproducible, C major pentatonic; not FPE)")
    print(f"  '{PASS}'   ->  {melody(PASS)}")
    print(f"  'other'    ->  {melody('other')}")
