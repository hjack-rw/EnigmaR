"""
Format-preserving encryption toys — the one thing the engine does that a generic
cipher doesn't: ciphertext stays in the input's own shape. Run: python demos/fpe.py

Not security — a showcase. Each is a keyed, reversible mapping over a constrained
domain (a card stays a valid card, a PESEL stays a valid PESEL, a sentence stays a
sentence). For checksummed fields the trick is: encrypt the free part with the engine
(an additive digit cipher is a bijection, so it round-trips), then recompute the check
digit — the output is valid by construction.
"""
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import enigmar as E

PASS = "hunter2"
_DIGITS = E.Alphabet("0123456789")


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
    d = [int(c) for c in card]
    return _luhn_check(d[:-1]) == d[-1]


def _pesel_check(d10):
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return (10 - sum(a * b for a, b in zip(d10, weights)) % 10) % 10


def pesel_valid(pesel):
    d = [int(c) for c in pesel]
    return len(d) == 11 and _pesel_check(d[:10]) == d[10]


# --- card -> card (Luhn preserved) ------------------------------------------

def card_encrypt(pan, nonce="card"):
    sc = E.StreamCipher.from_passphrase(PASS, nonce=nonce, alphabet=_DIGITS)
    enc = sc.encrypt(pan[:15])                       # 15 free digits, reversible
    return enc + str(_luhn_check([int(c) for c in enc]))


def card_decrypt(tok, nonce="card"):
    sc = E.StreamCipher.from_passphrase(PASS, nonce=nonce, alphabet=_DIGITS)
    dec = sc.decrypt(tok[:15])
    return dec + str(_luhn_check([int(c) for c in dec]))  # original card was valid


# --- PESEL -> PESEL (valid date kept, serial re-keyed, checksum recomputed) --

def pesel_encrypt(pesel, nonce="pesel"):
    sc = E.StreamCipher.from_passphrase(PASS, nonce=nonce, alphabet=_DIGITS)
    date, serial = pesel[:6], pesel[6:10]            # keep birth date, re-key the serial
    new = date + sc.encrypt(serial)
    return new + str(_pesel_check([int(c) for c in new]))


def pesel_decrypt(tok, nonce="pesel"):
    sc = E.StreamCipher.from_passphrase(PASS, nonce=nonce, alphabet=_DIGITS)
    orig = tok[:6] + sc.decrypt(tok[6:10])
    return orig + str(_pesel_check([int(c) for c in orig]))


# --- sentence -> sentence (real words in, real words out) --------------------

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


# --- passphrase -> melody (generative, reproducible) -------------------------

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
    pan = "4111111111111111"                        # a Luhn-valid test card
    tok = card_encrypt(pan)
    print(f"  {pan}  ->  {tok}")
    print(f"  input valid: {luhn_valid(pan)} | output valid: {luhn_valid(tok)} | "
          f"reverses: {card_decrypt(tok) == pan}")

    _rule("2.  PESEL -> PESEL   (valid date kept, valid checksum)")
    pesel = "44051401359"                            # a classic valid PESEL
    ptok = pesel_encrypt(pesel)
    print(f"  {pesel}  ->  {ptok}")
    print(f"  input valid: {pesel_valid(pesel)} | output valid: {pesel_valid(ptok)} | "
          f"reverses: {pesel_decrypt(ptok) == pesel}")

    _rule("3.  SENTENCE -> SENTENCE   (real words in, real words out)")
    msg = "attack the bridge at dawn"
    enc = sentence_map(msg)
    print(f"  '{msg}'\n    ->  '{enc}'\n    ->  '{sentence_map(enc, decrypt=True)}'")

    _rule("4.  PASSPHRASE -> MELODY   (reproducible, C major pentatonic)")
    print(f"  '{PASS}'   ->  {melody(PASS)}")
    print(f"  'other'    ->  {melody('other')}")
