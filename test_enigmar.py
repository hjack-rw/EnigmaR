"""
Regression / characterization tests for the EnigmaR engine.

These lock the engine's CURRENT behaviour. They make no claim about
cryptographic "correctness" — they simply guarantee that a refactor
(e.g. reworking double-stepping, optimising lookups) does not silently
change the output of the machine.

Run:  python test_enigmar.py      (or: pytest test_enigmar.py)
"""
import importlib.util
import os
import random
import hashlib

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE = os.path.join(_HERE, "main", "enigmar.py")

# import main/enigmar.py directly (avoid main/__init__.py -> Flask deps)
_spec = importlib.util.spec_from_file_location("enigmar_engine", _ENGINE)
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.,!?:'"

# Golden signature of the current engine. If a change is intentional,
# re-run `_signature()` and paste the new value here.
GOLDEN_SIGNATURE = "a924a8863d911b5e64d450e09852151a23fc8a6ec0e32140366b2618533ad20f"


def _rand_cfg(rnd):
    """Deterministic spread of ENIGMA configurations."""
    nrot = rnd.choice([3, 4])
    rotors = "".join(rnd.choice("12345678") for _ in range(nrot))
    reflector = rnd.randint(0, 4)
    pos = "".join(rnd.choice(ALPHABET) for _ in range(nrot))
    rings = "".join(rnd.choice(ALPHABET) for _ in range(nrot))
    npl = rnd.randint(0, 4)
    letters = rnd.sample(ALPHABET, min(2 * npl, len(ALPHABET)))
    plugs = "".join(letters[i] + letters[i + 1] + " "
                    for i in range(0, len(letters) - 1, 2))
    return rotors, reflector, pos, rings, plugs


def _signature(seed=1234, n=4000):
    """Hash of the engine's output over a fixed pseudo-random vector set."""
    rnd = random.Random(seed)
    outs = []
    for _ in range(n):
        rotors, reflector, pos, rings, plugs = _rand_cfg(rnd)
        val = rnd.randint(0, 65535)
        try:
            enc = E.ENIGMA(val, 'h', rotors, [], reflector, pos, rings, plugs).result
            outs.append(str(enc))
        except Exception as ex:  # behaviour includes how/when it raises
            outs.append("ERR:" + type(ex).__name__)
    return hashlib.sha256("\n".join(outs).encode()).hexdigest()


def test_engine_output_is_stable():
    """The machine's output over a fixed vector set must not change."""
    assert _signature() == GOLDEN_SIGNATURE, (
        "Engine output changed. If intentional, update GOLDEN_SIGNATURE."
    )


def test_codec_is_invertible_over_signed_16bit():
    """inCode/outCode must round-trip every signed 16-bit sample ('h')."""
    bad = [x for x in range(-32768, 32768)
           if E.outCode(*E.inCode(x, 'h'), 'h') != x]
    assert not bad, f"codec failed to round-trip {len(bad)} sample(s), first={bad[:1]}"


if __name__ == "__main__":
    s = _signature()
    print("signature:", s, "OK" if s == GOLDEN_SIGNATURE else "!! CHANGED")
    test_codec_is_invertible_over_signed_16bit()
    print("codec signed 16-bit round-trip: OK")
    print("all regression checks passed" if s == GOLDEN_SIGNATURE else "REGRESSION DETECTED")
