# EnigmaR

A Flask web application implementing classical cipher algorithms, including a full Enigma machine simulation.

Built as a companion project to a BSc thesis on message encryption algorithms in digital signal processing.

## Ciphers

- **Enigma machine** — full rotor/reflector simulation with plugboard configuration
- **Caesar cipher** — rotational substitution
- **Vigenère cipher** — polyalphabetic substitution
- **Atbash cipher** (1to0) — reflection substitution
- **Cipher Disk** — custom disk-based variant

## Features

- Browser UI for interactive encryption/decryption
- File-based input (WAV audio file encryption via signal-domain embedding)
- Configurable Enigma reflector positions stored in a local database

## Stack

Python · Flask · Flask-SQLAlchemy · NumPy · HTML/CSS

## Run locally

```bash
pip install flask flask-sqlalchemy numpy
python _run.py
```

App runs at `http://127.0.0.1:5000`