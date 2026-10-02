# ctfkit: Modular CTF Cryptanalysis & Automation Toolkit

High-performance, CLI-first, offline-resilient cryptanalysis engine designed for CTF competitions and finals (e.g., HackToday 2026 Finals).

## Key Features

- **Flag Targeting & Seeding**: Dynamic flag prefix default `HackToday26{` (reconfigurable via `.ctfkit.toml`, CLI `--flag-prefix`, or env `CTFKIT_FLAG_PREFIX`). Known prefix is automatically weaponized as known plaintext.
- **Recursive Beam Search Pipeline**: Explores transformation DAGs (`Hex -> Base64 -> Zlib -> ROT13 -> Flag`), scores branches, prevents cycles, and halts immediately on flag match.
- **Advanced RSA Attacks**: Small $e$, Wiener continued fractions ($d < \frac{1}{3}n^{1/4}$), Fermat factorization ($p \approx q$), Common Modulus, Hastad Broadcast, Batch GCD, Franklin-Reiter, and Coppersmith stereotyped messages.
- **Advanced AES Attacks**: ECB duplicate detection, automated byte-at-a-time ECB decryption, CBC padding oracle solver, and AES-GCM "Forbidden Attack" authentication tag forgery.
- **XOR Cryptanalysis**: 256-key single-byte frequency solver, repeating-key XOR via pairwise normalized Hamming distance, known-plaintext derivation, and multi-stream crib dragging.
- **PRNG & Stream Ciphers**: MT19937 untemper and Python `random` cloner, LCG algebraic parameter recovery, and LFSR Berlekamp-Massey solver.
- **Classical Ciphers**: Caesar (all 25 shifts), Vigenère (IoC + Chi-squared beam search), Affine ($312$ keys), Atbash, and Rail Fence transposition.

## Installation & Setup

```bash
cd d:\HTB\ctfkit
pip install -e .
```

Inspect environment and installed tools:
```bash
python -m ctfkit.cli.main doctor
```

## Quick CLI Reference

### 1. Autonomous Multi-Layer Decoding
```bash
# Recursively decode nested encodings/ciphers
python -m ctfkit.cli.main crypto auto "654a774c7a53756f634538..."

# Pass custom flag prefix on the fly
python -m ctfkit.cli.main crypto auto ./ciphertext.txt --flag-prefix "HackToday26{"
```

### 2. XOR Cryptanalysis
```bash
# Auto-breaks single-byte, repeating-key, or known-plaintext XOR from hex or raw bytes
python -m ctfkit.cli.main crypto xor "0a232129162d26233b..."

# Specify repeating key length search range
python -m ctfkit.cli.main crypto xor ./cipher.bin --mode repeating --key-len 4-16
```

### 3. RSA Automated Triage
```bash
# Auto-audit from JSON parameter file (Wiener, Fermat, Small e, etc.)
python -m ctfkit.cli.main crypto rsa --file ./rsa_params.json

# Explicit command-line parameters
python -m ctfkit.cli.main crypto rsa -n 0xbb56... -e 3 -c 0x489a...
```

### 4. Classical Ciphers
```bash
# ROT / Caesar search
python -m ctfkit.cli.main crypto classical rot "Uryyb Jbeyq!"

# Vigenere key and plaintext recovery
python -m ctfkit.cli.main crypto classical vigenere ./vigenere.txt

# Affine & Atbash
python -m ctfkit.cli.main crypto classical affine ./affine.txt
```

## Running Test Suite

```bash
python -m unittest discover tests
```
