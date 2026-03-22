# RSA CTF Toolkit

A practical RSA command-line utility for CTF players.

This tool supports:
- Secure RSA OAEP operations for normal crypto workflows.
- Textbook RSA operations and helpers for CTF challenge solving.

Main scripts:
- `rsa_ctf_tool.py` (preferred)
- `rsa_endecypt.py` (backward-compatible alias)

## Features

- Secure mode commands:
  - `keygen`
  - `encrypt`
  - `decrypt`
- CTF mode commands:
  - `ctf-encrypt` (`c = m^e mod n`)
  - `ctf-decrypt` (`m = c^d mod n`)
  - `ctf-derive-d` (derive `d` from `e` and `phi` or `p,q`)
  - `ctf-factor` (hybrid factoring: trivial checks, trial division, Pollard Rho)
  - `ctf-solve` (factor `n`, derive `d`, decrypt `c`)
  - `ctf-auto` (auto solve + auto decode output)
  - `ctf-common-modulus` (Common Modulus Attack: same `n`, two `(e, c)` pairs)
  - `ctf-pollard-pm1` (Pollard p-1 attack for smooth-prime challenges)
- Integer parsing supports decimal and hex (`0x...`).
- Output modes: `--auto` (default), `--as-text`, `--as-hex`, `--as-base64`.
- Verbose tracing for CTF solving with `--verbose`.

## Important Notes

- This is for legal CTF practice and education.
- `ctf-factor`, `ctf-solve`, `ctf-pollard-pm1` only work when `n` is weak/factorable.
- Real-world strong RSA keys will not be practically factorable with this script.

## Requirements

- Python 3.8+
- `cryptography` package (only required for secure mode commands: `keygen`, `encrypt`, `decrypt`)

## Installation

```bash
git clone <your-repo-url>
cd rsa_endecrypt
python3 -m pip install cryptography
```

## Quick Start

Show help:

```bash
python3 rsa_ctf_tool.py --help
```

## CTF Workflows

### 1) Encrypt then decrypt (known `d`)

```bash
python3 rsa_ctf_tool.py ctf-encrypt --n 55 --e 3 --m-int 12
# output: 23

python3 rsa_ctf_tool.py ctf-decrypt --n 55 --c 23 --d 27 --auto
# output: 12
```

### 2) Decrypt when `p`, `q`, and `e` are known

```bash
python3 rsa_ctf_tool.py ctf-decrypt --n <n> --c <c> --p <p> --q <q> --e <e> --auto
```

### 3) Derive `d` directly

```bash
python3 rsa_ctf_tool.py ctf-derive-d --e <e> --p <p> --q <q>
# or
python3 rsa_ctf_tool.py ctf-derive-d --e <e> --phi <phi>
```

### 4) Try to factor weak modulus

```bash
python3 rsa_ctf_tool.py ctf-factor --n <n> --verbose
```

### 5) Full auto solve for weak challenges

```bash
python3 rsa_ctf_tool.py ctf-solve --n <n> --e <e> --c <c> --auto --verbose
```

### 6) Fully automatic solve workflow

```bash
python3 rsa_ctf_tool.py ctf-auto --n <n> --e <e> --c <c> --auto --verbose
```

### 7) Work with text messages in textbook RSA

```bash
python3 rsa_ctf_tool.py ctf-encrypt --n <n> --e <e> --m-text "flag"
python3 rsa_ctf_tool.py ctf-decrypt --n <n> --c <cipher_int> --d <d> --as-text
```

### 8) Common Modulus Attack

Use when a challenge gives you the **same modulus `n`** encrypted under **two different exponents** (`e1`, `e2`) for the same plaintext. No private key or factoring needed.

```bash
python3 rsa_ctf_tool.py ctf-common-modulus \
  --n <n> \
  --e1 <e1> --c1 <c1> \
  --e2 <e2> --c2 <c2> \
  --verbose
```

**How it works:** Uses the Extended Euclidean Algorithm to find Bézout coefficients `a, b` such that `a·e1 + b·e2 = 1`, then recovers `m = c1^a · c2^b mod n`.

**When to use it:** The challenge provides two public keys with the same `n` but different exponents, and both encrypt the same secret message.

**Requirements:** `gcd(e1, e2) = 1` (true for virtually all standard exponent pairs).

### 9) Pollard p-1 Attack

Use when the challenge hints that the prime factors were generated with **smooth** `p-1` values (e.g. hints like "smooth primes", "Pollard", or references to factorials/small numbers).

```bash
python3 rsa_ctf_tool.py ctf-pollard-pm1 \
  --n <n> --e <e> --c <c> \
  --verbose
```

Two tunable parameters let you cover different challenge types:

| Flag | Default | Purpose |
|---|---|---|
| `--b1` | `1000000` | Standard smoothness bound: covers primes where all factors of `p-1` are ≤ B1 |
| `--factorial-limit` | `2000` | Factorial fallback: covers primes where `p-1` divides `k!` for some small `k` |

**Standard smoothness** (all prime factors of `p-1` are small):
```bash
python3 rsa_ctf_tool.py ctf-pollard-pm1 --n <n> --e <e> --c <c> --b1 5000000
```

**Factorial-smooth** (challenge hints at factorials or sequential numbers):
```bash
python3 rsa_ctf_tool.py ctf-pollard-pm1 --n <n> --e <e> --c <c> --factorial-limit 600
```

**How it works:**
- **Stage 1:** Computes `a = 2^(∏ pᵏ) mod n` for all prime powers `pᵏ ≤ B1`, then checks `gcd(a-1, n)`.
- **Factorial fallback:** Iteratively raises `a = 2^k mod n` for `k = 1, 2, 3, ...` and checks `gcd(a-1, n)` at each step. Catches primes where `p-1 | k!` for some small `k`.

## Secure Mode (OAEP-SHA256)

Generate keys:

```bash
python3 rsa_ctf_tool.py keygen --bits 3072 --private-out private.pem --public-out public.pem
```

Encrypt text:

```bash
python3 rsa_ctf_tool.py encrypt --public-key public.pem --text "hello"
```

Decrypt base64 ciphertext:

```bash
python3 rsa_ctf_tool.py decrypt --private-key private.pem --base64 "<ciphertext>" --as-text
```

## Command Reference

```bash
python3 rsa_ctf_tool.py keygen --help
python3 rsa_ctf_tool.py encrypt --help
python3 rsa_ctf_tool.py decrypt --help
python3 rsa_ctf_tool.py ctf-encrypt --help
python3 rsa_ctf_tool.py ctf-decrypt --help
python3 rsa_ctf_tool.py ctf-derive-d --help
python3 rsa_ctf_tool.py ctf-factor --help
python3 rsa_ctf_tool.py ctf-solve --help
python3 rsa_ctf_tool.py ctf-auto --help
python3 rsa_ctf_tool.py ctf-common-modulus --help
python3 rsa_ctf_tool.py ctf-pollard-pm1 --help
```

## Attack Selection Guide

| Symptom / Challenge Hint | Command |
|---|---|
| Given `p`, `q`, `e`, `c` | `ctf-decrypt --p --q --e --c` |
| Given `phi`, `e`, `c` | `ctf-decrypt --phi --e --c` |
| Given `d`, `c` | `ctf-decrypt --d --c` |
| Small or weak `n` | `ctf-auto` or `ctf-solve` |
| Same `n`, two `(e, c)` pairs, same plaintext | `ctf-common-modulus` |
| "Smooth primes", "Pollard", hints about small factors of `p-1` | `ctf-pollard-pm1 --b1 <bound>` |
| "Factorial", "sequential", hints about `k!` structure | `ctf-pollard-pm1 --factorial-limit <k>` |

## Troubleshooting

- **Error:** `plaintext integer must satisfy m < n`
  - Use a larger modulus or smaller message integer.
- **Error:** modular inverse failure (`gcd(e, phi) != 1`)
  - Verify challenge parameters; `e` and `phi` must be coprime.
- **`ctf-factor` fails**
  - The modulus is likely too strong for Pollard Rho. Try `ctf-pollard-pm1` if the challenge hints at smooth primes.
- **`ctf-common-modulus` fails with `gcd(e1, e2) != 1`**
  - The exponents share a common factor; the standard attack does not apply directly.
- **`ctf-pollard-pm1` fails**
  - Try increasing `--b1` (e.g. `--b1 10000000`) or `--factorial-limit` (e.g. `--factorial-limit 2000`). If it still fails, the prime was likely not generated with a smooth `p-1`.