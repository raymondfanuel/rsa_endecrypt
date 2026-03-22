# RSA CTF Toolkit

A practical RSA command-line utility for CTF players.

This tool supports:
- Secure RSA OAEP operations for normal crypto workflows.
- Textbook RSA operations and helpers for CTF challenge solving.

Main script:
- `rsa_endecypt.py`

## Features

- Secure mode commands:
  - `keygen`
  - `encrypt`
  - `decrypt`
- CTF mode commands:
  - `ctf-encrypt` (`c = m^e mod n`)
  - `ctf-decrypt` (`m = c^d mod n`)
  - `ctf-derive-d` (derive `d` from `e` and `phi` or `p,q`)
  - `ctf-factor` (Pollard Rho factor attempt)
  - `ctf-solve` (factor `n`, derive `d`, decrypt `c`)
- Integer parsing supports decimal and hex (`0x...`).
- Output helpers for CTF decrypt: integer, hex, text, base64.

## Important Notes

- This is for legal CTF practice and education.
- `ctf-factor` and `ctf-solve` only work when `n` is weak/factorable.
- Real-world strong RSA keys will not be practically factorable with this script.

## Requirements

- Python 3.8+
- `cryptography` package

## Installation

```bash
git clone <your-repo-url>
cd rsa_endecrypt
python3 -m pip install cryptography
```

## Quick Start

Show help:

```bash
python3 rsa_endecypt.py --help
```

## CTF Workflows

### 1) Encrypt then decrypt (known `d`)

```bash
python3 rsa_endecypt.py ctf-encrypt --n 55 --e 3 --m-int 12
# output: 23

python3 rsa_endecypt.py ctf-decrypt --n 55 --c 23 --d 27
# output: 12
```

### 2) Decrypt when `p`, `q`, and `e` are known

```bash
python3 rsa_endecypt.py ctf-decrypt --n <n> --c <c> --p <p> --q <q> --e <e>
```

### 3) Derive `d` directly

```bash
python3 rsa_endecypt.py ctf-derive-d --e <e> --p <p> --q <q>
# or
python3 rsa_endecypt.py ctf-derive-d --e <e> --phi <phi>
```

### 4) Try to factor weak modulus

```bash
python3 rsa_endecypt.py ctf-factor --n <n>
```

### 5) Full auto solve for weak challenges

```bash
python3 rsa_endecypt.py ctf-solve --n <n> --e <e> --c <c> --as-text
```

### 6) Work with text messages in textbook RSA

```bash
python3 rsa_endecypt.py ctf-encrypt --n <n> --e <e> --m-text "flag"
python3 rsa_endecypt.py ctf-decrypt --n <n> --c <cipher_int> --d <d> --as-text
```

## Secure Mode (OAEP-SHA256)

Generate keys:

```bash
python3 rsa_endecypt.py keygen --bits 3072 --private-out private.pem --public-out public.pem
```

Encrypt text:

```bash
python3 rsa_endecypt.py encrypt --public-key public.pem --text "hello"
```

Decrypt base64 ciphertext:

```bash
python3 rsa_endecypt.py decrypt --private-key private.pem --base64 "<ciphertext>" --as-text
```

## Command Reference

```bash
python3 rsa_endecypt.py keygen --help
python3 rsa_endecypt.py encrypt --help
python3 rsa_endecypt.py decrypt --help
python3 rsa_endecypt.py ctf-encrypt --help
python3 rsa_endecypt.py ctf-decrypt --help
python3 rsa_endecypt.py ctf-derive-d --help
python3 rsa_endecypt.py ctf-factor --help
python3 rsa_endecypt.py ctf-solve --help
```

## Troubleshooting

- Error: `plaintext integer must satisfy m < n`
  - Use a larger modulus or smaller message integer.
- Error: modular inverse failure (`gcd(e, phi) != 1`)
  - Verify challenge parameters.
- `ctf-factor` fails
  - The modulus is likely too strong for this method.

