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
- Integer parsing supports decimal and hex (`0x...`).
- Output modes: `--auto` (default), `--as-text`, `--as-hex`, `--as-base64`.
- Verbose tracing for CTF solving with `--verbose`.

## Important Notes

- This is for legal CTF practice and education.
- `ctf-factor` and `ctf-solve` only work when `n` is weak/factorable.
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
```

## Troubleshooting

- Error: `plaintext integer must satisfy m < n`
  - Use a larger modulus or smaller message integer.
- Error: modular inverse failure (`gcd(e, phi) != 1`)
  - Verify challenge parameters.
- `ctf-factor` fails
  - The modulus is likely too strong for this method.
