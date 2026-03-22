# RSA CTF Tool

A practical command-line toolkit for solving RSA-focused CTF challenges, with an optional secure RSA (OAEP) mode for normal cryptographic workflows.

## Scripts

- `rsa_ctf_tool.py` (preferred entrypoint)
- `rsa_endecrypt.py` (direct module entrypoint)

## What This Tool Covers

- Textbook RSA operations: encrypt/decrypt integer messages used in many CTF tasks
- Key math helpers: derive `d` from `phi` or `p`,`q`
- Factoring-assisted solves: hybrid trial division + Fermat + Pollard Rho
- Specialized attacks:
  - Fermat factorization (`ctf-fermat`)
  - Common modulus attack (`ctf-common-modulus`)
  - Pollard p-1 (`ctf-pollard-pm1`)
- Secure mode (OAEP-SHA256) via `cryptography`:
  - `keygen`, `encrypt`, `decrypt`

## Requirements

- Python 3.8+
- `cryptography` is only required for secure mode commands (`keygen`, `encrypt`, `decrypt`)
- CTF commands run without `cryptography`

## Installation

```bash
git clone <your-repo-url>
cd rsa_endecrypt
python3 -m pip install -r requirements.txt
```

If you only use CTF commands, `cryptography` is optional.

## Quick Start

```bash
python3 rsa_ctf_tool.py --help
```

## Command Overview

| Command | Purpose |
|---|---|
| `keygen` | Generate RSA keypair (PEM) for secure mode |
| `encrypt` | Secure OAEP encryption |
| `decrypt` | Secure OAEP decryption |
| `ctf-encrypt` | Textbook RSA encrypt (`c = m^e mod n`) |
| `ctf-decrypt` | Textbook RSA decrypt (`m = c^d mod n`) |
| `ctf-derive-d` | Compute private exponent from `e` + (`phi` or `p,q`) |
| `ctf-factor` | Factor `n` and print factors + `phi(n)` |
| `ctf-solve` | Factor `n`, derive `d`, decrypt `c` |
| `ctf-auto` | Auto-solve shortcut for weak RSA challenge instances |
| `ctf-fermat` | Fermat factorization (best when `p` and `q` are close) |
| `ctf-common-modulus` | Recover message from same `n`, different exponents |
| `ctf-pollard-pm1` | Pollard p-1 attack for smooth-prime style challenges |

## Input Format

- Integer inputs accept:
  - decimal: `123456`
  - hex: `0xdeadbeef`
- For textbook RSA text conversion:
  - `ctf-encrypt --m-text "flag{...}"` converts UTF-8 text to integer

## Output Modes (CTF commands)

Most CTF commands support:

- `--auto` (default): tries user-friendly decoding
- `--as-text`: UTF-8 output
- `--as-hex`: hex integer
- `--as-base64`: base64 bytes
- `--as-int`: raw integer

## Typical CTF Workflows

### 1) Decrypt when `d` is known

```bash
python3 rsa_ctf_tool.py ctf-decrypt --n <n> --c <c> --d <d> --auto
```

### 2) Decrypt when `p`, `q`, `e` are known

```bash
python3 rsa_ctf_tool.py ctf-decrypt --n <n> --c <c> --p <p> --q <q> --e <e> --auto
```

### 3) Derive `d` first

```bash
python3 rsa_ctf_tool.py ctf-derive-d --e <e> --phi <phi>
# or
python3 rsa_ctf_tool.py ctf-derive-d --e <e> --p <p> --q <q>
```

### 4) Factor only (inspect factors and phi)

```bash
python3 rsa_ctf_tool.py ctf-factor --n <n> --verbose
```

Useful tuning flags:

- `--max-rho-attempts` (default `24`)
- `--max-rho-steps` (default `200000`)
- `--fermat-iterations` (default `1000000`)

### 5) Factor + decrypt in one command

```bash
python3 rsa_ctf_tool.py ctf-solve --n <n> --e <e> --c <c> --auto --verbose
```

### 6) One-command auto solve

```bash
python3 rsa_ctf_tool.py ctf-auto --n <n> --e <e> --c <c> --auto --verbose
```

### 7) Fermat attack (close prime factors)

```bash
python3 rsa_ctf_tool.py ctf-fermat --n <n> --e <e> --c <c> --auto --verbose
```

Useful tuning flags:

- `--max-iterations`
- `--progress-interval`

### 8) Common modulus attack

Use this when two ciphertexts encrypt the same plaintext under the same `n` but different exponents:

```bash
python3 rsa_ctf_tool.py ctf-common-modulus \
  --n <n> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2> --auto --verbose
```

### 9) Pollard p-1 attack

Use this when challenge hints suggest smooth `p-1` structure:

```bash
python3 rsa_ctf_tool.py ctf-pollard-pm1 --n <n> --e <e> --c <c> --auto --verbose
```

Useful tuning flags:

- `--b1` (default `1000000`)
- `--factorial-limit` (default `2000`)

## Which Attack Should I Try?

| Challenge Clue | Start With |
|---|---|
| You already have `d` | `ctf-decrypt --d` |
| You have `p`,`q` | `ctf-decrypt --p --q --e` |
| You have `phi` | `ctf-decrypt --phi --e` |
| Weak/small modulus | `ctf-auto` or `ctf-solve` |
| `p` and `q` are close | `ctf-fermat` |
| Same `n`, two exponents, same message | `ctf-common-modulus` |
| Smooth-prime hints (`p-1` smooth) | `ctf-pollard-pm1` |

## Secure Mode (OAEP-SHA256)

Generate keys:

```bash
python3 rsa_ctf_tool.py keygen --bits 3072 --private-out private.pem --public-out public.pem
```

Encrypt:

```bash
python3 rsa_ctf_tool.py encrypt --public-key public.pem --text "hello"
```

Decrypt:

```bash
python3 rsa_ctf_tool.py decrypt --private-key private.pem --base64 "<ciphertext>" --as-text
```

## Full Help Reference

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
python3 rsa_ctf_tool.py ctf-fermat --help
python3 rsa_ctf_tool.py ctf-common-modulus --help
python3 rsa_ctf_tool.py ctf-pollard-pm1 --help
```

## Troubleshooting

- `plaintext integer must satisfy m < n`
  - Your message integer is too large for the modulus.
- `gcd(e, phi) != 1`
  - `e` is not invertible modulo `phi`; verify challenge values.
- Factorization commands do not finish
  - Increase rho/fermat limits or switch to a more suitable attack (`ctf-fermat`, `ctf-common-modulus`, `ctf-pollard-pm1`).
- `ctf-common-modulus` fails with non-coprime exponents
  - Standard common modulus attack requires `gcd(e1, e2) = 1`.

## Safety and Scope

- Intended for legal CTFs and education.
- Not intended for attacking real systems.

## License

MIT. See `LICENSE`.
