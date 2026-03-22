#!/usr/bin/env python3
"""RSA utility with secure mode and CTF helper mode.

Modes:
- Secure mode: RSA OAEP-SHA256 key generation/encrypt/decrypt for practical use.
- CTF mode: textbook RSA integer operations and helper commands commonly needed
  in CTF challenges.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from functools import lru_cache
import math
import pathlib
import random
import sys
from typing import Any, Optional


def _exit(message: str, code: int = 1) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(code)


def _read_bytes(path: pathlib.Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        _exit(f"file not found: {path}")
    except OSError as exc:
        _exit(f"failed to read {path}: {exc}")


def _write_bytes(path: pathlib.Path, data: bytes, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        _exit(f"refusing to overwrite existing file: {path} (use --force)")
    try:
        path.write_bytes(data)
    except OSError as exc:
        _exit(f"failed to write {path}: {exc}")


def _parse_nonnegative_int(value: str, name: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError:
        _exit(f"{name} must be an integer (supports decimal or 0x-prefixed hex)")
    if parsed < 0:
        _exit(f"{name} must be non-negative")
    return parsed


def _int_to_bytes(value: int) -> bytes:
    if value < 0:
        _exit("cannot convert negative integer to bytes")
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")


def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


def _mod_inverse(a: int, modulus: int) -> int:
    try:
        return pow(a, -1, modulus)
    except ValueError:
        _exit("e has no modular inverse modulo phi (gcd(e, phi) != 1)")


def _verbose(enabled: bool, message: str) -> None:
    if enabled:
        print(message)


@lru_cache(maxsize=1)
def _require_cryptography() -> dict[str, Any]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError:
        _exit(
            "secure mode requires the 'cryptography' package. "
            "Install it with: python3 -m pip install cryptography"
        )

    return {
        "hashes": hashes,
        "serialization": serialization,
        "padding": padding,
        "rsa": rsa,
        "Encoding": Encoding,
        "NoEncryption": NoEncryption,
        "PrivateFormat": PrivateFormat,
        "PublicFormat": PublicFormat,
    }


# -------------------------
# Secure OAEP mode
# -------------------------

def generate_keys(args: argparse.Namespace) -> None:
    deps = _require_cryptography()
    rsa = deps["rsa"]
    Encoding = deps["Encoding"]
    PrivateFormat = deps["PrivateFormat"]
    PublicFormat = deps["PublicFormat"]
    NoEncryption = deps["NoEncryption"]

    if args.bits < 2048:
        _exit("RSA key size must be at least 2048 bits")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    _write_bytes(args.private_out, private_pem, overwrite=args.force)
    _write_bytes(args.public_out, public_pem, overwrite=args.force)

    print(f"Private key written to: {args.private_out}")
    print(f"Public key written to:  {args.public_out}")


def _load_public_key(path: pathlib.Path):
    deps = _require_cryptography()
    serialization = deps["serialization"]

    key_data = _read_bytes(path)
    try:
        key = serialization.load_pem_public_key(key_data)
    except ValueError as exc:
        _exit(f"invalid public key PEM in {path}: {exc}")
    return key


def _load_private_key(path: pathlib.Path):
    deps = _require_cryptography()
    serialization = deps["serialization"]

    key_data = _read_bytes(path)
    try:
        key = serialization.load_pem_private_key(key_data, password=None)
    except ValueError as exc:
        _exit(f"invalid private key PEM in {path}: {exc}")
    return key


def _get_plaintext_from_args(args: argparse.Namespace) -> bytes:
    if args.text is not None and args.infile is not None:
        _exit("provide either --text or --infile, not both")
    if args.text is None and args.infile is None:
        _exit("provide one plaintext source: --text or --infile")

    if args.text is not None:
        return args.text.encode("utf-8")
    return _read_bytes(args.infile)


def _get_ciphertext_from_args(args: argparse.Namespace) -> bytes:
    if args.base64 is not None and args.infile is not None:
        _exit("provide either --base64 or --infile, not both")
    if args.base64 is None and args.infile is None:
        _exit("provide one ciphertext source: --base64 or --infile")

    if args.base64 is not None:
        try:
            return base64.b64decode(args.base64, validate=True)
        except ValueError as exc:
            _exit(f"invalid base64 ciphertext: {exc}")
    return _read_bytes(args.infile)


def _oaep_padding() -> Any:
    deps = _require_cryptography()
    padding = deps["padding"]
    hashes = deps["hashes"]
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_data(args: argparse.Namespace) -> None:
    deps = _require_cryptography()
    rsa = deps["rsa"]
    hashes = deps["hashes"]

    public_key = _load_public_key(args.public_key)
    plaintext = _get_plaintext_from_args(args)

    if not isinstance(public_key, rsa.RSAPublicKey):
        _exit("provided key is not an RSA public key")

    key_bytes = (public_key.key_size + 7) // 8
    max_plain_len = key_bytes - (2 * hashes.SHA256().digest_size) - 2
    if len(plaintext) > max_plain_len:
        _exit(
            f"plaintext too large for RSA OAEP single block (max {max_plain_len} bytes for this key). "
            "Use a hybrid scheme for larger data."
        )

    ciphertext = public_key.encrypt(plaintext, _oaep_padding())

    if args.outfile:
        _write_bytes(args.outfile, ciphertext, overwrite=args.force)
        print(f"Ciphertext written to: {args.outfile}")
    else:
        print(base64.b64encode(ciphertext).decode("ascii"))


def decrypt_data(args: argparse.Namespace) -> None:
    deps = _require_cryptography()
    rsa = deps["rsa"]

    private_key = _load_private_key(args.private_key)
    ciphertext = _get_ciphertext_from_args(args)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        _exit("provided key is not an RSA private key")

    try:
        plaintext = private_key.decrypt(ciphertext, _oaep_padding())
    except ValueError:
        _exit("decryption failed (wrong key, corrupted ciphertext, or wrong padding)")

    if args.outfile:
        _write_bytes(args.outfile, plaintext, overwrite=args.force)
        print(f"Plaintext written to: {args.outfile}")
        return

    if args.as_text:
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            _exit("decrypted bytes are not valid UTF-8; rerun without --as-text")
    else:
        print(base64.b64encode(plaintext).decode("ascii"))


# -------------------------
# CTF helper mode
# -------------------------


def _resolve_phi_and_d(
    d_raw: Optional[str],
    phi_raw: Optional[str],
    p_raw: Optional[str],
    q_raw: Optional[str],
    e_raw: Optional[str],
) -> tuple[int, Optional[int], list[int]]:
    if d_raw is not None:
        d = _parse_nonnegative_int(d_raw, "d")
        return d, None, []

    if phi_raw is not None:
        if e_raw is None:
            _exit("--e is required when using --phi")
        phi = _parse_nonnegative_int(phi_raw, "phi")
        e = _parse_nonnegative_int(e_raw, "e")
        if phi <= 1:
            _exit("phi must be > 1")
        d = _mod_inverse(e, phi)
        return d, phi, []

    if p_raw is not None or q_raw is not None:
        if p_raw is None or q_raw is None:
            _exit("both --p and --q are required together")
        if e_raw is None:
            _exit("--e is required when using --p/--q")
        p = _parse_nonnegative_int(p_raw, "p")
        q = _parse_nonnegative_int(q_raw, "q")
        e = _parse_nonnegative_int(e_raw, "e")
        if p <= 1 or q <= 1:
            _exit("p and q must be > 1")
        phi = (p - 1) * (q - 1)
        d = _mod_inverse(e, phi)
        return d, phi, [p, q]

    _exit("provide decryption material via one option: --d OR --phi --e OR --p --q --e")


def ctf_encrypt(args: argparse.Namespace) -> None:
    n = _parse_nonnegative_int(args.n, "n")
    e = _parse_nonnegative_int(args.e, "e")

    if n <= 1:
        _exit("n must be > 1")
    if e <= 0:
        _exit("e must be > 0")

    if args.m_int is not None and args.m_text is not None:
        _exit("provide either --m-int or --m-text, not both")
    if args.m_int is None and args.m_text is None:
        _exit("provide plaintext with --m-int or --m-text")

    if args.m_int is not None:
        m = _parse_nonnegative_int(args.m_int, "m")
    else:
        m = _bytes_to_int(args.m_text.encode("utf-8"))

    if m >= n:
        _exit("plaintext integer must satisfy m < n")

    c = pow(m, e, n)
    print(c)


def ctf_decrypt(args: argparse.Namespace) -> None:
    n = _parse_nonnegative_int(args.n, "n")
    c = _parse_nonnegative_int(args.c, "c")

    if n <= 1:
        _exit("n must be > 1")
    if c >= n:
        _exit("ciphertext integer should satisfy c < n")

    d, phi, known_factors = _resolve_phi_and_d(
        d_raw=args.d,
        phi_raw=args.phi,
        p_raw=args.p,
        q_raw=args.q,
        e_raw=args.e,
    )
    _verbose(args.verbose, f"[ctf-decrypt] using d={d}")

    m = pow(c, d, n)
    _verbose(args.verbose, f"[ctf-decrypt] computed m = c^d mod n")

    if args.show_private:
        print(f"d: {d}")
        if phi is not None:
            print(f"phi: {phi}")
        if known_factors:
            print("factors:")
            for factor in sorted(known_factors):
                print(factor)

    _print_ctf_plaintext(m, args.output_mode)


def ctf_derive_d(args: argparse.Namespace) -> None:
    if args.phi is not None and (args.p is not None or args.q is not None):
        _exit("use either --phi or --p/--q, not both")

    e = _parse_nonnegative_int(args.e, "e")

    if args.phi is not None:
        phi = _parse_nonnegative_int(args.phi, "phi")
    else:
        if args.p is None or args.q is None:
            _exit("provide --phi or both --p and --q")
        p = _parse_nonnegative_int(args.p, "p")
        q = _parse_nonnegative_int(args.q, "q")
        if p <= 1 or q <= 1:
            _exit("p and q must be > 1")
        phi = (p - 1) * (q - 1)

    if phi <= 1:
        _exit("phi must be > 1")

    d = _mod_inverse(e, phi)
    print(f"phi: {phi}")
    print(f"d: {d}")


def _generate_small_primes(limit: int = 1000) -> tuple[int, ...]:
    if limit < 2:
        return ()

    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False

    for p in range(2, int(limit ** 0.5) + 1):
        if sieve[p]:
            start = p * p
            sieve[start : limit + 1 : p] = [False] * (((limit - start) // p) + 1)

    return tuple(i for i, is_prime in enumerate(sieve) if is_prime)


_SMALL_PRIMES = _generate_small_primes(10000)


def _trial_division_factor(n: int) -> Optional[tuple[int, int]]:
    if n % 2 == 0:
        return 2, n // 2

    for prime in _SMALL_PRIMES:
        if prime == 2:
            continue
        if prime * prime > n:
            break
        if n % prime == 0:
            return prime, n // prime

    return None


def _is_probable_prime(n: int, rounds: int = 12) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True

    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if p * p > n:
            break
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def _pollards_rho(
    n: int, attempts: int = 24, max_steps: int = 200_000, verbose: bool = False
) -> Optional[int]:
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3

    for attempt_index in range(1, attempts + 1):
        _verbose(verbose, f"[+] Pollard Rho attempt {attempt_index}/{attempts}...")
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1

        for _ in range(max_steps):
            x = (pow(x, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            d = math.gcd(abs(x - y), n)
            if d == 1:
                continue
            if d == n:
                break
            _verbose(verbose, f"[+] factor found: {d}")
            return d

    _verbose(verbose, "[+] Pollard Rho did not find a factor with current limits")
    return None


def _factor_recursive(
    n: int,
    factors: list[int],
    verbose: bool = False,
    max_rho_attempts: int = 24,
    max_rho_steps: int = 200_000,
) -> bool:
    if n == 1:
        return True
    if _is_probable_prime(n):
        factors.append(n)
        _verbose(verbose, f"[+] factor found: {n}")
        return True

    _verbose(verbose, "[+] trial division...")
    trial_factor = _trial_division_factor(n)
    if trial_factor is not None:
        left, right = trial_factor
        left_ok = _factor_recursive(
            left,
            factors,
            verbose=verbose,
            max_rho_attempts=max_rho_attempts,
            max_rho_steps=max_rho_steps,
        )
        right_ok = _factor_recursive(
            right,
            factors,
            verbose=verbose,
            max_rho_attempts=max_rho_attempts,
            max_rho_steps=max_rho_steps,
        )
        return left_ok and right_ok

    divisor = _pollards_rho(
        n,
        attempts=max_rho_attempts,
        max_steps=max_rho_steps,
        verbose=verbose,
    )
    if divisor is None:
        return False
    left_ok = _factor_recursive(
        divisor,
        factors,
        verbose=verbose,
        max_rho_attempts=max_rho_attempts,
        max_rho_steps=max_rho_steps,
    )
    right_ok = _factor_recursive(
        n // divisor,
        factors,
        verbose=verbose,
        max_rho_attempts=max_rho_attempts,
        max_rho_steps=max_rho_steps,
    )
    return left_ok and right_ok


def _factorize(
    n: int,
    verbose: bool = False,
    max_rho_attempts: int = 24,
    max_rho_steps: int = 200_000,
) -> Optional[list[int]]:
    factors: list[int] = []
    success = _factor_recursive(
        n,
        factors,
        verbose=verbose,
        max_rho_attempts=max_rho_attempts,
        max_rho_steps=max_rho_steps,
    )
    if not success:
        return None
    factors.sort()
    return factors


def _phi_from_factorization(factors: list[int]) -> int:
    if not factors:
        _exit("cannot compute phi from empty factor list")

    counts = Counter(factors)
    phi = 1
    for prime, multiplicity in counts.items():
        if prime <= 1:
            _exit("factorization contains invalid factors")
        phi *= (prime - 1) * (prime ** (multiplicity - 1))
    return phi


def _render_ctf_plaintext(m: int) -> str:
    message_bytes = _int_to_bytes(m)

    try:
        decoded_text = message_bytes.decode("utf-8")
        if decoded_text and all(ch.isprintable() or ch in "\r\n\t" for ch in decoded_text):
            return decoded_text
    except UnicodeDecodeError:
        pass

    try:
        decoded = base64.b64decode(message_bytes, validate=True)
    except ValueError:
        decoded = b""

    if decoded:
        try:
            decoded_text = decoded.decode("utf-8")
            if decoded_text and all(ch.isprintable() or ch in "\r\n\t" for ch in decoded_text):
                return decoded_text
        except UnicodeDecodeError:
            pass

    return "\n".join(
        [
            f"message_int: {m}",
            f"message_hex: {hex(m)}",
            f"message_base64: {base64.b64encode(message_bytes).decode('ascii')}",
        ]
    )


def _print_ctf_plaintext(m: int, output_mode: str) -> None:
    message_bytes = _int_to_bytes(m)

    if output_mode == "text":
        try:
            print(message_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            _exit("decrypted integer is not valid UTF-8")
        return

    if output_mode == "hex":
        print(hex(m))
        return

    if output_mode == "base64":
        print(base64.b64encode(message_bytes).decode("ascii"))
        return

    rendered = _render_ctf_plaintext(m)
    if "\n" in rendered:
        print(rendered)
    else:
        print(f"message: {rendered}")


def _solve_ctf_values(
    n: int,
    e: int,
    c: int,
    verbose: bool = False,
    max_rho_attempts: int = 24,
    max_rho_steps: int = 200_000,
) -> Optional[tuple[list[int], int, int, int]]:
    _verbose(verbose, f"[ctf-solve] starting factorization of n={n}")
    factors = _factorize(
        n,
        verbose=verbose,
        max_rho_attempts=max_rho_attempts,
        max_rho_steps=max_rho_steps,
    )
    if factors is None:
        return None
    _verbose(verbose, f"[ctf-solve] factors={factors}")
    phi = _phi_from_factorization(factors)
    _verbose(verbose, f"[ctf-solve] phi(n)={phi}")
    d = _mod_inverse(e, phi)
    _verbose(verbose, f"[ctf-solve] derived d={d}")
    m = pow(c, d, n)
    _verbose(verbose, f"[ctf-solve] computed m = c^d mod n")
    return factors, phi, d, m


def _print_factorization(factors: list[int]) -> None:
    print("factors:")
    for factor in factors:
        print(factor)


def ctf_factor(args: argparse.Namespace) -> None:
    n = _parse_nonnegative_int(args.n, "n")
    if n <= 1:
        _exit("n must be > 1")
    if args.max_rho_attempts <= 0:
        _exit("--max-rho-attempts must be > 0")
    if args.max_rho_steps <= 0:
        _exit("--max-rho-steps must be > 0")

    _verbose(args.verbose, "[+] trial division...")
    factors = _factorize(
        n,
        verbose=args.verbose,
        max_rho_attempts=args.max_rho_attempts,
        max_rho_steps=args.max_rho_steps,
    )
    if factors is None:
        print(
            "factorization did not complete with current methods; "
            "this challenge may require a different RSA attack"
        )
        return
    _print_factorization(factors)
    phi = _phi_from_factorization(factors)
    print(f"phi: {phi}")


def ctf_solve(args: argparse.Namespace) -> None:
    n = _parse_nonnegative_int(args.n, "n")
    e = _parse_nonnegative_int(args.e, "e")
    c = _parse_nonnegative_int(args.c, "c")

    if n <= 1:
        _exit("n must be > 1")
    if c >= n:
        _exit("ciphertext integer should satisfy c < n")
    if args.max_rho_attempts <= 0:
        _exit("--max-rho-attempts must be > 0")
    if args.max_rho_steps <= 0:
        _exit("--max-rho-steps must be > 0")

    _verbose(args.verbose, "[+] trial division...")
    solved = _solve_ctf_values(
        n,
        e,
        c,
        verbose=args.verbose,
        max_rho_attempts=args.max_rho_attempts,
        max_rho_steps=args.max_rho_steps,
    )
    if solved is None:
        print(
            "factorization did not complete with current methods; "
            "this challenge may require a different RSA attack"
        )
        return
    factors, phi, d, m = solved
    _print_factorization(factors)
    print(f"phi: {phi}")
    print(f"d: {d}")
    _print_ctf_plaintext(m, args.output_mode)

def ctf_auto(args: argparse.Namespace) -> None:
    n = _parse_nonnegative_int(args.n, "n")
    e = _parse_nonnegative_int(args.e, "e")
    c = _parse_nonnegative_int(args.c, "c")

    if n <= 1:
        _exit("n must be > 1")
    if c >= n:
        _exit("ciphertext integer should satisfy c < n")

    _verbose(
        args.verbose,
        "[ctf-auto] strategy: trivial checks -> trial division -> Pollard Rho recursion",
    )
    solved = _solve_ctf_values(n, e, c, verbose=args.verbose)
    if solved is None:
        print(
            "factorization did not complete with current methods; "
            "this challenge may require a different RSA attack"
        )
        return
    factors, phi, d, m = solved
    _print_factorization(factors)
    print(f"phi: {phi}")
    print(f"d: {d}")
    _print_ctf_plaintext(m, args.output_mode)


# -------------------------
# CLI
# -------------------------


def _add_ctf_output_mode_flags(parser: argparse.ArgumentParser) -> None:
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--auto",
        dest="output_mode",
        action="store_const",
        const="auto",
        help="Auto decode plaintext (default)",
    )
    output_group.add_argument(
        "--as-text",
        dest="output_mode",
        action="store_const",
        const="text",
        help="Decode plaintext as UTF-8 text",
    )
    output_group.add_argument(
        "--as-hex",
        dest="output_mode",
        action="store_const",
        const="hex",
        help="Print plaintext integer as hex",
    )
    output_group.add_argument(
        "--as-base64",
        dest="output_mode",
        action="store_const",
        const="base64",
        help="Print plaintext bytes as base64",
    )
    parser.set_defaults(output_mode="auto")


def _add_verbose_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress and intermediate values",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "RSA utility: secure OAEP mode for practical crypto and CTF mode "
            "for textbook RSA challenge solving."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate RSA keypair in PEM format (secure mode)")
    keygen.add_argument("--bits", type=int, default=3072, help="Key size in bits (default: 3072)")
    keygen.add_argument(
        "--private-out",
        type=pathlib.Path,
        default=pathlib.Path("private_key.pem"),
        help="Output path for private key PEM",
    )
    keygen.add_argument(
        "--public-out",
        type=pathlib.Path,
        default=pathlib.Path("public_key.pem"),
        help="Output path for public key PEM",
    )
    keygen.add_argument("--force", action="store_true", help="Overwrite output files if they exist")
    keygen.set_defaults(func=generate_keys)

    encrypt = subparsers.add_parser("encrypt", help="Encrypt one plaintext block with RSA-OAEP (secure mode)")
    encrypt.add_argument("--public-key", type=pathlib.Path, required=True, help="Public key PEM path")
    encrypt.add_argument("--text", type=str, help="UTF-8 plaintext string")
    encrypt.add_argument("--infile", type=pathlib.Path, help="Plaintext file path")
    encrypt.add_argument("--outfile", type=pathlib.Path, help="Write raw ciphertext bytes to file")
    encrypt.add_argument("--force", action="store_true", help="Overwrite outfile if it exists")
    encrypt.set_defaults(func=encrypt_data)

    decrypt = subparsers.add_parser("decrypt", help="Decrypt RSA-OAEP ciphertext (secure mode)")
    decrypt.add_argument("--private-key", type=pathlib.Path, required=True, help="Private key PEM path")
    decrypt.add_argument("--base64", type=str, help="Base64 ciphertext")
    decrypt.add_argument("--infile", type=pathlib.Path, help="Ciphertext file path (raw bytes)")
    decrypt.add_argument("--outfile", type=pathlib.Path, help="Write plaintext bytes to file")
    decrypt.add_argument("--as-text", action="store_true", help="Print plaintext as UTF-8")
    decrypt.add_argument("--force", action="store_true", help="Overwrite outfile if it exists")
    decrypt.set_defaults(func=decrypt_data)

    ctf_encrypt_parser = subparsers.add_parser(
        "ctf-encrypt", help="Textbook RSA encryption for CTFs: c = m^e mod n"
    )
    ctf_encrypt_parser.add_argument("--n", required=True, help="Modulus n (decimal or 0x hex)")
    ctf_encrypt_parser.add_argument("--e", required=True, help="Public exponent e")
    ctf_encrypt_parser.add_argument("--m-int", help="Plaintext integer m")
    ctf_encrypt_parser.add_argument("--m-text", help="Plaintext text converted to integer (UTF-8 big-endian)")
    ctf_encrypt_parser.set_defaults(func=ctf_encrypt)

    ctf_decrypt_parser = subparsers.add_parser(
        "ctf-decrypt", help="Textbook RSA decryption for CTFs: m = c^d mod n"
    )
    ctf_decrypt_parser.add_argument("--n", required=True, help="Modulus n")
    ctf_decrypt_parser.add_argument("--c", required=True, help="Ciphertext integer")
    ctf_decrypt_parser.add_argument("--d", help="Private exponent d")
    ctf_decrypt_parser.add_argument("--phi", help="Euler totient phi(n)")
    ctf_decrypt_parser.add_argument("--p", help="Prime factor p of n")
    ctf_decrypt_parser.add_argument("--q", help="Prime factor q of n")
    ctf_decrypt_parser.add_argument("--e", help="Public exponent e (required with --phi or --p/--q)")
    ctf_decrypt_parser.add_argument("--show-private", action="store_true", help="Show derived private values")
    _add_ctf_output_mode_flags(ctf_decrypt_parser)
    _add_verbose_flag(ctf_decrypt_parser)
    ctf_decrypt_parser.set_defaults(func=ctf_decrypt)

    ctf_derive_d_parser = subparsers.add_parser(
        "ctf-derive-d", help="Derive private exponent d from e and phi, or e/p/q"
    )
    ctf_derive_d_parser.add_argument("--e", required=True, help="Public exponent e")
    ctf_derive_d_parser.add_argument("--phi", help="Euler totient phi(n)")
    ctf_derive_d_parser.add_argument("--p", help="Prime factor p")
    ctf_derive_d_parser.add_argument("--q", help="Prime factor q")
    ctf_derive_d_parser.set_defaults(func=ctf_derive_d)

    ctf_factor_parser = subparsers.add_parser(
        "ctf-factor", help="Try factoring n with Pollard Rho (works for weaker CTF moduli)"
    )
    ctf_factor_parser.add_argument("--n", required=True, help="Modulus n")
    ctf_factor_parser.add_argument(
        "--max-rho-attempts",
        type=int,
        default=24,
        help="Maximum Pollard Rho retry attempts (default: 24)",
    )
    ctf_factor_parser.add_argument(
        "--max-rho-steps",
        type=int,
        default=200000,
        help="Maximum iteration steps per Pollard Rho attempt (default: 200000)",
    )
    _add_verbose_flag(ctf_factor_parser)
    ctf_factor_parser.set_defaults(func=ctf_factor)

    ctf_solve_parser = subparsers.add_parser(
        "ctf-solve",
        help="Attempt full solve: factor n, derive d from e, decrypt c",
    )
    ctf_solve_parser.add_argument("--n", required=True, help="Modulus n")
    ctf_solve_parser.add_argument("--e", required=True, help="Public exponent e")
    ctf_solve_parser.add_argument("--c", required=True, help="Ciphertext integer")
    ctf_solve_parser.add_argument(
        "--max-rho-attempts",
        type=int,
        default=24,
        help="Maximum Pollard Rho retry attempts (default: 24)",
    )
    ctf_solve_parser.add_argument(
        "--max-rho-steps",
        type=int,
        default=200000,
        help="Maximum iteration steps per Pollard Rho attempt (default: 200000)",
    )
    _add_ctf_output_mode_flags(ctf_solve_parser)
    _add_verbose_flag(ctf_solve_parser)
    ctf_solve_parser.set_defaults(func=ctf_solve)

    ctf_auto_parser = subparsers.add_parser(
        "ctf-auto",
        help="Auto solve RSA CTF challenge: factor n, derive d, decrypt c with auto decoding",
    )
    ctf_auto_parser.add_argument("--n", required=True, help="Modulus n")
    ctf_auto_parser.add_argument("--e", required=True, help="Public exponent e")
    ctf_auto_parser.add_argument("--c", required=True, help="Ciphertext integer")
    _add_ctf_output_mode_flags(ctf_auto_parser)
    _add_verbose_flag(ctf_auto_parser)
    ctf_auto_parser.set_defaults(func=ctf_auto)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
