#!/usr/bin/env python3
"""Hash and verify passwords using Python's memory-hard scrypt KDF.

The stored representation is:

    scrypt$v=1$n=16384$r=8$p=1$<salt_hex>$<digest_hex>

Parameters are encoded alongside the derived key so records remain
self-describing and can be upgraded deliberately in the future.

This utility is intended for defensive authentication development.
Never store plaintext passwords or expose password values in logs.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import secrets
import sys
from dataclasses import dataclass


SALT_BYTES = 16
DK_BYTES = 32

DEFAULT_N = 2**14
DEFAULT_R = 8
DEFAULT_P = 1

SCHEME = "scrypt"
VERSION = 1


@dataclass(frozen=True)
class ScryptRecord:
    """Parsed, self-describing scrypt password record."""

    n: int
    r: int
    p: int
    salt: bytes
    digest: bytes

    def encode(self) -> str:
        """Serialize the record into the portable storage format."""
        return (
            f"{SCHEME}$v={VERSION}$n={self.n}$r={self.r}$p={self.p}$"
            f"{self.salt.hex()}${self.digest.hex()}"
        )


def derive_key(
    password: str,
    salt: bytes,
    *,
    n: int = DEFAULT_N,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
    dklen: int = DK_BYTES,
) -> bytes:
    """Derive a password key using scrypt."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
    )


def hash_password(password: str) -> str:
    """Create a new random-salt scrypt password record."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = derive_key(password, salt)

    return ScryptRecord(
        n=DEFAULT_N,
        r=DEFAULT_R,
        p=DEFAULT_P,
        salt=salt,
        digest=digest,
    ).encode()


def parse_record(stored: str) -> ScryptRecord:
    """Parse and validate a serialized scrypt record."""
    parts = stored.split("$")

    if len(parts) != 7:
        raise ValueError("invalid stored password format")

    scheme, version, n_field, r_field, p_field, salt_hex, digest_hex = parts

    if scheme != SCHEME or version != f"v={VERSION}":
        raise ValueError("unsupported password hash scheme or version")

    try:
        n = int(n_field.removeprefix("n="))
        r = int(r_field.removeprefix("r="))
        p = int(p_field.removeprefix("p="))
        salt = bytes.fromhex(salt_hex)
        digest = bytes.fromhex(digest_hex)
    except ValueError as exc:
        raise ValueError("invalid scrypt record fields") from exc

    if not n_field.startswith("n=") or not r_field.startswith("r="):
        raise ValueError("invalid scrypt parameter fields")

    if not p_field.startswith("p="):
        raise ValueError("invalid scrypt parameter fields")

    if n <= 1 or n & (n - 1):
        raise ValueError("scrypt n must be a power of two greater than 1")

    if r <= 0 or p <= 0:
        raise ValueError("scrypt r and p must be positive")

    if len(salt) < 16:
        raise ValueError("salt must be at least 16 bytes")

    if len(digest) != DK_BYTES:
        raise ValueError(f"derived key must be exactly {DK_BYTES} bytes")

    return ScryptRecord(n=n, r=r, p=p, salt=salt, digest=digest)


def verify_password(password: str, stored: str) -> bool:
    """Verify a password using constant-time digest comparison."""
    record = parse_record(stored)

    candidate = derive_key(
        password,
        record.salt,
        n=record.n,
        r=record.r,
        p=record.p,
        dklen=len(record.digest),
    )

    return hmac.compare_digest(candidate, record.digest)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Hash and verify passwords using the scrypt KDF."
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    hash_parser = subparsers.add_parser(
        "hash",
        help="Generate a new password hash.",
    )
    hash_parser.add_argument(
        "--password",
        help="Password to hash. Omit to enter it securely without echo.",
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a password against a stored hash.",
    )
    verify_parser.add_argument(
        "--password",
        help="Password to verify. Omit to enter it securely without echo.",
    )
    verify_parser.add_argument(
        "--stored",
        required=True,
        help="Stored scrypt record.",
    )

    return parser


def read_password(value: str | None, prompt: str) -> str:
    """Use a supplied password or securely prompt without terminal echo."""
    return value if value is not None else getpass.getpass(prompt)


def main() -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.mode == "hash":
            password = read_password(args.password, "Password: ")
            print(hash_password(password))
            return 0

        password = read_password(args.password, "Password: ")
        matched = verify_password(password, args.stored)

    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("MATCH" if matched else "NO MATCH")
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
