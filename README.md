# Scrypt Password Hasher

A dependency-free Python utility for **password hashing and verification using scrypt**, a memory-hard password-based key derivation function available through Python's standard library.

The project is designed as a clear reference implementation for authentication-development and security-learning workflows.

> **Security:** Use only for systems and accounts you own or are explicitly authorized to administer. Never store or log plaintext passwords.

## Why scrypt?

Password hashing should be deliberately expensive for attackers while remaining practical for legitimate authentication.

scrypt is designed to be both computationally expensive and memory-intensive, making large-scale password guessing more costly than with ordinary fast hashes such as SHA-256.

This project uses:

- `N = 16384`
- `r = 8`
- `p = 1`
- 16-byte random salt
- 32-byte derived key

These are reasonable reference parameters for a small demonstration utility, but **production parameters should be selected and benchmarked for the deployment environment**.

## Features

- Python standard library only
- Cryptographically secure random salts
- Memory-hard scrypt KDF
- Self-describing stored hash format
- Per-record parameters
- Constant-time digest comparison
- Secure terminal password prompt when `--password` is omitted
- Input validation
- Machine-friendly exit codes
- Unit tests
- GitHub Actions CI

## Requirements

- Python 3.10+
- No third-party runtime dependencies

## Usage

### Generate a password hash

For interactive use, omit `--password`:

```bash
python3 scrypt_password_hasher.py hash
```

The program prompts without echoing the password.

For testing or automation:

```bash
python3 scrypt_password_hasher.py hash --password 'MyP@ss'
```

Example output:

```text
scrypt$v=1$n=16384$r=8$p=1$...$...
```

### Verify a password

```bash
python3 scrypt_password_hasher.py verify \
  --password 'MyP@ss' \
  --stored 'scrypt$v=1$n=16384$r=8$p=1$...$...'
```

Successful verification:

```text
MATCH
```

Incorrect password:

```text
NO MATCH
```

The process exits with:

- `0` for a match
- `1` for a valid record with no match
- `2` for malformed input or an operational error

## Stored format

Each record stores the algorithm version, scrypt parameters, salt, and derived key:

```text
scrypt$v=1$n=16384$r=8$p=1$<salt_hex>$<digest_hex>
```

Keeping parameters with the hash is important because password-hashing settings may need to change as hardware improves.

An authentication system can use the stored parameters to verify existing records and then rehash them with newer parameters after a successful login.

## Security considerations

### Do not use fast hashes

Do not replace password hashing with:

```text
SHA-256(password)
MD5(password)
SHA-1(password)
```

Fast hashes are designed for speed and are therefore poorly suited to password storage.

### Do not reuse salts

Every password hash receives a fresh random salt. Salts should not be secret, but they must be unique and unpredictable enough to prevent precomputed attacks.

### Do not pass production passwords on the command line

Command-line arguments may be visible through shell history or process inspection.

Prefer:

```bash
python3 scrypt_password_hasher.py hash
```

and enter the password interactively.

The `--password` option exists primarily for controlled testing and automation.

### Do not treat this as a complete authentication system

A production authentication system should additionally address:

- Login throttling
- Account lockout/risk controls where appropriate
- MFA
- Password-reset security
- Credential-stuffing defenses
- Secure session management
- TLS
- Secret handling
- Audit logging
- Secure password policies
- Rehashing/upgrading KDF parameters

## Parameter tuning

There is no universal "best" scrypt configuration.

Production parameters should be benchmarked on the actual server hardware and selected according to the application's authentication latency and threat model.

The important property is that the work factor is expensive enough to resist offline guessing while remaining acceptable for legitimate users.

## Limitations

This utility currently handles UTF-8 text passwords and stores the derived key as hexadecimal text.

It is intentionally not a complete password-management library or authentication framework.

For a production application, consider a mature password-hashing library with a well-maintained API and established migration support.

## Development

Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

## License

MIT. See [LICENSE](LICENSE).
