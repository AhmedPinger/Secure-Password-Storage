# Secure-Password-Storage

A from-scratch implementation of salted, iterated password hashing and constant-time verification, built without bcrypt, scrypt, argon2, or `hashlib.pbkdf2_hmac`. It exists to show what those libraries do internally: generate a unique salt, run a deliberately slow key derivation function, and compare hashes in a way that does not leak timing information. It is a reference implementation for understanding the mechanics, not a drop-in replacement for a vetted password-hashing library in production.

## What it does

All logic lives in one class, `SecurePasswordManager`, in `manager.py`:

- `generate_salt()`: a 32-byte random salt per password, from `os.urandom()`.
- `slow_hash()`: an iterative SHA-256 construction (100,000 rounds by default), each round folding in the running hash, the password, the salt, and a counter.
- `_constant_time_compare()`: an XOR-and-accumulate comparison across the full length of both byte strings, so the comparison takes the same time regardless of where a mismatch occurs.
- `register_user()`, `authenticate_user()`, `change_password()`: user management built on the above.
- `export_storage()` / `import_storage()`: persist the in-memory user table to and from a JSON file, as hex-encoded salt, hash, and iteration count per user.

Why the slow hash matters: a single SHA-256 call takes microseconds, so an attacker who steals a hash database can test billions of password guesses per second against it. Running 100,000 chained rounds per guess raises that cost by the same factor, turning an attack that takes hours into one that takes over a decade for the same password space.

Why the constant-time comparison matters: a comparison that returns as soon as it finds the first mismatched byte leaks, through response timing, how many leading bytes of a guess were already correct. An attacker can use that signal to reconstruct a hash byte by byte. Accumulating the XOR of every byte pair before checking the result removes that signal.

`authenticate_user()` also runs a dummy hash for usernames that do not exist, so a login attempt against a real account and one against a nonexistent account take the same amount of time; without it, timing alone would let an attacker enumerate valid usernames.

## Requirements

Python 3, standard library only (`os`, `hashlib`, `time`, `json`, `typing`). No packages to install.

## Running it

```bash
python3 manager.py
```

This runs the bundled `demonstrate_system()` walkthrough: it registers three users, authenticates each with the correct password, confirms wrong passwords and a nonexistent user are rejected, changes one user's password and confirms the old password stops working, prints the per-operation timing (expect roughly 0.3 to 0.5 seconds per hash, by design), and exports the resulting store to `password_storage.json` before reloading it into a second manager instance to confirm the round trip works.

## Using it directly

```python
from manager import SecurePasswordManager

pm = SecurePasswordManager(iterations=100000)
pm.register_user("alice", "SecurePassword123!")
pm.authenticate_user("alice", "SecurePassword123!")  # True
```

## Limitations

- Storage is an in-memory dictionary for the life of the process; `export_storage()` writes it to a plain JSON file with no encryption at rest, so protecting that file is left to the caller.
- The iterative construction chains raw SHA-256 calls rather than using HMAC (as PBKDF2 does) or a memory-hard function (as scrypt and argon2 do), so unlike those, it is not resistant to GPU- or ASIC-parallelized cracking attempts, only to unparallelized brute force at the process level.
- There is no password strength validation, rate limiting, or account lockout; those are left to the caller.
- This has not been independently audited. For anything handling real user credentials, use a maintained library (argon2id or bcrypt) instead of this implementation.

## Credit

`manager.py` was originally written as a joint university software security
project with Jakyi Humphrey.

---
https://www.assumed-breach.com
