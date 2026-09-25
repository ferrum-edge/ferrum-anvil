# ADR 0004: Encrypted local store and key wrapping

## Context
URLs, bodies and history are often sensitive, not just the variables marked
secret (plan §13). The vault must survive a lost passphrase through an
explicit recovery path and must never depend on a cloud account.

## Decision
- One SQLite database per profile. Every payload (objects, secrets, history,
  blobs, load reports) is sealed with XChaCha20-Poly1305 under a random data
  key, using an AAD that binds table, kind and id so records cannot be
  swapped.
- The data key is wrapped by an Argon2id passphrase key and separately by a
  recovery key shown once at creation. Alternatively it is held in the OS
  keychain (`keyring` 4). The header records the KDF parameters.
- Locking drops the key and caches. Backend commands refuse while locked.
- Migrations are versioned, and the app refuses to open a database written by
  a newer schema. Checkpoints (`VACUUM INTO`) are taken before imports.
- A plaintext-leak audit test scans the database, WAL/journal files and
  blobs for known secrets.

## Consequences
- A lost passphrase without the recovery key means the data is gone, and the
  app says so. Portable backups (ADR 0005) are the other recovery route.
- An unlocked OS session with a keychain profile is not a separate security
  boundary. The UI states this.
