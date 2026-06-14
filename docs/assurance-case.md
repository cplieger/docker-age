# Security assurance case — docker-age

This extends the fleet-wide
[default assurance case](https://github.com/cplieger/.github/blob/main/assurance-case.md)
with the threat model specific to `docker-age`. Read that first.

## What this is

A distroless Go tool (`age-decrypt`) that decrypts age-encrypted `.env` files
**in place** at deploy time — the secrets-decryption step of the deploy
pipeline. It runs with access to the age identity (private key) and writes
plaintext secrets, so path-safety and bounded behaviour are the core concerns.

## Top-level claim

docker-age decrypts only the intended files, to the intended locations, without
following symlinks out of its target tree or being driven to exhaust resources,
and never exposes plaintext beyond the decrypted file.

## Threats and mitigations

| Threat | Mitigation | Evidence |
|---|---|---|
| Symlink attack redirecting a write outside the target dir | symlink-safe traversal via `os.OpenRoot` (Go 1.24+) | `main.go`, decrypt path tests |
| Path traversal in file selection | scoped, validated paths; decrypts only matched files | `identity.go`, `decrypt.go` |
| Malformed/hostile ciphertext crashing the decryptor | hardened decode under fuzz; bounded reads | `main_test.go`, fuzz target |
| Resource exhaustion (huge inputs) | bounded `io.LimitReader` sizes | source review |
| Concurrent deploy races corrupting files | concurrency-safe in-place rewrite | tests |
| Plaintext leakage | plaintext only written to the decrypted file; nothing logged | source review |

## Cryptography

Decryption uses `filippo.io/age` (the reference age implementation) — no
home-grown crypto. The age identity is provided at runtime and never logged.

## Residual risks

- Security depends on the age private key staying confidential; key custody is a
  deployment concern (documented in the homelab secrets handling).
- Decrypted `.env` files are plaintext on disk by design (consumed immediately
  by `docker compose up`); their lifetime/permissions are a deployment concern.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
