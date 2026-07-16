# Security assurance case — docker-age

This extends the shared
[default assurance case](https://github.com/cplieger/.github/blob/main/assurance-case.md)
with the threat model specific to `docker-age`. Read that first.

## What this is

A distroless Go tool (`age-decrypt`) that decrypts age-encrypted `.enc`
sources to their **plaintext siblings** (`apps/x/.env.enc` → `apps/x/.env`) at
deploy time — the secrets-decryption step of the deploy pipeline. It runs with
access to the age identity (private key) and writes plaintext secrets, so
path-safety, source immutability, and bounded behaviour are the core concerns.

## Top-level claim

docker-age decrypts only intended regular, single-link `.enc` sources, writes
plaintext only to sibling paths inside the target tree (mode 0600), never
modifies a ciphertext source, and fails closed on stable symlink, hardlink, and
nonregular inputs. Each file is bounded to 10 MB of ciphertext and 1 MB of
plaintext; aggregate work scales with the checkout. Plaintext is published through a cryptographically
random, exclusively created temp whose inode, mode, and link count are checked
before atomic rename. Under an `--ext` filter it additionally fails closed on
stray age ciphertext or a nonregular entry at a plaintext path, blocking a
deploy that cannot prove its config path is regular plaintext.

## Threats and mitigations

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| Symlink or nonregular source redirects/blocks a read | rooted before/open/after inode checks, nonblocking open, regular-file requirement | `openRegularReadOnly`, symlink/FIFO tests |
| Hardlinked source imports ciphertext from outside the root | every source snapshot and descriptor must have link count one | hardlinked-source unit and walk tests |
| Pre-seeded temp truncates ciphertext or another victim | 128-bit random same-directory name; `O_CREATE\|O_EXCL`; writes only through the owned descriptor | `createTempFile`, pre-seeded regular/symlink/hardlink tests |
| Temp hardlink or mode drift leaks plaintext | exact 0600 and link-count-one checks before rename; cleanup zeroes the validated inode, never an unchecked path | `validateTempFile`, temp lifecycle tests |
| Path traversal in output derivation | output = source minus `.enc`, same directory; malformed bare/double suffixes fail before filtering | `outputRelFor`, walk tests |
| Failed decrypt destroys tracked ciphertext | sources are read-only; plaintext goes to a sibling via temp+rename | fuzz invariant, source-preservation tests |
| Malformed/hostile ciphertext crashes or expands output | hardened decode; 10 MB encrypted and 1 MB plaintext per-file bounds | fuzz target, boundary tests |
| Concurrent decrypt passes collide | random exclusive temp names; age-bound sweep preserves young peers | concurrency tests |
| Orphan sweep deletes/truncates an unrelated file | strict v3/legacy name grammar plus no-follow regular, 0600, single-link and age checks | matcher and sweep tests |
| Un-migrated secret is consumed as ciphertext | stray-ciphertext and matching-nonregular guard under `--ext` fails the pass | `checkStray`, walk tests |
| Plaintext appears beyond intended output | plaintext only enters an owned 0600 temp and sibling output; buffers are cleared; values are never logged | source review |

## Cryptography

Decryption uses `filippo.io/age` (the reference age implementation) — no
home-grown crypto. The age identity is provided at runtime and never logged.

## Residual risks

- Security depends on the age private key staying confidential; key custody is a
  deployment concern (documented in the deployment's secrets handling).
- Generated `.env` siblings are plaintext on disk by design (consumed
  immediately by `docker compose up`); they persist between deploys on the
  live volume. Deleting a `.enc` source does not delete a previously generated
  sibling. If a sibling remains tracked, decrypt intentionally overwrites it
  and leaves the checkout dirty.
- Sources with more than one hardlink are rejected so a static directory entry
  cannot import an out-of-scope ciphertext inode. Path and link checks cannot
  prove the historical provenance of bytes copied or renamed into the root.
- The filesystem must be stable against untrusted mutation during a pass.
  Concurrent `age-decrypt` invocations are supported, but an attacker with
  active write/rename/hardlink control over the checkout is outside the
  snapshot-free threat model.
- On cancellation (SIGINT/SIGTERM) a pass exits non-zero and never reports
  success, and `decrypt -` returns promptly even when stdin is a blocking
  inherited descriptor. Publication is not transactional at the final step,
  though: a signal landing in the single-syscall window between the last
  cancellation check and the stdout write (stdin mode) or the atomic rename
  (file mode) can still emit that one file's plaintext before the non-zero
  exit. A generic stdout sink and a POSIX rename cannot be rolled back; the
  file-mode output is always a complete, current derivation of its own source,
  and the non-zero exit blocks the deploy from consuming a partial result.
- Input/output bounds are per file. There is no aggregate file-count,
  total-byte, or wall-clock budget; deployment controls must bound tree size
  and invocation frequency.
- The strict random and legacy `.age-decrypt-tmp` grammars are reserved for
  decryptor plaintext temps; application files must not use that namespace.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
