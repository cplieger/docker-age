#!/bin/sh
# Build-time smoke test for docker-age.
#
# Runs in the Dockerfile `test` stage (FROM the builder, which additionally
# installs the upstream `age` CLI), so the central `ci / validate` docker
# build-ability gate executes it on every PR and push (the final stage depends
# on this stage's /tests-passed marker). Asserts the real, high-value failure
# mode for this image: that the freshly built age-decrypt binary actually
# DECRYPTS age ciphertext end to end. A broken build means the homelab's
# deploy-time secrets step (`docker exec age /age-decrypt decrypt --ext .env`)
# decrypts nothing and every deploy fails, so "it decrypts" is worth proving.
#
# age-decrypt is decrypt-only (no keygen/encrypt subcommand), so the fixture is
# MINTED at build time with the upstream `age`/`age-keygen` CLIs rather than
# committed: a throwaway X25519 identity plus a known plaintext encrypted to it.
# Nothing secret is committed to the repo, which keeps the gitleaks scan clean
# and the deny-all .dockerignore intact.
#
# Run locally:  AGE_DECRYPT_BIN=./age-decrypt sh tests/smoke.sh
#   (build the binary first with `go build .`; needs `age` + `age-keygen` on PATH)
set -eu

bin="${AGE_DECRYPT_BIN:-age-decrypt}"
fail=0
log() { printf '%s\n' "$*"; }     # progress + final verdict -> stdout
err() { printf '%s\n' "$*" >&2; } # failures + captured output -> stderr

# The binary under test must be resolvable (clearer than a failure mid-assert).
if ! command -v "$bin" >/dev/null 2>&1; then
  err "FAIL: age-decrypt binary not found at '$bin' (set AGE_DECRYPT_BIN)"
  exit 1
fi

# The upstream age CLIs mint the fixture the decrypt-only binary cannot make
# itself. Missing here means the test stage forgot to install `age`.
for tool in age age-keygen; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "FAIL: '$tool' not found (the Dockerfile test stage must 'apk add age')"
    exit 1
  fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Fixture: a throwaway identity (0600, written by age-keygen) and the recipient
# derived from it. Fixture-setup failures are fatal (the asserts are meaningless
# without it), so they exit rather than accumulate.
key="$work/keys.txt"
if ! age-keygen -o "$key" 2>/dev/null; then
  err "FAIL: age-keygen could not create a test identity"
  exit 1
fi
if ! recipient=$(age-keygen -y "$key" 2>/dev/null); then
  err "FAIL: age-keygen -y could not derive the recipient"
  exit 1
fi

# A .env-shaped marker (no secret-scanner trigger word, low entropy) — the
# assertion is only that decrypt returns exactly what was encrypted.
plaintext='SMOKE_CHECK=round-trip-ok'

# 1. In-place tree decrypt: the exact command the homelab deploy runs
#    (`age-decrypt decrypt --ext .env <dir>`), against a BINARY-format fixture.
#    Encrypt to a .env under a subtree, decrypt the tree in place, and assert
#    the file now holds the original plaintext.
repo="$work/repo"
mkdir -p "$repo"
if ! printf '%s' "$plaintext" | age --encrypt --recipient "$recipient" --output "$repo/secret.env"; then
  err "FAIL: could not create the binary-format .env fixture"
  exit 1
fi
if AGE_KEY_FILE="$key" "$bin" decrypt --ext .env "$repo" 2>"$work/err1"; then
  got=$(cat "$repo/secret.env")
  if [ "$got" != "$plaintext" ]; then
    err "FAIL: in-place decrypt did not restore the expected plaintext (got: $got)"
    fail=1
  fi
else
  err "FAIL: 'age-decrypt decrypt --ext .env <dir>' exited non-zero on a valid fixture"
  err "$(cat "$work/err1")"
  fail=1
fi

# 2. Stdin pipe decrypt: the scripted single-file path (Komodo Materialize),
#    against an ARMORED fixture. slog diagnostics go to stderr, so the captured
#    stdout is pure plaintext.
if ! printf '%s' "$plaintext" | age --encrypt --armor --recipient "$recipient" --output "$work/secret.age"; then
  err "FAIL: could not create the armored fixture"
  exit 1
fi
if out=$(AGE_KEY_FILE="$key" "$bin" decrypt - <"$work/secret.age" 2>"$work/err2"); then
  if [ "$out" != "$plaintext" ]; then
    err "FAIL: stdin decrypt did not restore the expected plaintext (got: $out)"
    fail=1
  fi
else
  err "FAIL: 'age-decrypt decrypt -' exited non-zero on valid ciphertext"
  err "$(cat "$work/err2")"
  fail=1
fi

# 3. Negative: a non-age payload must be rejected with a non-zero exit. This
#    proves the binary runs and validates its input, not merely that it exists
#    (a bare "binary is present" check would be a tautology).
if printf 'this is not age ciphertext\n' | AGE_KEY_FILE="$key" "$bin" decrypt - >/dev/null 2>&1; then
  err "FAIL: 'age-decrypt decrypt -' accepted non-age input (expected non-zero exit)"
  fail=1
fi

[ "$fail" -eq 0 ] && log "docker-age smoke: ok"
exit "$fail"
