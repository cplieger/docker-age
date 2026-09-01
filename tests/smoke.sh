#!/bin/sh
# Build-time smoke test for the shipped decrypt path.
set -eu

bin="${AGE_DECRYPT_BIN:-age-decrypt}"
fail=0
log() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

if ! command -v "$bin" >/dev/null 2>&1; then
  err "FAIL: age-decrypt binary not found at '$bin' (set AGE_DECRYPT_BIN)"
  exit 1
fi

# age-decrypt cannot create its own fixture.
for tool in age age-keygen; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    err "FAIL: '$tool' not found (the Dockerfile test stage must 'apk add age')"
    exit 1
  fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

key="$work/keys.txt"
if ! age-keygen -o "$key" 2>/dev/null; then
  err "FAIL: age-keygen could not create a test identity"
  exit 1
fi
if ! recipient=$(age-keygen -y "$key" 2>/dev/null); then
  err "FAIL: age-keygen -y could not derive the recipient"
  exit 1
fi

plaintext='SMOKE_CHECK=round-trip-ok'
repo="$work/repo"
mkdir -p "$repo"
if ! printf '%s' "$plaintext" | age --encrypt --recipient "$recipient" --output "$repo/secret.env.enc"; then
  err "FAIL: could not create the binary-format .env.enc fixture"
  exit 1
fi
cp "$repo/secret.env.enc" "$work/secret.env.enc.orig"
if IDENTITY_PATH="$key" "$bin" decrypt --ext .env "$repo" 2>"$work/err1"; then
  got=$(cat "$repo/secret.env")
  if [ "$got" != "$plaintext" ]; then
    err "FAIL: sibling decrypt did not produce the expected plaintext (got: $got)"
    fail=1
  fi
  if ! cmp -s "$repo/secret.env.enc" "$work/secret.env.enc.orig"; then
    err "FAIL: the ciphertext source was modified by the decrypt pass"
    fail=1
  fi
else
  err "FAIL: 'age-decrypt decrypt --ext .env <dir>' exited non-zero on a valid fixture"
  err "$(cat "$work/err1")"
  fail=1
fi

if ! printf '%s' "$plaintext" | age --encrypt --armor --recipient "$recipient" --output "$work/secret.age"; then
  err "FAIL: could not create the armored fixture"
  exit 1
fi
if out=$(IDENTITY_PATH="$key" "$bin" decrypt - <"$work/secret.age" 2>"$work/err2"); then
  if [ "$out" != "$plaintext" ]; then
    err "FAIL: stdin decrypt did not restore the expected plaintext (got: $out)"
    fail=1
  fi
else
  err "FAIL: 'age-decrypt decrypt -' exited non-zero on valid ciphertext"
  err "$(cat "$work/err2")"
  fail=1
fi

if printf 'this is not age ciphertext\n' | IDENTITY_PATH="$key" "$bin" decrypt - >/dev/null 2>&1; then
  err "FAIL: 'age-decrypt decrypt -' accepted non-age input (expected non-zero exit)"
  fail=1
fi

stray="$work/stray-repo"
mkdir -p "$stray"
if ! printf '%s' "$plaintext" | age --encrypt --recipient "$recipient" --output "$stray/legacy.env"; then
  err "FAIL: could not create the stray-ciphertext fixture"
  exit 1
fi
if IDENTITY_PATH="$key" "$bin" decrypt --ext .env "$stray" >/dev/null 2>&1; then
  err "FAIL: stray ciphertext at legacy.env did not fail the pass (expected non-zero exit)"
  fail=1
fi

plainenc="$work/plainenc-repo"
mkdir -p "$plainenc"
printf 'NOT=encrypted\n' >"$plainenc/broken.env.enc"
if IDENTITY_PATH="$key" "$bin" decrypt --ext .env "$plainenc" >/dev/null 2>&1; then
  err "FAIL: plaintext under broken.env.enc did not fail the pass (expected non-zero exit)"
  fail=1
fi

invalidnames="$work/invalid-name-repo"
mkdir -p "$invalidnames"
printf 'invalid\n' >"$invalidnames/.enc"
printf 'invalid\n' >"$invalidnames/app.env.enc.enc"
if IDENTITY_PATH="$key" "$bin" decrypt --ext .env "$invalidnames" >/dev/null 2>&1; then
  err "FAIL: malformed .enc names were hidden by --ext (expected non-zero exit)"
  fail=1
fi

[ "$fail" -eq 0 ] && log "docker-age smoke: ok"
exit "$fail"
