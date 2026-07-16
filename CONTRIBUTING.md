# Contributing to docker-age

Notes specific to this repo. For org-wide defaults (commit conventions,
PR workflow), the [`cplieger/.github`](https://github.com/cplieger/.github)
fallback applies; this file covers what's particular to the code here.

## What this is

A single static Go binary (`age-decrypt`) shipped on
`gcr.io/distroless/static:nonroot`. It walks a mounted tree, reads tracked
`<name>.enc` age ciphertext, and atomically generates the canonical plaintext
sibling `<name>` (for example `.env.enc` → `.env`). Ciphertext is never
modified; generated plaintext is expected to be gitignored. The module path is
`github.com/cplieger/age-decrypt/v3` even though the repo and image are named
`docker-age` — the binary name, not the repo name, is the canonical identifier.

## Layout

Flat `package main`, one concern per file:

- `main.go` — entry point and the two run modes (`runDecrypt`,
  `runServer`), plus the file-based health marker/probe wiring via
  `github.com/cplieger/health`. The `health` probe is intercepted here
  _before_ `parseConfig` runs, because the probe must work without
  `AGE_KEY_FILE` set.
- `config.go` — env-var parsing (`AGE_KEY_FILE`, `AGE_REPO_ROOT`) and mode
  selection from `os.Args[1]` (`decrypt` → decrypt mode with `--ext`/path/pipe parsing, `health` → probe,
  empty → server).
- `identity.go` — `loadIdentities` loads **all** age identities from the key
  file, returning `[]age.Identity` (the interface, not a concrete key type) so
  future key kinds don't churn callers and multiple identities enable key
  rotation. Caps the key file at 1 MB.
- `decrypt.go` — the core: candidate/name validation, safe source opens,
  decrypt limits, random exclusive temp publication, strict orphan cleanup,
  and the fail-closed tree walk.

## Load-bearing invariants

These are easy to break and the tests exist to catch them. Read this
before touching `decrypt.go`.

- **All tree I/O goes through the `*os.Root` handle.** `decryptAll` opens
  the tree with `os.OpenRoot`; reads use a nonblocking rooted descriptor plus
  before/open/after inode checks and reject nonregular or multiply-linked
  sources. Ciphertext is streamed through bounded readers. Plaintext is
  written only through a newly created rooted descriptor and published with
  `rootDir.Rename`. Do not add a bare path open/write for files inside the
  walked tree.
- **Temp creation is random and exclusive.** New names are
  `<output>.<32-lowercase-hex-chars>.age-decrypt-tmp` (128 random bits), opened
  with `O_CREATE|O_EXCL` at 0600. All bytes go through that owned descriptor;
  mode 0600 and link count 1 are rechecked before rename. Never replace this
  with `WriteFile` or a predictable name: either can truncate a pre-seeded
  regular file, symlink target, or hardlink to the ciphertext source.
- **The temp namespace and cleanup checks move together.** The orphan sweep
  recognizes only the random v3 grammar and strict legacy
  `<output>.<pid>.<counter>` grammar, and touches only stale regular 0600
  single-link files. Failed-write cleanup truncates the owned/verified inode,
  never an unchecked path. The namespace is reserved and the checkout is
  assumed stable against untrusted mutation during a pass; concurrent
  `age-decrypt` peers are supported.
- **`decryptFile` is tri-state, but `.enc` content never silently skips.** It
  returns `fileDecrypted`, `fileFailed`, or `fileSkipped` only for cancellation.
  A `.enc` source that is non-age, malformed, unreadable, nonregular, or cannot
  publish its sibling is a failure. In decrypt mode the process exits non-zero
  when `result.Failed > 0`, on any walk error, cancellation, or unreadable root.
  Under `--ext`, matching non-`.enc` regular plaintext counts as skipped; stray
  ciphertext and matching nonregular paths fail. A legitimately empty tree is
  still a clean run with a no-match warning.
- **Name validation precedes filtering.** Bare `.enc` and double
  `.enc.enc` names fail even when `--ext` would otherwise exclude them.
  `--ext` filters the post-strip output name for walks and explicit files;
  path-like/whitespace values are rejected, and stdin cannot use `--ext`.
- **Server mode idles; it performs no startup decrypt.** `runServer`
  sets the health marker healthy (`marker.Set(true)`) and blocks on the
  signal context until SIGINT/SIGTERM, then cleans up on shutdown.
  There is no startup decrypt and no `startupHealthy` gate --
  the container's only job is to stay alive as a long-lived
  `docker exec age /age-decrypt decrypt --ext .env` target for the deploy.
  All decrypt work, and its loud deploy-blocking non-zero exit on failure,
  happens in the exec'd `decrypt` subcommand, never at server startup.
  Don't add a startup decrypt to `runServer` or make it exit non-zero on a
  decrypt outcome -- that would crash-loop it under `restart: unless-stopped`
  and remove the exec target precisely when a deploy needs it.
- **`loadIdentities` returns every identity, and `decryptFile` tries them
  all.** The key file is "one identity per line"; `loadIdentities` returns the
  full `[]age.Identity` and `decryptFile` forwards it to the variadic
  `age.Decrypt`. Returning only the first, or threading a single
  `age.Identity` through, silently breaks key rotation — a file encrypted to
  the second key would fail. Keep the slice end-to-end.
- **Decryption is repeatable, not in-place-idempotent.** Every pass reads the
  unchanged `.enc` source and atomically refreshes the plaintext sibling. A
  plaintext payload under a `.enc` name is a failure. Under `--ext`, a regular
  plaintext output is accepted; if its sibling source exists, that source's
  result gates the pass so stale ciphertext is repaired in one run.
- **Size caps are per file.** Encrypted input is capped at 10 MB,
  decrypted output at 1 MB, and the key file at 1 MB. There is no aggregate
  pass budget; deployment controls own tree size and invocation frequency.

## Local development

Build the binary:

```bash
go build -o age-decrypt .
```

Run the full test suite (unit, property-based, concurrency, fuzz seeds):

```bash
go test ./...
```

The property-based tests use `pgregory.net/rapid`. The concurrency tests
reproduce the parallel-deploy race directly, so keep them green.

Exercise a fuzz target (corpus runs as a normal test without `-fuzz`):

```bash
go test -run='^$' -fuzz=FuzzDecryptFile -fuzztime=30s
go test -run='^$' -fuzz=FuzzLoadIdentity -fuzztime=30s
```

Benchmarks:

```bash
go test -bench=BenchmarkDecryptFile -benchmem
```

Lint and format are enforced by golangci-lint v2 against
`.golangci.yaml` (standard preset plus the enabled linters, with
`gofumpt -extra-rules` and `gci` as formatters):

```bash
golangci-lint run
golangci-lint fmt
```

`golangci-lint run` flags unformatted files as issues, so `run` alone
catches formatting drift; `fmt` applies the fixes. Test files have several
linters relaxed via the `_test\.go` exclusion rules — don't be surprised
when production-only checks (`gosec`, `gocyclo`, etc.) don't fire there.

Build the image to verify the Dockerfile (`# check=error=true` makes
BuildKit warnings fatal):

```bash
docker build -t age-decrypt .
```

## Gotchas

- A pre-existing plaintext sibling is intentionally replaced, even if it is
  tracked by git. Ignore rules do not untrack files: migrations must remove
  secret outputs from the index or every decrypt will dirty the checkout.
- `# nosec G304` in `identity.go` is deliberate: the key path is
  operator-supplied, not untrusted input. Keep the explanation comment if
  you move the line — `nolintlint` requires it.
- Mutation testing config lives in `.gremlins.yaml` and excludes
  `main.go` (lifecycle/signal handling plus the health-marker filesystem
  ops that mutate without signal). That's expected, not a coverage gap to
  fix.
- CI (`.github/workflows/ci.yaml`) is synced from `cplieger/ci` — don't
  edit it locally; changes land upstream.
- Logs are UTC: the `slogx` library (its `UTCTime` `ReplaceAttr`) forces every record's
  timestamp to UTC, so the container needs no `TZ` and the binary embeds
  no `time/tzdata`.

## Commits & PRs

Conventional Commits, parsed by git-cliff (see `cliff.toml`) to build
release notes. Use `feat:` / `fix:` / `sec:`; `chore:`/`docs:`/`refactor:`
and friends don't trigger a release. Branch from `main`, keep changes
focused, and open a PR.

## Conduct & security

By participating you agree to the
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report vulnerabilities through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md),
never in a public issue.
