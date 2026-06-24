# Contributing to docker-age

Notes specific to this repo. For org-wide defaults (commit conventions,
PR workflow), the [`cplieger/.github`](https://github.com/cplieger/.github)
fallback applies; this file covers what's particular to the code here.

## What this is

A single static Go binary (`age-decrypt`) shipped on
`gcr.io/distroless/static:nonroot`. It walks a mounted tree,
decrypts every age-encrypted `.env` in place, and skips everything else.
The module path is `github.com/cplieger/age-decrypt/v2` even though the repo
and image are named `docker-age` — the binary name, not the repo name, is
the canonical identifier.

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
- `decrypt.go` — the core: `decryptAll` walks the tree and `decryptFile`
  handles one file.

## Load-bearing invariants

These are easy to break and the tests exist to catch them. Read this
before touching `decrypt.go`.

- **All tree I/O goes through the `*os.Root` handle.** `decryptAll` opens
  the tree with `os.OpenRoot` and every open/write/rename uses the `rootDir`
  handle: `rootDir.Open` (reads stream through a bounded `io.LimitReader`,
  not a `Stat`+`ReadFile`, which also enforces the size cap on bytes actually
  read), `rootDir.WriteFile`, `rootDir.Rename`. This confines I/O to the
  mounted tree and blocks symlink escapes. Do not reach for the bare `os`
  package for paths inside the tree.
- **Temp file names must stay unique per call and carry the marker.**
  `decryptFile` names its temp file `<rel>.<pid>.<counter>.age-decrypt-tmp`
  (the `tmpSuffix` marker) using the PID plus a process-local atomic counter
  (`tmpCounter`). The PID+counter keep concurrent peers from colliding (a
  shared name reintroduces the production rename-vs-sweep race); the
  `tmpSuffix` marker is how the orphan sweep recognizes the tool's own temps
  for any extension without ever matching a user's file. Keep both.
- **`decryptFile` is tri-state, and skips are not failures.** It returns
  `fileSkipped` (not age-formatted — legitimate, logged at debug),
  `fileDecrypted`, or `fileFailed`. In **decrypt mode** (`runDecrypt`,
  the `decrypt` subcommand) the process exits non-zero when
  `result.Failed > 0` **or** when the repo root itself is unreadable: a
  root-level `WalkDir` error (e.g. a stale mount, `readdirent /repo: no such
file or directory`) is fatal, so a stale `/repo` fails loudly instead of
  reporting a clean `decrypted=0` / exit 0. Per-subdirectory walk errors stay
  non-fatal (logged, the walk continues). A tree of plaintext files (no age headers) —
  or a legitimately empty tree — is still a clean run.
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
- **Decryption is idempotent.** Format is detected by the first bytes
  (armored `-----BEGIN AGE ENCRYPTED FILE-----` vs binary
  `age-encryption.org/v1`); a previously-decrypted file is plaintext and
  gets skipped on the next pass.
- **Size caps are intentional.** Encrypted input is capped at 10 MB and
  decrypted output at 1 MB (decompression-bomb guard). The key file is
  capped at 1 MB. Don't loosen these without a reason.
- **The orphan-tmp sweep is age-bound.** `sweepOrphanTmpFile` only removes
  temp files older than the 10-minute `staleThreshold`, so it never rips a
  temp out from under a concurrent peer mid-decrypt.

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

- `# nosec G304` in `identity.go` is deliberate: the key path is
  operator-supplied, not untrusted input. Keep the explanation comment if
  you move the line — `nolintlint` requires it.
- Mutation testing config lives in `.gremlins.yaml` and excludes
  `main.go` (lifecycle/signal handling plus the health-marker filesystem
  ops that mutate without signal). That's expected, not a coverage gap to
  fix.
- CI (`.github/workflows/ci.yaml`) is synced from `cplieger/ci` — don't
  edit it locally; changes land upstream.

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
