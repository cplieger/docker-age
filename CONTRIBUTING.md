# Contributing to docker-age

Notes specific to this repo. For org-wide defaults (commit conventions,
PR workflow), the [`cplieger/.github`](https://github.com/cplieger/.github)
fallback applies; this file covers what's particular to the code here.

## What this is

A single static Go binary (`age-decrypt`) shipped on
`gcr.io/distroless/static-debian13:nonroot`. It walks a mounted tree,
decrypts every age-encrypted `.env` in place, and skips everything else.
The module path is `github.com/cplieger/age-decrypt` even though the repo
and image are named `docker-age` — the binary name, not the repo name, is
the canonical identifier.

## Layout

Flat `package main`, one concern per file:

- `main.go` — entry point and the two run modes (`runSubcommand`,
  `runServer`). The `health` probe is intercepted here *before*
  `parseConfig` runs, because the probe must work without `AGE_KEY_FILE`
  set.
- `config.go` — env-var parsing (`AGE_KEY_FILE`, `AGE_REPO_ROOT`) and mode
  selection from `os.Args[1]` (`decrypt` → subcommand, `health` → probe,
  empty → server).
- `identity.go` — loads the age identity, returning the `age.Identity`
  interface (not a concrete key type) so future key kinds don't churn
  callers. Caps the key file at 1 MB.
- `decrypt.go` — the core: `decryptAll` walks the tree and `decryptFile`
  handles one file.
- `health.go` — file-based health marker, delegating to
  `github.com/cplieger/health`.

## Load-bearing invariants

These are easy to break and the tests exist to catch them. Read this
before touching `decrypt.go`.

- **All tree I/O goes through the `*os.Root` handle.** `decryptAll` opens
  the tree with `os.OpenRoot` and every read/write/rename uses
  `rootDir.ReadFile` / `rootDir.WriteFile` / `rootDir.Rename`. This
  confines I/O to the mounted tree and blocks symlink escapes. Do not
  reach for the bare `os` package for paths inside the tree.
- **Temp file names must stay unique per call.** `decryptFile` names its
  temp file `<rel>.tmp.<pid>.<counter>` using the PID plus a process-local
  atomic counter (`tmpCounter`). A shared name like `.env.tmp` reintroduces
  the production race where one invocation's rename collides with another's
  orphan sweep. Keep the per-call uniqueness.
- **`decryptFile` is tri-state, and skips are not failures.** It returns
  `fileSkipped` (not age-formatted — legitimate, logged at debug),
  `fileDecrypted`, or `fileFailed`. The process exits non-zero only when
  `result.Failed > 0`. A tree of plaintext `.env` files is a clean run.
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
  `main.go` and `health.go` (lifecycle and marker filesystem ops that
  mutate without signal). That's expected, not a coverage gap to fix.
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
