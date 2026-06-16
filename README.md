# docker-age

[![Image Size](https://ghcr-badge.egpl.dev/cplieger/docker-age/size)](https://github.com/cplieger/docker-age/pkgs/container/docker-age)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)
![base: distroless static](https://img.shields.io/badge/base-distroless%2Fstatic-2496ED?logo=docker)
[![Go Report Card](https://goreportcard.com/badge/github.com/cplieger/docker-age)](https://goreportcard.com/report/github.com/cplieger/docker-age)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/coverage.json)](https://github.com/cplieger/docker-age/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/mutation.json)](https://github.com/cplieger/docker-age/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13202/badge)](https://www.bestpractices.dev/projects/13202)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/docker-age/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/docker-age)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/docker-age/releases)

Decrypt [age](https://github.com/FiloSottile/age)-encrypted `.env` files at deploy time so your orchestrator can read them as plaintext.

## What it does

Walks a mounted directory tree, finds every `.env` file that's age-encrypted (binary or armored), and rewrites it in place with its decrypted plaintext. Files that aren't age-encrypted are left untouched. Designed to run as a `pre_deploy` step before `docker compose up` reads the `.env` files.

The `age-decrypt` binary is a single static Go executable on `gcr.io/distroless/static:nonroot`:

- `decrypt --ext .env` — decrypt every `.env` file in `AGE_REPO_ROOT` (the deploy use case)
- `decrypt /path` — decrypt a specific file or directory tree
- `decrypt -` — pipe: stdin ciphertext in, stdout plaintext out
- `health` — file-based health probe for Docker `HEALTHCHECK`

The `decrypt` subcommand always requires you to say **what** to decrypt (an extension filter, a path, or `-`). Server mode (no subcommand) is the always-on container entrypoint — it idles and serves as a `docker exec` target; it does not decrypt anything on its own.

### Why this design

- **In-place rewrites** — your compose file references `apps/<x>/.env` like usual; no separate plaintext path to track
- **Multi-identity** — the key file may hold several identities (one per line); a file encrypted to any one of them decrypts, so key rotation is just adding the new key alongside the old
- **Concurrency-safe** — multiple parallel invocations on the same tree won't collide. Tmp files are named with PID + a process-local atomic counter, and an orphan-tmp sweep with an age-bound threshold preserves in-flight peer writes
- **Atomic** — write-temp-then-rename so a failed decrypt never leaves a half-written `.env`
- **Symlink-safe** — uses `os.OpenRoot` to confine all I/O to the mounted tree (no escape via symlinks)
- **Distroless + nonroot** — minimal attack surface; no shell, no package manager, no extra binaries
- **Bounded memory** — encrypted files capped at 10 MB, decrypted output capped at 1 MB (defense against decompression bombs and runaway inputs); decrypted plaintext is zeroed from memory once written
- **File-based health marker** — works with Docker's no-shell distroless healthcheck (`HEALTHCHECK CMD ["/age-decrypt", "health"]`)

## Quick start

Available from both `ghcr.io/cplieger/docker-age` and `docker.io/cplieger/docker-age` — identical images and tags.

The expected workflow is encryption-at-rest in git, decryption at deploy:

1. Encrypt your `.env` files locally:

   ```bash
   age -a -R recipients.txt -o apps/myservice/.env apps/myservice/.env.dec
   ```

2. Commit `apps/myservice/.env` (encrypted, ASCII-armored) to git. `.env.dec` stays local.
3. On each server, run `age-decrypt` as an always-on decryptor. It does one
   decrypt pass at startup, then stays up so your deploy can trigger a fresh
   pass before the stack starts with `docker exec age /age-decrypt decrypt`:

```yaml
services:
  age:
    image: ghcr.io/cplieger/docker-age:latest
    container_name: age
    restart: unless-stopped  # always-on: stays up between deploys as an exec target

    environment:
      # Required: path to the age identity file (one identity per line).
      AGE_KEY_FILE: "/age/keys.txt"
      # AGE_REPO_ROOT defaults to /repo (the tree walked for *.env files). Set it
      # only to target a SUBDIRECTORY of /repo — see the note below on re-cloning
      # orchestrators. A tree (or folder of many repos) mounted at /repo is fine as-is.

    volumes:
      - "/path/to/age-keys:/age:ro"  # directory with the age identity (keys.txt, mode 0600)
      - "/path/to/repo:/repo"        # the tree to decrypt — or a folder containing many repos
```

Trigger a decrypt pass on demand (no restart needed):

```bash
docker exec age /age-decrypt decrypt
```

> **Re-cloning orchestrators (e.g. Komodo):** if your deploy tool replaces the
> repo directory on each sync (a new inode, not an in-place `git pull`), a
> container mounting that directory sees a stale mount. Mount the stable
> **parent** at `/repo` and set `AGE_REPO_ROOT=/repo/<repo-name>` so the walk
> re-resolves the child on every pass.

Or as a fire-and-forget one-shot before deploy (no long-running container):

```bash
docker run --rm \
  -e AGE_KEY_FILE=/age/keys.txt \
  -v $PWD/age-keys:/age:ro \
  -v $PWD/repo:/repo \
  ghcr.io/cplieger/docker-age:latest decrypt
```

## Configuration reference

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGE_KEY_FILE` | Absolute path to the age identity file (one identity per line; all are tried, so key rotation works) | _required_ (example: `/age/keys.txt`) |
| `AGE_REPO_ROOT` | Absolute path to the tree to walk for encrypted files (defaults to filtering `.env` in server mode; pass `--ext` to override) | `/repo` |

### Volumes

| Mount | Description |
|-------|-------------|
| `/age` | Directory containing your age identity (`keys.txt`, mode 0600). Mount read-only. |
| `/repo` | Repository tree containing `.env` files to decrypt in place. |

### Subcommands

```
/age-decrypt decrypt [--ext <suffix>]... [<path>...]
/age-decrypt decrypt -
/age-decrypt health
```

The `decrypt` subcommand requires **at least one** of: `--ext`, a target path, or `-`. Calling `decrypt` with no arguments is an error (nothing to do).

| Input | Behavior |
|-------|----------|
| `decrypt --ext .env` | Walk `AGE_REPO_ROOT`, decrypt only files ending in `.env` |
| `decrypt --ext .env --ext .yaml` | Walk `AGE_REPO_ROOT`, decrypt files ending in `.env` OR `.yaml` |
| `decrypt --ext .env /path/to/dir` | Walk the given directory (not `AGE_REPO_ROOT`), filter by `.env` |
| `decrypt /path/to/file.env` | Decrypt that one file in place (no extension filter — explicit target) |
| `decrypt /path/to/dir` | Walk that directory, decrypt **all** age-formatted files (no filter) |
| `decrypt -` | Pipe: read ciphertext from stdin, write plaintext to stdout |
| `decrypt` (bare, no args) | **Error** (exit 1) — you must specify what to decrypt |
| `health` | Read `/tmp/.healthy` marker — exit 0 if healthy, 1 if not |

**`--ext` behavior:** when provided, only files whose name ends with the suffix are candidates. When omitted with an explicit path target, all age-formatted files in the target are decrypted. The dot is auto-prefixed if missing (`--ext env` = `--ext .env`).

**Server mode** (no subcommand, the container's PID 1 entrypoint): starts up, marks itself healthy, and **idles**. No startup decrypt — all decryption is triggered explicitly via `docker exec age /age-decrypt decrypt --ext .env` (or any other `decrypt` invocation). The container stays alive as a long-lived exec target; the health marker is always healthy while the process is running. Use `restart: unless-stopped` in compose so it recovers from OOM/crashes.

## File-format detection

`.env` files are inspected by their first bytes:

- **Armored age** (`-----BEGIN AGE ENCRYPTED FILE-----`) — decrypted via `age/armor`
- **Binary age** (`age-encryption.org/v1`) — decrypted directly
- **Anything else** — treated as already-plaintext and skipped silently

This means you can mix encrypted and plaintext `.env` files in the same tree, and re-running `decrypt` is idempotent (a previously-decrypted file will be skipped on the next pass).

## Healthcheck

`age-decrypt health` reads `/tmp/.healthy`. The marker is written when the most recent `decrypt` run completed successfully, and removed (or left unset) if a run failed — in **server mode** the marker is set only when every file decrypted cleanly (any failure, including an unreadable repo root, reports unhealthy). Server mode never exits on a startup decrypt failure: it stays running and marks itself unhealthy, so it remains a valid `docker exec age /age-decrypt decrypt` target (exiting would crash-loop the container under `restart: unless-stopped`). The loud, deploy-blocking signal is the non-zero exit of the one-shot `decrypt` subcommand. The baked healthcheck targets the long-running server, so the always-on setup above uses it as-is. If you instead run a one-shot `decrypt` container (the `docker run --rm` form above), disable the healthcheck (`healthcheck: {disable: true}` in compose) since the one-shot exits without ever writing the marker. The standard distroless `HEALTHCHECK` uses CMD form (no shell needed):

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD ["/age-decrypt", "health"]
```

## File-permission requirements

- The age identity file (`keys.txt`) must be readable by the container user. The image runs as the distroless non-root user by default; keep the identity mode 0600 on the host and readable by that user.
- The container needs write access to the `.env` files it rewrites and the directories holding them (decryption is an atomic temp-then-rename). Run it as a user that owns the tree, or fix ownership on the mounts. If the tree has mixed or root ownership (for example an orchestrator that clones it as root), override with `user: "0:0"`.

## Security

| Tool | Result |
|------|--------|
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | No vulnerabilities |
| [golangci-lint](https://golangci-lint.run/) | Clean (`default: standard` preset incl. govet + staticcheck) |
| [hadolint](https://github.com/hadolint/hadolint) | Clean |
| [trivy](https://trivy.dev/) | 0 dependency CVEs (distroless base only) |
| [grype](https://github.com/anchore/grype) | 0 dependency CVEs (distroless base only) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | No secrets detected |
| [CodeQL](https://codeql.github.com/) | No findings |

The image is published with [cosign](https://github.com/sigstore/cosign) signatures and SBOM attestations.

The Go binary is built with `-trimpath` (strip absolute paths) and `-ldflags="-s -w"` (strip symbol tables and DWARF). All file I/O goes through `os.OpenRoot` to prevent symlink traversal out of the mounted tree.

## Dependencies

All dependencies are updated automatically via [Renovate](https://github.com/renovatebot/renovate) and pinned by digest or version for reproducibility.

| Dependency | Source |
|------------|--------|
| golang (builder) | [Docker Hub](https://hub.docker.com/_/golang) |
| distroless/static | [GoogleContainerTools](https://github.com/GoogleContainerTools/distroless) |
| filippo.io/age | [GitHub](https://github.com/FiloSottile/age) |

## Credits

This project packages [age](https://github.com/FiloSottile/age) (the encryption library by [@FiloSottile](https://github.com/FiloSottile)) into a deploy-time decryption tool. All credit for the core encryption work goes to the upstream maintainers.

## Contributing

Issues and pull requests are welcome. Please open an issue first for larger changes so the approach can be discussed before implementation.

## Disclaimer

This image is built with care and follows security best practices, but it is intended for **homelab use**. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude Opus](https://www.anthropic.com/claude) and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
