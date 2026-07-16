# docker-age

[![Image Size](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/size.json)](https://github.com/cplieger/docker-age/pkgs/container/docker-age)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)
![base: distroless static](https://img.shields.io/badge/base-distroless%2Fstatic-2496ED?logo=docker)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/coverage.json)](https://github.com/cplieger/docker-age/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/mutation.json)](https://github.com/cplieger/docker-age/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13202/badge)](https://www.bestpractices.dev/projects/13202)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/docker-age/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/docker-age)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/docker-age/releases)

Decrypt [age](https://github.com/FiloSottile/age)-encrypted `.enc` files to their plaintext siblings at deploy time so your orchestrator can read them — `.env` files, any other config, or a single file piped through stdin/stdout. Ciphertext stays tracked in git; plaintext is generated next to it and never committed.

## What it does

Walks a mounted directory tree (or a single `.enc` file you name), finds every `<name>.enc` ciphertext source (binary or armored age format), and atomically writes its decrypted plaintext to the sibling `<name>` — `apps/x/.env.enc` becomes `apps/x/.env`. The source is never modified, so your working tree stays clean: `git pull` always applies rotated secrets, and the generated plaintext is just re-derived on the next pass. An `--ext` filter narrows a walk by the OUTPUT suffix (`--ext .env` selects `.env.enc` sources); a `-` target switches to a stdin→stdout pipe for a single file. Designed to run as a `pre_deploy` step before `docker compose up` reads the files.

The `age-decrypt` binary is a single static Go executable on `gcr.io/distroless/static:nonroot`:

- `decrypt --ext .env` — decrypt every `.env.enc` in `AGE_REPO_ROOT` to its `.env` sibling (the deploy use case)
- `decrypt /path` — decrypt a specific `.enc` file or every `.enc` source under a directory tree
- `decrypt -` — pipe: stdin ciphertext in, stdout plaintext out
- `health` — file-based health probe for Docker `HEALTHCHECK`

The `decrypt` subcommand always requires you to say **what** to decrypt (an extension filter, a path, or `-`). Server mode (no subcommand) is the always-on container entrypoint that idles as a `docker exec` target (see the Server mode note under [Subcommands](#subcommands) for details).

### Why this design

- **Ciphertext and plaintext are separate planes** — `<name>.enc` is tracked in git and never touched; `<name>` is generated and gitignored. Your compose file references `apps/<x>/.env` like usual, `git status` stays meaningful on live checkouts, and a `git pull` can never conflict with a decrypted secret (the failure mode of in-place rewriting, which v2 used)
- **Fail-closed** — a `.enc` source that will not decrypt, an unreadable subtree, or stray age ciphertext sitting at a plaintext path (an un-migrated secret) all exit non-zero and block the deploy; ciphertext can never be silently consumed as config
- **Multi-identity** — the key file may hold several identities (one per line); a file encrypted to any one of them decrypts, so key rotation is just adding the new key alongside the old
- **Concurrency-safe** — multiple parallel invocations on the same stable tree won't collide. Each plaintext temp has a cryptographically random 128-bit name and is created with `O_EXCL`; an age-bound orphan sweep preserves in-flight peer writes
- **Atomic** — write-temp-then-rename so a failed decrypt never leaves a half-written `.env`, and a source can never be corrupted (it is opened read-only)
- **Scoped source reads** — a source must remain the same regular, single-link inode across rooted `Lstat`/open/`Lstat` checks, rejecting symlinks, hardlinks, FIFOs, devices, and directories; `os.OpenRoot` confines pathname resolution to the mounted tree. Rename never follows an output symlink, and under `--ext` any matching nonregular plaintext path fails the pass
- **Distroless + nonroot** — minimal attack surface; no shell, no package manager, no extra binaries
- **Per-file bounds** — each encrypted input is capped at 10 MB and each decrypted output at 1 MB (defense against decompression bombs and runaway files); plaintext is zeroed from memory once written and published mode 0600
- **File-based health marker** — works with Docker's no-shell distroless healthcheck (`HEALTHCHECK CMD ["/age-decrypt", "health"]`)

## Quick start

Available from both `ghcr.io/cplieger/docker-age` and `docker.io/cplieger/docker-age` — identical images and tags.

The expected workflow is encryption-at-rest in git, decryption at deploy:

1. Encrypt your `.env` files locally:

   ```bash
   age -a -R recipients.txt -o apps/myservice/.env.enc apps/myservice/.env
   ```

2. Commit `apps/myservice/.env.enc` (encrypted, ASCII-armored) and gitignore
   the plaintext (`echo 'apps/*/.env' >> .gitignore` or equivalent). The
   `.env` you edit locally is exactly the file your apps read after decrypt.
3. On each server, run `age-decrypt` as an always-on container (see the Server
   mode note below). Your deploy triggers a fresh pass before the stack starts
   with `docker exec age /age-decrypt decrypt --ext .env`:

```yaml
services:
  age:
    image: ghcr.io/cplieger/docker-age:latest
    container_name: age
    restart: unless-stopped  # always-on: stays up between deploys as an exec target

    environment:
      # Required: path to the age identity file (one identity per line).
      AGE_KEY_FILE: "/age/keys.txt"
      # AGE_REPO_ROOT defaults to /repo (the tree `decrypt` walks when no path is
      # given). Set it only to target a SUBDIRECTORY of /repo — see the note below
      # on re-cloning orchestrators. A tree (or folder of many repos) mounted at
      # /repo is fine as-is.

    volumes:
      - "/path/to/age-keys:/age:ro"  # directory with the age identity (keys.txt, mode 0600)
      - "/path/to/repo:/repo"        # the tree to decrypt — or a folder containing many repos
```

Trigger a decrypt pass on demand (no restart needed):

```bash
docker exec age /age-decrypt decrypt --ext .env
```

> **Re-cloning orchestrators:** if your deploy tool replaces the repo directory
> (a new inode) on each sync, a container mounting that directory sees a stale
> mount. Mount the stable **parent** at `/repo` and set
> `AGE_REPO_ROOT=/repo/<repo-name>` so the walk re-resolves the child on every
> pass.

Or as a fire-and-forget one-shot before deploy (no long-running container):

```bash
docker run --rm \
  -e AGE_KEY_FILE=/age/keys.txt \
  -v $PWD/age-keys:/age:ro \
  -v $PWD/repo:/repo \
  ghcr.io/cplieger/docker-age:latest decrypt --ext .env
```

## Configuration reference

### Environment variables

| Variable        | Description                                                                                          | Default                               |
| --------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `AGE_KEY_FILE`  | Absolute path to the age identity file (one identity per line; all are tried, so key rotation works) | _required_ (example: `/age/keys.txt`) |
| `AGE_REPO_ROOT` | Absolute path to the tree `decrypt` walks when no target path is given                               | `/repo`                               |
| `AGE_LOG_LEVEL` | Log level: `debug`/`info`/`warn`/`error` (case-insensitive); `debug` shows per-file skip reasons     | `info`                                |

### Volumes

| Mount   | Description                                                                      |
| ------- | -------------------------------------------------------------------------------- |
| `/age`  | Directory containing your age identity (`keys.txt`, mode 0600). Mount read-only. |
| `/repo` | Repository tree containing the `.enc` sources; plaintext siblings are generated in it. |

### Subcommands

```
/age-decrypt decrypt [--ext <suffix>]... [<path>...]
/age-decrypt decrypt -
/age-decrypt health
```

The `decrypt` subcommand requires **at least one** of: `--ext`, a target path, or `-`. Calling `decrypt` with no arguments is an error (nothing to do).

| Input                             | Behavior                                                                        |
| --------------------------------- | ------------------------------------------------------------------------------- |
| `decrypt --ext .env`              | Walk `AGE_REPO_ROOT`, decrypt every `*.env.enc` to its `.env` sibling           |
| `decrypt --ext .env --ext .yaml`  | Walk `AGE_REPO_ROOT`, decrypt `*.env.enc` OR `*.yaml.enc` sources               |
| `decrypt --ext .env /path/to/dir` | Walk the given directory (not `AGE_REPO_ROOT`), same filter                     |
| `decrypt /path/to/file.env.enc`   | Decrypt that one source to `/path/to/file.env` (explicit target must be `.enc`) |
| `decrypt /path/to/dir`            | Walk that directory, decrypt **all** `.enc` sources (no filter)                 |
| `decrypt -`                       | Pipe: read ciphertext from stdin, write plaintext to stdout                     |
| `decrypt` (bare, no args)         | **Error** (exit 1) — you must specify what to decrypt                           |
| `health`                          | Read `/tmp/.healthy` marker — exit 0 if healthy, 1 if not                       |

**`--ext` behavior:** the filter names the decrypted OUTPUT suffix — `--ext .env` selects `.env.enc` sources and produces `.env` files. The dot is auto-prefixed if missing (`--ext env` = `--ext .env`); values ending in `.enc`, containing `/` or `\\`, or carrying surrounding whitespace are rejected instead of becoming silent no-op filters. The same post-strip filter applies to an explicit file target: `decrypt --ext .env config.yaml.enc` skips that source because its output is `config.yaml`. `--ext` cannot be combined with stdin (`decrypt -`) because a byte stream has no output filename to filter. Under `--ext`, non-`.enc` paths matching the suffix are also checked: regular plaintext there is the expected steady state (a generated output from a previous pass, or a committed plaintext config) and is skipped, while **age ciphertext or a nonregular path at the plaintext name fails the pass**. Without `--ext`, only `.enc` files are considered and everything else is out of scope (a deliberately encrypted archive kept at rest never trips the guard).

**Server mode** (no subcommand, the container's PID 1 entrypoint): starts up, marks itself healthy, and **idles**. No startup decrypt — all decryption is triggered explicitly via `docker exec age /age-decrypt decrypt --ext .env` (or any other `decrypt` invocation). The container stays alive as a long-lived exec target; the health marker is always healthy while the process is running. Use `restart: unless-stopped` in compose so it recovers from OOM/crashes.

## File-format detection

Each `.enc` source is inspected by its first bytes:

- **Armored age** (`-----BEGIN AGE ENCRYPTED FILE-----`) — decrypted via `age/armor`
- **Binary age** (`age-encryption.org/v1`) — decrypted directly
- **Anything else** — a **failure** (exit non-zero): a `.enc` file that is not age ciphertext means a broken encrypt workflow, and silently passing it through would hide that

Mixing encrypted and plaintext files in the same tree is fine: plaintext lives at the plain name, ciphertext at the `.enc` name. Re-running `decrypt` is idempotent in outcome — every pass re-derives the same plaintext siblings from the same sources (a rotated `.enc` simply produces the new plaintext on the next pass).

Two source names are rejected up front, before any decryption: a bare `.enc` (no output name) and a double-suffixed `<x>.enc.enc` (its output would itself look like a ciphertext source and poison the next pass).

## Migrating from v2 (in-place model)

v2 rewrote ciphertext files in place (`apps/x/.env` was tracked ciphertext that became plaintext on the server). v3 flips the layout: ciphertext moves to `apps/x/.env.enc` and the plaintext `.env` is generated. To migrate a repo:

1. Rename every tracked ciphertext file: `git mv apps/x/.env apps/x/.env.enc` (repeat per file; plaintext configs that were never encrypted stay put).
2. Gitignore the generated plaintext paths (for example `apps/*/.env`). If an output path is still tracked, v3 deliberately overwrites it with the decrypted bytes and leaves the checkout dirty; remove migrated secret outputs from the index rather than relying on the ignore rule alone.
3. Remove any deploy script that restores or resets the old tracked plaintext path (for example `git restore -- 'apps/*/.env'`). After the rename there is nothing tracked at that path, and under `set -e` such a command can abort before pull/decrypt.
4. Deploy the v3 image **before** the renamed tree reaches the servers (an old v2 binary finds no `.env` ciphertext after the rename and decrypts nothing; a v3 binary on a pre-rename tree fails loudly on the stray ciphertext under `--ext`).
5. Keep the trigger command unchanged: `--ext .env` selects `.env.enc` sources in v3.

The stray-ciphertext guard is the migration net: after step 3, any secret you forgot to rename fails the deploy with a `stray age ciphertext` error naming the file, instead of letting an app read ciphertext.

## Healthcheck

`age-decrypt health` reads `/tmp/.healthy`. In **server mode** the marker is set healthy the moment the container starts and stays healthy for as long as the process is alive; it is removed on shutdown. So the marker reflects process **liveness** — it lets Docker detect and restart a crashed server — **not** decrypt outcome. A `decrypt` invocation does not touch the marker; its success or failure is reported by its **exit code** (non-zero on any failure, including an unreadable repo root). That non-zero exit is the loud, deploy-blocking signal — wire your `pre_deploy` step to fail on it. The baked healthcheck targets the long-running server, so the always-on setup above uses it as-is. If you instead run a one-shot `decrypt` container (the `docker run --rm` form above), disable the healthcheck (`healthcheck: {disable: true}` in compose) since the one-shot exits without ever running the server that writes the marker. The standard distroless `HEALTHCHECK` uses CMD form (no shell needed):

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD ["/age-decrypt", "health"]
```

## File-permission requirements

- The age identity file (`keys.txt`) must be readable by the container user. The image runs as the distroless non-root user by default; keep the identity mode 0600 on the host and readable by that user.
- The container needs read access to the `.enc` sources and write access to the directories holding them (the plaintext sibling is created via an atomic temp-then-rename in the same directory). Generated plaintext is written mode 0600, owned by the container user. Run it as a user that owns the tree, or fix ownership on the mounts. If the tree has mixed or root ownership (for example an orchestrator that clones it as root), override with `user: "0:0"`.

## Filesystem stability and temp namespace

A decrypt pass supports other `age-decrypt` processes operating concurrently on the same **stable checkout**. It does not turn a repository that an untrusted process can actively rename, hardlink, or replace during the pass into a transactional snapshot; do not grant untrusted writers access to the mounted tree while decryption runs. Sources must be regular, single-link inodes, and random exclusive temp creation plus inode, mode, and link-count checks make static source hardlinks, pre-seeded temp paths, and ordinary races fail closed. As with any path-scoped API, these checks cannot prove the historical provenance of copied or renamed file contents.

The final path pattern `<output>.<32-lowercase-hex-chars>.age-decrypt-tmp` is reserved for v3 plaintext temps. The orphan sweep also recognizes the exact legacy `<output>.<pid>.<counter>.age-decrypt-tmp` form so upgrades can reclaim interrupted writes. It only touches stale regular files that are mode 0600 with one link; do not create application files in this namespace.

The 10 MB ciphertext and 1 MB plaintext limits are **per file**. A pass intentionally has no aggregate file-count, total-byte, or wall-clock budget, so operators should bound repository size and invocation frequency at the deployment layer.

## Security

| Tool                                                                | Result                                                       |
| ------------------------------------------------------------------- | ------------------------------------------------------------ |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | No vulnerabilities                                           |
| [golangci-lint](https://golangci-lint.run/)                         | Clean (`default: standard` preset incl. govet + staticcheck) |
| [hadolint](https://github.com/hadolint/hadolint)                    | Clean                                                        |
| [trivy](https://trivy.dev/)                                         | 0 dependency CVEs (distroless base only)                     |
| [grype](https://github.com/anchore/grype)                           | 0 dependency CVEs (distroless base only)                     |
| [gitleaks](https://github.com/gitleaks/gitleaks)                    | No secrets detected                                          |
| [CodeQL](https://codeql.github.com/)                                | No findings                                                  |

The image is published with [cosign](https://github.com/sigstore/cosign) signatures and SBOM attestations.

The Go binary is built with `-trimpath` (strip absolute paths) and `-ldflags="-s -w"` (strip symbol tables and DWARF). Tree I/O goes through `os.OpenRoot` for pathname confinement; source descriptors additionally require matching rooted snapshots, regular-file type, and link count one so a symlink or same-filesystem hardlink cannot import an out-of-scope ciphertext inode.

## Dependencies

All dependencies are updated automatically via [Renovate](https://github.com/renovatebot/renovate) and pinned by digest or version for reproducibility.

| Dependency        | Source                                                                     |
| ----------------- | -------------------------------------------------------------------------- |
| golang (builder)  | [Docker Hub](https://hub.docker.com/_/golang)                              |
| distroless/static | [GoogleContainerTools](https://github.com/GoogleContainerTools/distroless) |
| filippo.io/age    | [GitHub](https://github.com/FiloSottile/age)                               |

## Credits

This project packages [age](https://github.com/FiloSottile/age) (the encryption library by [@FiloSottile](https://github.com/FiloSottile)) into a deploy-time decryption tool. All credit for the core encryption work goes to the upstream maintainers.

## Contributing

Issues and pull requests are welcome. Please open an issue first for larger changes so the approach can be discussed before implementation.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude Opus](https://www.anthropic.com/claude) and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
