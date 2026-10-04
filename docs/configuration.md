# Configuration

This page lists every `decrypt` command and the rules `--ext` follows, and shows how to run docker-age once, as another user, or against a checkout your deploy tool re-clones. It is for readers setting up the deploy step.

## Settings

The three settings are in the README's [configuration reference](../README.md#configuration-reference). `IDENTITY_PATH` is read when the container starts, and the container exits with `invalid configuration` when it is unset. The identity file itself is read only when a `decrypt` command runs, so a missing or unreadable `keys.txt` shows up then, as `failed to load identities`.

The identity file holds age identities made by `age-keygen`, one per line, and lines starting with `#` are ignored. SSH keys and a passphrase-protected identity file are not read. The `failed to load identities` line names the cause:

- `permission denied`: the container's user cannot read the file.
- `key file too large`: the file is over 1 MB.
- `malformed identity`: a line is not an age identity. The line is not shown, because it may hold a key.
- `no identities found`: the file holds no identity.

`LOG_LEVEL` ignores case. An unknown value logs `invalid LOG_LEVEL, using default` and uses `info`. Logs go to standard error with UTC times, so `decrypt -` keeps standard output for the plaintext alone.

## Commands

Run each one with `docker exec age /age-decrypt <command>`. A `decrypt` command exits 0 when every file it selected decrypted and 1 on any failure. It exits 2 when an argument or a setting is invalid, such as an unknown flag or an unset `IDENTITY_PATH`.

| Command | What it does |
| --- | --- |
| `decrypt --ext .env` | Searches `REPO_ROOT` and decrypts every `*.env.enc` file to the `.env` beside it |
| `decrypt --ext .env --ext .yaml` | Searches `REPO_ROOT` for `*.env.enc` and `*.yaml.enc` files |
| `decrypt --ext .env /path/to/dir` | Searches that folder instead of `REPO_ROOT`, with the same filter |
| `decrypt /path/to/file.env.enc` | Decrypts that one file to `/path/to/file.env`. A file you name must end in `.enc` |
| `decrypt /path/to/dir` | Searches that folder and decrypts every `.enc` file in it, with no filter |
| `decrypt -` | Reads encrypted text from standard input and writes the plaintext to standard output |
| `decrypt` | Exits 1, because it names nothing to decrypt |
| `health` | Checks the file at `/tmp/.healthy`. Exits 0 when it is there and 1 when it is not |

You can name several paths in one command. Arguments after `--` are read as paths even when they start with `-`. `-` cannot be combined with other paths.

## How --ext selects files

- The value names the decrypted file's suffix. `--ext .env` selects `.env.enc` files and writes `.env` files.
- The leading dot is optional, so `--ext env` means `--ext .env`. `--ext=.env` works too.
- A value that ends in `.enc`, contains `/` or `\`, or starts or ends with a space is refused. Each of these would otherwise match nothing.
- The filter also applies to a file you name. `decrypt --ext .env config.yaml.enc` skips that file, because it would write `config.yaml`.
- `--ext` cannot be used with `decrypt -`, because standard input has no file name to filter.
- With `--ext`, files that already carry the plain name are checked too. A plain file there is the normal result of an earlier pass, or a setting you committed unencrypted, and it is skipped. Encrypted text, a link or any other special file at that name fails the pass.
- Without `--ext`, only `.enc` files are read and every other file is left alone. An encrypted archive you keep under its own name never fails a pass.

## Running once

You can run a pass in a container that exits when it is done, with no container waiting between deploys:

```bash
docker run --rm \
  -e IDENTITY_PATH=/age/keys.txt \
  -v "$PWD/age-keys:/age:ro" \
  -v "$PWD/repo:/repo" \
  ghcr.io/cplieger/docker-age:latest decrypt --ext .env
```

In a compose file, give the service `command: ["decrypt", "--ext", ".env"]` and `healthcheck: {disable: true}`, and leave out `restart:` so the container stays stopped after the pass. The image's healthcheck is for the waiting container, and a one-time pass never writes the file it checks.

## Running as another user

The container runs as UID 65532 by default, and it must be able to read `keys.txt` and write to every folder that holds a `.enc` file. When your checkout belongs to your own user, run the container as that user instead. Add this line under `age:` in `compose.yaml`, then give `keys.txt` to the same user:

```yaml
    user: "${PUID:-1000}:${PGID:-1000}"
```

It runs as UID and GID 1000 unless `.env` sets `PUID` and `PGID`. When the checkout's folders belong to several users, or to root, set `user: "0:0"` so the container runs as root.

## A checkout your deploy tool re-clones

Some deploy tools delete the checkout folder and clone it again on each sync. The new folder is a different folder on disk, and a container that mounted the old one keeps seeing it, now deleted. The next pass fails with `repo root unreadable` and stops the deploy. Restarting the container mounts the new folder, and so does this setup:

1. Mount the folder that holds the checkout, which the tool never deletes, at `/repo`. For example, use `"/path/to/repos:/repo"`.
2. Set `REPO_ROOT` to the checkout inside it, such as `REPO_ROOT: "/repo/my-repo"`.

docker-age then looks up the checkout again on every pass.

## Limits

Each encrypted file may be 10 MB at most, each decrypted file 1 MB and the identity file 1 MB. A larger encrypted or decrypted file fails the pass. These limits are per file. A pass has no limit on the number of files, their total size or its running time, so keep the checkout and how often you run a pass to what your server can handle.
