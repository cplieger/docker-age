# docker-age

[![Image Size](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/size.json)](https://github.com/cplieger/docker-age/pkgs/container/docker-age) [![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-blue)](https://github.com/cplieger/docker-age/pkgs/container/docker-age) [![base: distroless static](https://img.shields.io/badge/base-distroless%2Fstatic-2496ED?logo=docker)](https://github.com/cplieger/docker-age/blob/main/Dockerfile) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/docker-age/badges/mutation.json)](https://github.com/cplieger/docker-age/issues?q=label%3Agremlins-tracker) [![SBOM](https://img.shields.io/badge/SBOM-SPDX-1D4ED8)](https://github.com/cplieger/docker-age/releases)

<!-- hub-overview BEGIN -->
docker-age decrypts the [age](https://github.com/FiloSottile/age)-encrypted `.env` files in a git checkout on your server, right before your Docker Compose stacks start. Your secrets stay encrypted in git. It does not encrypt files or start your stacks.

## What it does

docker-age lets you commit every secret encrypted and still start each stack with a plain `.env` file:

- Writes `apps/x/.env` next to each `apps/x/.env.enc` and never changes the encrypted file, so `git pull` stays clean.
- Fails when a file will not decrypt or encrypted text sits at a plain file's name, so your deploy can stop.
- Tries every key in your identity file, so you rotate a key by adding the new one beside the old.
- Also decrypts any other file named `<name>.enc`, or one file you pipe through it.

## Who it is for

docker-age is built for Docker Compose stacks deployed from a git checkout, with each secret committed as an age-encrypted file. You need the age command-line tool to encrypt your files and an identity file from `age-keygen` on each server. Your deploy step must run `docker exec` before your stacks start.

Two other projects suit a different setup:

- Consider [SOPS](https://github.com/getsops/sops) if you want an editor for encrypted YAML, JSON, ENV and INI files. It can use keys from AWS KMS, GCP KMS, Azure Key Vault, age or PGP.
- Consider [git-crypt](https://github.com/AGWA/git-crypt) if you want files decrypted whenever the repository is checked out, with keys shared through GPG.

docker-age is free software under the Apache-2.0 license.
<!-- hub-overview END -->

## Quick start

The image is on GitHub Container Registry and Docker Hub, for `amd64` and `arm64`. This is the [`compose.yaml`](compose.yaml) in this repository. The container stays running between deploys, and your deploy step runs one `docker exec` command against it to decrypt. [Configuration](docs/configuration.md#running-once) also has a one-time `docker run` form.

```yaml
services:
  age:
    image: ghcr.io/cplieger/docker-age:latest
    container_name: age
    # Before each "docker compose up", your deploy step runs
    # "docker exec age /age-decrypt decrypt --ext .env" to write the .env files.
    restart: unless-stopped  # stays up between deploys so the deploy step can reach it

    environment:
      IDENTITY_PATH: "/age/keys.txt"  # required, your age identity file

    volumes:
      # Put your age identity in keys.txt, then run "sudo chown 65532:65532 keys.txt"
      # and "sudo chmod 600 keys.txt" before the first decrypt.
      - "/path/to/age-keys:/age:ro"
      # Your checkout with the .env.enc files. For each folder that holds one, run
      # "sudo chgrp 65532 <folder>" and "sudo chmod g+w <folder>" before the first decrypt.
      - "/path/to/repo:/repo"
```

1. On your computer, encrypt each `.env` file to your age recipients with `age -a -R recipients.txt -o apps/myservice/.env.enc apps/myservice/.env`.
2. Keep the plain files out of git with `echo 'apps/*/.env' >> .gitignore`.
3. If git already tracks a plain `.env`, run `git rm --cached apps/myservice/.env`. Otherwise git would show your decrypted secret as a change you could commit.
4. Commit the `.env.enc` files and `.gitignore`.
5. On the server, put your age identity in `/path/to/age-keys/keys.txt`, then run `sudo chown 65532:65532 keys.txt` and `sudo chmod 600 keys.txt` in that folder.
6. For each folder in your checkout that holds a `.env.enc` file, run `sudo chgrp 65532 apps/myservice` and `sudo chmod g+w apps/myservice`. To run the container as the checkout's owner instead, see [Configuration](docs/configuration.md#running-as-another-user).
7. Run `docker compose up -d`.
8. Add `docker exec age /age-decrypt decrypt --ext .env` to your deploy step, before `docker compose up` runs. Make the deploy stop when that command fails.

Run that command once by hand. You should see `decryption complete` with a `decrypted=` count above 0. If you see `failed to load identities` with `permission denied`, the container's user cannot read `keys.txt`, so repeat step 5. With any other error in that line, fix `keys.txt` itself, which must hold one age identity per line and be 1 MB at most.

## Configuration reference

Settings are environment variables. Recreate the container after you change one.

| Variable | Description | Default |
| --- | --- | --- |
| `IDENTITY_PATH` | Path inside the container to your age identity file from `age-keygen`. Every identity in it is tried, one per line | required |
| `REPO_ROOT` | Folder that `decrypt --ext` searches when you name no path | `/repo` |
| `LOG_LEVEL` | `debug`, `info`, `warn` or `error`. `debug` shows why each file was skipped | `info` |

| Mount | Description |
| --- | --- |
| `/age` | The folder that holds your identity file. Mount it read-only |
| `/repo` | Your checkout. Each `.env` is written next to its `.env.enc` here |

The image opens no ports. The container runs these commands through `docker exec age /age-decrypt <command>`:

| Command | What it does |
| --- | --- |
| `decrypt --ext .env` | Decrypts every `.env.enc` file under `REPO_ROOT` to the `.env` beside it |
| `decrypt <path>` | Decrypts that `.enc` file, or every `.enc` file in that folder |
| `decrypt -` | Decrypts one file from standard input to standard output |
| `health` | Runs the healthcheck |

`decrypt` with nothing to decrypt is an error. Each encrypted file may be 10 MB at most and each decrypted file 1 MB, and a larger file fails the pass. [Configuration](docs/configuration.md) has every command, the `--ext` rules and a one-time `docker run` form.

## Security

The image opens no ports and runs as UID 65532 on a distroless base with no shell. Each decrypted file is written with mode 0600 and appears complete or not at all. A `.enc` file that is not age-encrypted, encrypted text at a plain file's name, and a link or other special file in place of a source all fail the pass. Lookups stay inside the folder you name, so a link cannot pull in a file from outside it.

docker-age runs several of its own passes at once safely. Make sure no other program renames or replaces files in the checkout while a pass runs, because docker-age does not defend against that. Deleting a `.env.enc` file leaves its `.env` on disk, so delete that file yourself when you retire a secret. [Security](docs/hardening.md) has a hardened compose example and what the image contains.

## Troubleshooting

The healthcheck shows only whether the waiting container is up and ready for `docker exec`. A failed decrypt leaves it healthy. The `docker exec` command reports a failure with a non-zero exit code instead, and that is what your deploy step must check.

- `repo root unreadable` after your deploy tool syncs the repository. The tool replaced the checkout folder, so the container still sees the old one. Mount the parent folder at `/repo` and set `REPO_ROOT=/repo/<repo-name>`.
- `stray age ciphertext at a plaintext path`. A file you encrypted still has its plain name. Rename it to `<name>.enc`.
- `temp create error` with `permission denied`. The container's user cannot write to that folder. Repeat step 6 of the quick start.
- `no matching files found under repo root`. Nothing matched. Check `REPO_ROOT`, the `/repo` mount and the `--ext` value.

## Documentation

- [Configuration](docs/configuration.md) has the identity file format, every command, the `--ext` rules, running once and running as another user.
- [How docker-age works](docs/how-it-works.md) explains a decrypt pass, how files are written and the waiting container.
- [Security](docs/hardening.md) has what docker-age refuses, the hardened compose example and what the image contains.

## Credits

docker-age decrypts with the [age](https://github.com/FiloSottile/age) Go library by [@FiloSottile](https://github.com/FiloSottile). All credit for the encryption goes to the age maintainers.

## Contributing

Issues and pull requests are welcome. Please open an issue first for larger changes, and see [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).

The image carries the license text of every bundled component under `/usr/share/licenses/`, including the BSD-3-Clause text of the [age](https://github.com/FiloSottile/age) library it links.
