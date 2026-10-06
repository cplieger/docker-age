# Security

This page covers what docker-age refuses, what it leaves to you, a hardened compose example, and what the image contains. It is for readers who want to lock the container down further than the quick start does.

## What docker-age refuses

docker-age fails closed. Each of these fails the pass with a non-zero exit, so the deploy stops instead of an app reading encrypted text as its settings:

- A `.enc` file that is not age-encrypted, or that none of your identities can decrypt.
- A source that is a link, a hard-linked file, a named pipe, a device or a folder. A source must be a plain file with one link.
- A link or other special file at a plain file's name, when `--ext` matches that name.
- Encrypted text at a plain file's name, when `--ext` matches that name and no regular `<name>.enc` file sits beside it. With that file beside it, the result of decrypting `<name>.enc` decides instead.
- A source path that is replaced by a different file while docker-age opens it.

docker-age reads each encrypted file, and writes, checks and replaces each plain file, through a handle on the folder being searched. A path cannot lead outside that folder, and a link cannot pull a file in from elsewhere. The identity file is opened read-only, and an identity that fails to parse is reported without its contents. Each plaintext is created with mode 0600, owned by the container's user, and checked again before it replaces the old file.

## What it leaves to you

docker-age expects a stable checkout while a pass runs. It handles several of its own passes at once. It does not defend against another program that renames, links or replaces files during a pass. Give no untrusted program write access to the mounted checkout. A stop signal during a pass makes the command fail, and one file can still be written after the last check, as [How docker-age works](how-it-works.md#stopping-a-pass) explains.

The decrypted files stay on the server's disk at mode 0600 between deploys. Deleting a `.enc` file leaves the plain file an earlier pass wrote, so delete it yourself when you retire a secret.

The size limits are per file. A pass has no limit on the number of files, their total size or its running time. Keep the size of the checkout and how often a pass runs under your own control.

## Hardened compose settings

These settings add to the quick start's `compose.yaml`. [Hardening a compose file](https://github.com/cplieger/docs/blob/main/docs/hardening.md) explains each setting. docker-age decrypts with all of them as its own user, UID 65532, with no Linux capability. It writes only to the folders of the checkout and to `/tmp`, where the healthcheck file lives. Without the `/tmp` line it still decrypts, but it logs `health marker directory not writable` and its healthcheck always reports healthy.

```yaml
services:
  age:
    read_only: true
    tmpfs:
      - "/tmp:size=1m,mode=1777,noexec,nosuid,nodev"
    cap_drop:
      - ALL
    security_opt:
      - "no-new-privileges:true"
    user: "65532:65532"
    mem_limit: 64m
    pids_limit: 64
```

As root, with `user: "0:0"`, `cap_drop: ALL` also stops docker-age from reading a `keys.txt` owned by UID 65532 and from writing to folders another user owns. A decrypt then fails with `permission denied`. Add back `DAC_OVERRIDE`, the capability that lets root read and write files whatever their permissions, and keep the rest of the settings above:

```yaml
    user: "0:0"
    cap_add:
      - DAC_OVERRIDE
```

## What the image contains

The image holds one static Go binary, `/age-decrypt`, on a distroless base with no shell and no package manager. It runs as the base image's `nonroot` user, UID 65532.

| Component | Source |
| --- | --- |
| Go builder stage | [Go](https://hub.docker.com/_/golang) |
| Distroless static, nonroot | [Distroless](https://github.com/GoogleContainerTools/distroless) |
| age library | [GitHub](https://github.com/FiloSottile/age) |

[Renovate](https://github.com/renovatebot/renovate) keeps these up to date, pinned by digest or version. Each image is signed with [cosign](https://github.com/sigstore/cosign) and carries SBOM attestations, which [Checking a signature](https://github.com/cplieger/docs/blob/main/docs/images.md#checking-a-signature) and [Reading the software bill of materials](https://github.com/cplieger/docs/blob/main/docs/images.md#reading-the-software-bill-of-materials) show how to check. Live scan results are on the repository's Security tab.
