# docker-age

`age-decrypt` — a small Go tool (built on [age](https://github.com/FiloSottile/age))
that decrypts age-encrypted `.env` files in place across a mounted repo tree
at deploy time, with a `health` subcommand for container health checks.
Shipped on `distroless/static` (nonroot).

## Image

```
ghcr.io/cplieger/docker-age
```

Multi-arch, signed (cosign) and SBOM-attested via the shared
[`cplieger/ci`](https://github.com/cplieger/ci) workflows.

## Usage

See [`compose.yaml`](./compose.yaml). Mount the age identity at `/age` and the
tree to decrypt at `/repo`.
