# Contributing to docker-age

The [shared rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) for commits, releases, synced files and checks apply here.

## Checks

Run `tests/smoke.sh` before you push a change to what a pass decrypts, refuses or exits with. CI runs it in the image build and `go test ./...` does not, so the Go tests can pass on a change CI rejects.

To run it without Docker, put `age` and `age-keygen` on your `PATH`:

```sh
go build -o age-decrypt . && AGE_DECRYPT_BIN=./age-decrypt sh tests/smoke.sh
```
