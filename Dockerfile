# check=error=true
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /age-decrypt .

# ---------------------------------------------------------------------------
# Test stage — build-time smoke test against the freshly built binary. It
# round-trips a known secret through age-decrypt (encrypt with the upstream
# `age` CLI, decrypt with the built binary, assert the plaintext matches), so
# the central `ci / validate` docker build gate fails if the build produced a
# binary that cannot actually decrypt. The final stage depends on this stage's
# /tests-passed marker, so BuildKit always builds it. `age` (an Alpine community
# package, like keepalived's) is installed ONLY in this throwaway stage, never
# in the distroless final image; age-decrypt is decrypt-only, so the fixture is
# minted at build time rather than committed (no test key trips the secret scan).
# No apk version pin: the digest-pinned builder base fixes the Alpine release
# line, matching the fleet convention.
# ---------------------------------------------------------------------------
FROM builder AS test
RUN apk add --no-cache age
COPY tests/ /tmp/tests/
RUN AGE_DECRYPT_BIN=/age-decrypt sh /tmp/tests/smoke.sh && touch /tests-passed

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --chmod=755 --from=builder /age-decrypt /age-decrypt
# Force the test stage to build and pass before the runtime image is produced
# (the marker's only purpose is this dependency edge; it is a root-owned,
# zero-byte /tests-passed and does not affect the binary, entrypoint, or user).
COPY --from=test /tests-passed /tests-passed
# Runs as the distroless nonroot user by default. Deployments that must rewrite
# a tree with mixed or root ownership (e.g. orchestrator-cloned repos) override
# to root in compose with user: "0:0".
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD ["/age-decrypt", "health"]
ENTRYPOINT ["/age-decrypt"]
