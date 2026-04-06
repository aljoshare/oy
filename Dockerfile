# syntax=docker/dockerfile:1

# Build stage — runs natively on the build machine, cross-compiles for the target.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# Cache dependency downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /oy .

# Runtime stage — Chainguard git image includes git for `oy repo add`.
# Runs as nonroot by default.
FROM cgr.dev/chainguard/git:latest

COPY --from=builder /oy /usr/local/bin/oy

ENTRYPOINT ["oy"]
