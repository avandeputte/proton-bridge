# syntax=docker/dockerfile:1
#
# Proton Mail Bridge for a home LAN, configured through a web page.
#
# Build from the repository root:
#   docker build -f docker/Dockerfile -t mailbridge .

ARG GO_IMAGE=golang:1.26
ARG BASE_IMAGE=ubuntu:24.04

FROM ${GO_IMAGE} AS go

# ---------------------------------------------------------------------------
# Stage 1: build bridge (headless) from this source tree
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS bridge-build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git make gcc g++ libc6-dev pkg-config \
      libsecret-1-dev libfido2-dev libcbor-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH GOPATH=/go

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    make build-nogui \
 && mkdir -p /out \
 && cp bridge LICENSE /out/

# ---------------------------------------------------------------------------
# Stage 2: build the supervisor / web UI
# ---------------------------------------------------------------------------
FROM go AS web-build

WORKDIR /src/mailbridge
COPY docker/mailbridge/ ./

# The gRPC client is the generated code of the bridge being built, so the web
# UI always speaks exactly the API of the bridge it ships with.
COPY internal/frontend/grpc/bridge.pb.go internal/frontend/grpc/bridge_grpc.pb.go internal/bridgepb/
RUN sed -i 's/^package grpc$/package bridgepb/' internal/bridgepb/*.go

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mailbridge .

# ---------------------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates gnupg pass tini libsecret-1-0 libfido2-1 \
 && rm -rf /var/lib/apt/lists/* \
 && (userdel --remove ubuntu 2>/dev/null || true) \
 && groupadd --gid 1000 bridge \
 && useradd --uid 1000 --gid 1000 --home-dir /data --no-create-home --shell /usr/sbin/nologin bridge \
 && install -d -o bridge -g bridge -m 0700 /data

COPY --from=bridge-build /out/bridge /usr/lib/protonmail/bridge/bridge
COPY --from=bridge-build /out/LICENSE /usr/lib/protonmail/bridge/LICENSE
COPY --from=web-build /out/mailbridge /usr/local/bin/mailbridge
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV HOME=/data \
    MAILBRIDGE_WEB_LISTEN=:8080 \
    MAILBRIDGE_IMAP_LISTEN=:143 \
    MAILBRIDGE_SMTP_LISTEN=:587

VOLUME /data
EXPOSE 8080 143 587

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/mailbridge", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
