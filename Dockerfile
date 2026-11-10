# Build stage. Build on the native runner platform and cross-compile for the
# requested image platform so linux/arm64 releases don't depend on slow QEMU
# emulation for the Go build itself.
ARG BUILDPLATFORM
# Base images are pinned by multi-arch index digest so a moved upstream tag
# cannot change what a release builds. Update the tag and digest together.
FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473 AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
    -ldflags="-s -w \
      -X github.com/peg/rampart/internal/build.versionFromLDFlags=${VERSION} \
      -X github.com/peg/rampart/internal/build.Commit=${COMMIT} \
      -X github.com/peg/rampart/internal/build.Date=${DATE}" \
    -o /rampart ./cmd/rampart
RUN mkdir -p /runtime-home/.rampart/policies /runtime-home/.rampart/audit

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /rampart /rampart
COPY --from=build --chown=65532:65532 /runtime-home/ /home/nonroot/
USER nonroot:nonroot
ENV HOME=/home/nonroot
WORKDIR /home/nonroot
EXPOSE 9090
ENTRYPOINT ["/rampart"]
CMD ["serve", "--addr", "0.0.0.0", "--port", "9090"]
