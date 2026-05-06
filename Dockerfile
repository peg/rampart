# Build stage. Build on the native runner platform and cross-compile for the
# requested image platform so linux/arm64 releases don't depend on slow QEMU
# emulation for the Go build itself.
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.25.9-bookworm AS build
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

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /rampart /rampart
USER nonroot:nonroot
ENV HOME=/tmp
WORKDIR /tmp
EXPOSE 9090
ENTRYPOINT ["/rampart"]
CMD ["serve", "--addr", "0.0.0.0", "--port", "9090"]
