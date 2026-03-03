# Build stage
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /rampart ./cmd/rampart

# Runtime stage — distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /rampart /rampart
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/rampart"]
CMD ["serve", "--bind", "0.0.0.0:9090"]
