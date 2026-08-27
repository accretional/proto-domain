# DNS Resolver gRPC service (cmd/server) for Cloud Run / any container host.
#
# The build expects a vendor/ directory (deploy.sh runs `go mod vendor` on
# the host first) because go.mod replaces accretional/gluon and
# accretional/proto-ip with sibling checkouts that don't exist inside the
# build context. With vendor/ present, Go ignores the replace targets.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY . .
RUN test -d vendor || { echo "vendor/ missing - run 'go mod vendor' (see deploy.sh)" >&2; exit 1; } && \
    CGO_ENABLED=0 GOOS=linux go build -o /out/dns-server ./cmd/server

# Pure Go, no cgo (the dns fork removed the cgo path); static distroless.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dns-server /usr/local/bin/dns-server
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dns-server"]
