# MIRASTACK Connector — Keycloak (OSS, AGPL v3)
#
# Build (from monorepo root):
#   docker build -f connectors/AAAA/oss/mirastack-connector-keycloak/Dockerfile .
#
# Multi-arch build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f connectors/AAAA/oss/mirastack-connector-keycloak/Dockerfile \
#     -t mirastack-connector-keycloak:latest .

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY sdk/ent/connector-sdk/mirastack-connector-sdk-go/ sdk/ent/connector-sdk/mirastack-connector-sdk-go/

COPY connectors/AAAA/oss/mirastack-connector-keycloak/go.mod \
     connectors/AAAA/oss/mirastack-connector-keycloak/go.sum* \
     connectors/AAAA/oss/mirastack-connector-keycloak/

WORKDIR /src/connectors/AAAA/oss/mirastack-connector-keycloak
RUN go mod download

WORKDIR /src
COPY connectors/AAAA/oss/mirastack-connector-keycloak/ connectors/AAAA/oss/mirastack-connector-keycloak/

WORKDIR /src/connectors/AAAA/oss/mirastack-connector-keycloak
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags "-s -w" -o /mirastack-connector-keycloak .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /mirastack-connector-keycloak /usr/local/bin/mirastack-connector-keycloak

EXPOSE 50051

ENTRYPOINT ["mirastack-connector-keycloak"]
