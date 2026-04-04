# Build stage
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /dns-supreme-mini ./cmd/dns-supreme-mini

# Final stage - minimal image
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /dns-supreme-mini /app/dns-supreme-mini
COPY configs/default.json /app/configs/default.json

# Create data directory
RUN mkdir -p /data

VOLUME ["/data"]

EXPOSE 53/udp 53/tcp 80 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -q --spider http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/app/dns-supreme-mini"]
