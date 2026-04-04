# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/web/frontend
COPY web/frontend/package*.json ./
RUN npm install
COPY web/frontend/ ./
RUN npm run build

# Stage 2: Build Go backend
FROM golang:1.23-alpine AS backend-builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /dns-supreme-mini ./cmd/dns-supreme

# Stage 3: Final image
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata curl
WORKDIR /app
COPY --from=backend-builder /dns-supreme-mini /app/dns-supreme-mini
COPY --from=frontend-builder /app/web/frontend/dist /app/web/dist
COPY configs/default.json /app/configs/default.json

RUN mkdir -p /data

VOLUME ["/data"]

EXPOSE 53/udp 53/tcp 80 443 853/tcp 853/udp 5380

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf http://localhost:5380/api/health || exit 1

ENTRYPOINT ["/app/dns-supreme-mini"]
