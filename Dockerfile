FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mcp-visor ./cmd/mcp-visor

FROM alpine:3.21@sha256:21dc6063f4f8f2d37c3c792e177016b679652b758c62b3e0b4b5c97fa1a6b467

RUN apk add --no-cache ca-certificates

RUN addgroup -S app && adduser -S app -G app

COPY --from=builder /mcp-visor /usr/local/bin/mcp-visor
COPY examples/policies/ /etc/mcp-visor/policies/

USER app
ENTRYPOINT ["/usr/local/bin/mcp-visor"]
CMD ["serve", "--help"]
