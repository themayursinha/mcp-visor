FROM golang:1.23-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mcp-visor ./cmd/mcp-visor

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /mcp-visor /usr/local/bin/mcp-visor
COPY examples/policies/ /etc/mcp-visor/policies/

ENTRYPOINT ["/usr/local/bin/mcp-visor"]
CMD ["serve", "--help"]
