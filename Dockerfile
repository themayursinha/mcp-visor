FROM golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mcp-visor ./cmd/mcp-visor

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates

RUN addgroup -S app && adduser -S app -G app

COPY --from=builder /mcp-visor /usr/local/bin/mcp-visor
COPY examples/policies/ /etc/mcp-visor/policies/

USER app
ENTRYPOINT ["/usr/local/bin/mcp-visor"]
CMD ["serve", "--help"]
