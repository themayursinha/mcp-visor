FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mcp-visor ./cmd/mcp-visor

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache ca-certificates

RUN addgroup -S app && adduser -S app -G app

COPY --from=builder /mcp-visor /usr/local/bin/mcp-visor
COPY examples/policies/ /etc/mcp-visor/policies/

USER app
ENTRYPOINT ["/usr/local/bin/mcp-visor"]
CMD ["serve", "--help"]
