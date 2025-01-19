FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o auto-tunnel cmd/tunnel/main.go

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/auto-tunnel /usr/local/bin/
COPY config.yaml.example /etc/auto-tunnel/config.yaml

RUN mkdir -p /var/log/auto-tunnel

ENTRYPOINT ["auto-tunnel"] 