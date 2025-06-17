FROM golang:1.23.9-alpine3.22 AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty)" \
    -o /app/main cmd/main.go

FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata && \
    ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

RUN mkdir -p /app/logs /app/config && \
    chown -R appuser:appgroup /app

COPY --from=builder /app/main .
COPY --chown=appuser:appgroup config/config.yaml ./config/

RUN chmod +x /app/main

USER appuser

EXPOSE 8080

ENTRYPOINT ["./main"]
CMD ["serve", "--config", "config/config.yaml"]