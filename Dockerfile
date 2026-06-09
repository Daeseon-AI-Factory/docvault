FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /docvault ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /docvault /usr/local/bin/docvault

EXPOSE 8080
ENTRYPOINT ["docvault"]
CMD ["serve"]
