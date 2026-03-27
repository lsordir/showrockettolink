FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bot .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/bot /bot

CMD ["/bot"]
