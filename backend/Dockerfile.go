FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY cmd cmd

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /go-api cmd/api/main.go

FROM alpine:latest

RUN apk --no-cache add tzdata

WORKDIR /root/

COPY --from=builder /go-api .

EXPOSE 8080

ENTRYPOINT ["./go-api"]