# syntax=docker/dockerfile:1
FROM golang:1.23 as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o secret-scanner ./cmd/server

FROM gcr.io/distroless/base-debian11
WORKDIR /app
COPY --from=builder /app/secret-scanner .
USER nonroot:nonroot
EXPOSE 50051
ENTRYPOINT ["./secret-scanner"]
