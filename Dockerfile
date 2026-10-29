# syntax=docker/dockerfile:1
FROM golang:1.26.10-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/shortlinks ./cmd/shortlinks

# The service is a pure-Go binary. Scratch keeps the production image to the
# executable and public CA roots required for outbound HTTPS link checks.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/shortlinks /shortlinks
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/shortlinks"]
