# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/speedtest ./cmd/speedtest

# The proxy kernel is downloaded (and SHA-256 verified) on first run, so the image
# needs CA certificates and a writable working directory.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/speedtest /usr/local/bin/speedtest
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/speedtest"]
CMD ["-version"]
