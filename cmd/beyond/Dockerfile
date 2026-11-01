FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X github.com/bluesky-social/beyond/internal/beyond.Version=${VERSION}" \
    -o /beyond ./cmd/beyond

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /beyond /usr/bin/beyond
ENTRYPOINT ["/usr/bin/beyond"]
CMD ["serve"]

EXPOSE 443 6060
LABEL org.opencontainers.image.source=https://github.com/bluesky-social/beyond
LABEL org.opencontainers.image.description="beyond - zero-trust network access proxy"
