FROM golang:1.26.7-bookworm AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X github.com/bluesky-social/beyond/internal/beyond.Version=${VERSION}" \
    -o /beyond ./cmd/beyond

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /beyond /usr/bin/beyond
ENTRYPOINT ["/usr/bin/beyond"]
CMD ["serve"]

EXPOSE 443 6060
LABEL org.opencontainers.image.source=https://github.com/bluesky-social/beyond
LABEL org.opencontainers.image.description="beyond - zero-trust network access proxy"
