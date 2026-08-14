# beyond

A zero-trust network access (ZTNA) reverse proxy. It sits in front of internal HTTP apps (Grafana, ArgoCD, etc.), authenticates users against an OIDC provider, checks group membership, and forwards allowed requests upstream with identity headers (`X-Beyond-Email`, `X-Beyond-Groups`, ...). Access logs go to stdout and Postgres.

Apps and their allowed groups are declared in a YAML config:

```yaml
portal:
  host: example.com
  title: Applications

applications:
  grafana:
    upstream: http://grafana:3000
    host: grafana.example.com
    display_name: Grafana
    description: Metrics and dashboards
    launch_url: https://grafana.example.com/
    allowed_groups: [engineering, ops]
```

When `portal` is configured, its host serves a small authenticated application
directory. It lists only applications allowed by the user's current groups;
administrators see all applications. `display_name`, `description`, and
`launch_url` are optional. Launch URLs default to `https://<host>/` and, when
set explicitly, must remain on the application's configured host.

The config is read once at startup; policy changes require a restart. beyond is stateless — run as many replicas as you like, as long as they share the same `BEYOND_SESSION_SECRET`.

## Running with docker

Images are published to `ghcr.io/bluesky-social/beyond`.

```bash
docker run --rm \
  -p 443:443 \
  -v /path/to/beyond.yaml:/etc/beyond.yaml:ro \
  -e BEYOND_CONFIG=/etc/beyond.yaml \
  -e BEYOND_SESSION_SECRET=<32-byte hex key> \
  -e BEYOND_OIDC_ISSUER=https://auth.example.com/application/o/beyond/ \
  -e BEYOND_OIDC_CLIENT_ID=... \
  -e BEYOND_OIDC_CLIENT_SECRET=... \
  -e BEYOND_DB_URL=postgresql://... \
  ghcr.io/bluesky-social/beyond:latest
```

beyond serves plain HTTP unless you hand it a cert with `BEYOND_TLS_CERT`/`BEYOND_TLS_KEY` — terminate TLS at your load balancer or mount a cert. Run `beyond serve --help` for the full list of flags. The metrics/pprof server listens on `:6060` and should never be exposed publicly.

## Development

You need Go, docker compose, OpenSSL, and [just](https://github.com/casey/just).

```bash
just install-tools  # one-time: golangci-lint + gotestsum
just up             # dev stack: Authentik, Postgres, echo server
just run beyond serve

just                # lint + test
just down
```

The development portal is at `https://localhost:8443`. `just up` generates an
ignored, self-signed certificate for `localhost` and `echo.localhost`; accept
or locally trust that certificate when using a browser. Sign in with
`test@beyond.local` / `test`.

Unit tests need no infrastructure; e2e/DB tests want the dev stack up and skip themselves otherwise. The dev Authentik login is `test@beyond.local` / `test`.

## License

Dual MIT/Apache-2.0, see [LICENSE-DUAL](LICENSE-DUAL).
