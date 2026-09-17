# beyond

A zero-trust network access (ZTNA) reverse proxy. It sits in front of internal HTTP apps (Grafana, ArgoCD, etc.), authenticates users against an OIDC provider, checks group membership, and forwards allowed requests upstream with identity headers (`X-Beyond-Email`, `X-Beyond-Groups`, ...). Access logs are written to ClickHouse in efficient batches and retained for 90 days.

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
administrators see all applications except entries marked `hide_from_portal`.
`display_name`, `description`, and `launch_url` are optional. Launch URLs
default to `https://<host>/` and, when set explicitly, must remain on the
application's configured host. Set `hide_from_portal: true` for supporting
hosts such as a browser API origin.

The config is read once at startup; policy changes require a restart. beyond is stateless — run as many replicas as you like, as long as they share the same `BEYOND_SESSION_SECRET`.

For machine protocols whose OAuth discovery begins unauthenticated, an app may
delegate a narrow set of exact paths to an independently authenticating
upstream while retaining Beyond JWT verification for bearer requests:

```yaml
applications:
  mcp:
    upstream: http://agent-gateway:4004
    host: mcp.example.com
    preserve_host: true
    allowed_groups: [engineering]
    bearer_auth:
      issuer: https://auth.example.com/application/o/mcp/
      jwks_url: http://authentik/application/o/mcp/jwks/
      audience: mcp
    unauthenticated_passthrough_paths:
      - /mcp
      - /.well-known/oauth-protected-resource/mcp
```

Only requests with no `Authorization` header use this path. Bearer requests
still receive Beyond's JWT and group-policy checks.

For the delegated paths themselves, Beyond applies no authorization:
`allowed_groups` is not enforced, no identity is injected, and any client can
reach them. Beyond strips inbound `X-Beyond-*` identity headers and forwards
the request. The upstream is therefore the sole access-control boundary for
every delegated path and must authenticate it (for example, by returning a
`401` with `WWW-Authenticate`) or intentionally serve it anonymously. Never
delegate a path that exposes data or actions before upstream authentication.

Split-origin browser applications can opt in to
`cors_preflight_passthrough: true` when their API uses `bearer_auth`. Beyond
delegates only credential-free `OPTIONS` requests containing both `Origin` and
`Access-Control-Request-Method`; the upstream remains responsible for its CORS
policy. Actual API requests still require Beyond's normal session or verified
bearer token.

`preserve_host: true` sends the configured public application hostname in the
upstream HTTP `Host` header while still dialing `upstream`. This is useful when
the upstream derives OAuth metadata or absolute URLs from `Host`; Beyond still
sets authoritative `X-Forwarded-Host` and `X-Forwarded-Proto` headers as usual.

## Identity headers for upstream services

Beyond removes every client-supplied `X-Beyond-*` header before proxying a
request. For an authenticated request, it adds the verified identity to the
outbound request:

| Header | Value | How to use it |
| --- | --- | --- |
| `X-Beyond-User` | The user's verified email address | Email-valued user identifier; it is currently identical to `X-Beyond-Email`. |
| `X-Beyond-Email` | The user's verified email address | Use as the stable user identifier for new integrations. |
| `X-Beyond-Name` | The user's display name | Use only for display; the header is omitted when no name is available. |
| `X-Beyond-Groups` | Verified group names joined with `\|` | Split on `\|` and compare complete group names; the header is omitted when the user has no groups. |
| Configured `grafana_role_projection.header` (commonly `X-Beyond-Role`) | `Admin`, `Editor`, `Viewer`, or `None` | Optional, app-specific Grafana role; present only when role projection is configured. |

Treat the headers as trusted only when the upstream cannot be reached except
through Beyond (for example, enforce this with a private network or network
policy). A directly reachable upstream lets callers forge the same headers.
Treat a missing identity header as unauthenticated and fail closed; Beyond
intentionally injects no identity on configured unauthenticated or
authentication-passthrough paths. Use `X-Beyond-Email`, not the display name,
for identity, and perform exact group comparisons rather than substring
matches.

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
  -e BEYOND_CLICKHOUSE_URL='clickhouse://user:password@clickhouse:9440/beyond?secure=true' \
  ghcr.io/bluesky-social/beyond:latest
```

beyond serves plain HTTP unless you hand it a cert with `BEYOND_TLS_CERT`/`BEYOND_TLS_KEY` — terminate TLS at your load balancer or mount a cert. Run `beyond serve --help` for the full list of flags. The metrics/pprof server listens on `:6060` and should never be exposed publicly.

### Access-log storage

`BEYOND_CLICKHOUSE_URL` is required. At startup, each Beyond replica
idempotently creates one `access_logs` `MergeTree` table with monthly
partitions and a native 90-day TTL. Rows are ordered by day, user, and event
time for time-bounded audit queries.

Beyond batches up to 1,000 events per native insert and flushes low-volume
traffic every five seconds. ClickHouse I/O runs outside request goroutines.
Failed batches are retried, while the in-memory queue is capped at 50,000
events; overflow drops the oldest events and increments
`beyond_access_log_dropped_entries_total`. Failed writes increment
`beyond_access_log_write_failures_total`. Because a connection can fail after
ClickHouse commits but before it acknowledges an insert, retries are
at-least-once and may very rarely produce duplicate rows.

## Design proposals

- [Machine identity and scoped credentials](docs/design/machine-identity-and-scoped-credentials.md)

## Development

You need Go, docker compose, OpenSSL, and [just](https://github.com/casey/just).

```bash
just install-tools  # one-time: golangci-lint + gotestsum
just up             # dev stack: Authentik, Postgres, ClickHouse, echo server
just run beyond serve

just                # lint + test
just down
```

The development portal is at `https://localhost:8443`. `just up` generates an
ignored, self-signed certificate for `localhost` and `echo.localhost`; accept
or locally trust that certificate when using a browser. Sign in with
`test@beyond.local` / `test`.

Unit tests need no infrastructure; e2e/ClickHouse tests want the dev stack up and skip themselves otherwise. The dev Authentik login is `test@beyond.local` / `test`.

## License

Dual MIT/Apache-2.0, see [LICENSE-DUAL](LICENSE-DUAL).
