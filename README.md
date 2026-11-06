# beyond

A zero-trust network access (ZTNA) reverse proxy. It sits in front of internal HTTP apps (Grafana, ArgoCD, etc.), authenticates users against an OIDC provider, checks group membership, and forwards allowed requests upstream with identity headers (`X-Beyond-Email`, `X-Beyond-Groups`, ...). Inspired by [presbrey/beyond](https://github.com/presbrey/beyond).

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

The config is read once at startup. beyond is stateless — run as many replicas as you like, as long as they share the same `BEYOND_SESSION_SECRET`.

### Access policy from Authentik applications

When the Authentik API is configured (`BEYOND_AUTHENTIK_API_URL` and
`BEYOND_AUTHENTIK_API_TOKEN`), **a route's name is the slug of the Authentik
application that governs it**. For the `grafana` route above, Beyond looks up
the Authentik application `grafana`:

- **The application exists:** its policy bindings are the route's only access
  list. The route's `allowed_groups` is ignored, and Beyond logs a warning
  naming the route.
- **Authentik answers 404:** the route uses its `allowed_groups`.
- **No answer yet** (Authentik unreachable since startup): the route denies
  every non-admin request. It does not fall back to `allowed_groups`, which may
  grant more than Authentik's bindings.

`allowed_groups` therefore stays required, as the fallback. Without the
Authentik API configured, every route uses its `allowed_groups`.

Beyond evaluates the bindings itself, so it accepts only bindings it can
evaluate exactly: policy engine mode `any`, with every enabled binding a plain
group binding (not negated, not expiring). A user passes if they are a member
of a bound group or of any of its descendant groups, which is how Authentik
evaluates group bindings. Disabled bindings are ignored. Anything else
(user or expression-policy bindings, negated or expiring bindings, mode `all`)
denies every non-admin request to the route. So does an application with no
enabled bindings: Authentik treats that as open to everyone, but Beyond fails
closed.

Policies load once before Beyond starts serving and refresh every 60 seconds
(every 10 seconds while a route is unresolved). If a lookup fails after a
route has resolved, the route keeps its last-known-good policy. A definitive
answer (the application now exists, now 404s, or its bindings changed)
replaces it. Each change is logged with the route's old and new groups.
`beyond_app_policy_source{app,source}` reports each route's current source
(`authentik`, `allowed_groups`, `unresolved` or `invalid`), and
`beyond_app_policy_last_refresh_success_timestamp_seconds` records the last
refresh in which every route got a definitive answer.

The API token needs only read access. It should belong to a non-superuser
service account with Authentik's built-in `authentik Read-only` role; the dev
stack sets one up the same way. Beyond retrieves each application by slug
because Authentik's application list only returns applications the caller can
access itself.

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
the route's group policy is not enforced, no identity is injected, and any client can
reach them. Beyond strips inbound `X-Beyond-*` identity headers and forwards
the request. The upstream is therefore the sole access-control boundary for
every delegated path and must authenticate it (for example, by returning a
`401` with `WWW-Authenticate`) or intentionally serve it anonymously. Never
delegate a path that exposes data or actions before upstream authentication.

For an upstream that authenticates opaque bearer tokens Beyond cannot verify,
use exact `upstream_auth_passthrough_paths` instead:

```yaml
applications:
  opaque-mcp:
    upstream: http://agent-gateway:4011
    host: opaque-mcp.example.com
    allowed_groups: [engineering]
    upstream_auth_passthrough_paths:
      - /mcp
      - /.well-known/oauth-protected-resource/mcp
```

These paths accept either no `Authorization` header for protocol bootstrap or
a non-empty `Bearer` credential, which is forwarded unchanged. Beyond does not
apply the route's group policy or inject identity. Other schemes and all unlisted,
nearby, escaped, or non-canonical paths retain Beyond's normal authentication.
Use this only when the upstream independently fails closed on protected paths.

Split-origin browser applications can opt in to
`cors_preflight_passthrough: true` when their API uses `bearer_auth`. Beyond
delegates only credential-free `OPTIONS` requests containing both `Origin` and
`Access-Control-Request-Method`; the upstream remains responsible for its CORS
policy. Actual API requests still require Beyond's normal session or verified
bearer token.

Beyond's own bearer-path responses (401, 403, 429) carry no CORS headers, so a
split-origin UI can't read them: the browser reports a network error. Two
opt-in `bearer_auth` settings support browser clients:

```yaml
    bearer_auth:
      issuer: https://auth.example.com/application/o/app/
      jwks_url: http://authentik/application/o/app/jwks/
      audience: app
      cors_origins: [https://app.example.com]
      signal_expiry: true
```

`cors_origins` lists exact https origins allowed to read the responses Beyond
generates on the bearer path. Proxied responses keep only the upstream's CORS
headers. `signal_expiry` answers an expired token with
`{"status":401,"message":"jwt expired"}` (the wording clients of
`jsonwebtoken` backends, such as GrowthBook, refresh on) instead of the opaque
`invalid token`, and stops expired tokens from spending the failure
budget. Only a genuinely signed token can be reported as expired, because the
signature is verified first.

`preserve_host: true` sends the configured public application hostname in the
upstream HTTP `Host` header while still dialing `upstream`. This is useful when
the upstream derives OAuth metadata or absolute URLs from `Host`; Beyond still
sets authoritative `X-Forwarded-Host` and `X-Forwarded-Proto` headers as usual.

## Identity headers for upstream services

Beyond removes every client-supplied `X-Beyond-*` header before proxying a
request, in any letter case and also when spelled with `_` for `-` (such as
`X_Beyond_Email`), because CGI-style servers treat both spellings as the same
header. For an authenticated request, it adds the verified identity to the
outbound request:

| Header | Value | How to use it |
| --- | --- | --- |
| `X-Beyond-User` | The user's verified email address | Email-valued user identifier; it is currently identical to `X-Beyond-Email`. |
| `X-Beyond-Email` | The user's verified email address | Use as the stable user identifier for new integrations. |
| `X-Beyond-Name` | The user's display name | Use only for display; the header is omitted when no name is available. |
| `X-Beyond-Groups` | Verified group names joined with `\|` | Split on `\|` and compare complete group names; the header is omitted when the user has no groups. |
| `X-Beyond-Did` | The user's atproto DID (`did:plc:...` or `did:web:...`) | Optional; present only for users mapped to an atproto account. Use to attribute actions to that account; see below. |
| Configured `grafana_role_projection.header` (commonly `X-Beyond-Role`) | `Admin`, `Editor`, `Viewer`, or `None` | Optional, app-specific Grafana role; present only when role projection is configured. |

Treat the headers as trusted only when the upstream cannot be reached except
through Beyond (for example, enforce this with a private network or network
policy). A directly reachable upstream lets callers forge the same headers.
Treat a missing identity header as unauthenticated and fail closed; Beyond
intentionally injects no identity on configured unauthenticated or
authentication-passthrough paths. Use `X-Beyond-Email`, not the display name,
for identity, and perform exact group comparisons rather than substring
matches.

Beyond takes `X-Beyond-Did` from the identity provider's optional
`atproto_did` OIDC claim at login. It forwards the value only when it is
`did:plc:` followed by 24 characters from `[a-z2-7]`, or `did:web:` followed
by a lowercase hostname. Any other value is logged and dropped; it never fails
the login. The DID is fixed for the life of the session, whereas groups are
re-resolved, so a mapping change takes effect at the user's next login. Only
the browser login carries the claim, so the header is sent only on
browser-session requests: never on `bearer_auth` or `credential_auth` requests,
or on passthrough paths. As with the other identity headers, an upstream may rely on
`X-Beyond-Did` only when Beyond is the sole path to it, because a caller that
can reach the upstream directly can claim any DID. Treat a missing header as
"no atproto identity", never as a reason to fall back to another identifier.

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
  -e BEYOND_AUTHENTIK_API_URL=http://authentik:9000 \
  -e BEYOND_AUTHENTIK_API_TOKEN=... \
  -e BEYOND_DB_URL=postgresql://... \
  ghcr.io/bluesky-social/beyond:latest
```

beyond serves plain HTTP unless you hand it a cert with `BEYOND_TLS_CERT`/`BEYOND_TLS_KEY` — terminate TLS at your load balancer or mount a cert. Run `beyond serve --help` for the full list of flags. The metrics/pprof server listens on `:6060` and should never be exposed publicly.

## Design proposals

- [Machine identity and scoped credentials](docs/design/machine-identity-and-scoped-credentials.md)

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

`just up` also creates Beyond's Authentik API identity the way prod has it (a
non-superuser service account with the `authentik Read-only` role; its token
is in `.env`) and an `echo` application bound to `engineering`, so the dev
`echo` route takes its policy from Authentik.

## Releases and commit messages

Releases are cut by [release-please](https://github.com/googleapis/release-please)
through the org release pipeline ([shared workflow](https://github.com/bluesky-social/.github#release-pleaseyml-and-actionsrelease-gate)).

**Commit messages need a `type:` prefix, but any word works.** PRs are
squash-merged, so the PR title becomes the commit, and a required
`pr-title / pr-title` check enforces the prefix. release-please drops commits without
one. `feat:` releases a minor version, a breaking change (`feat!:`, or a
`BREAKING CHANGE:` footer) a major one (a minor while the version is 0.x),
and anything else, including subsystem prefixes like `ask:`, a patch.
Release notes are built from merged PR titles, so write the title as the
changelog line you want. Direct pushes appear only in the release's
compare link.

**How a release happens.** Every push to `main` updates a standing
`chore(main): release X.Y.Z` PR maintained by `bsky-public-release-bot`. Merging it
tags `vX.Y.Z` and builds `ghcr.io/bluesky-social/beyond:vX.Y.Z` and, after re-checking that the released tree passed `test`, `build` and `lint`, dispatches the deploy into `bluesky-social/deploy`.

- If every commit since the last tag came from a merged Renovate or
  Dependabot PR, the Release PR merges itself on the hourly run, weekdays
  09:00-16:00 PT. Otherwise a human merges it.
- Any human-authored commit in that range, even one that doesn't release on
  its own, means a human merges the next Release PR.
- Label the Release PR `release:manual` to hold a release.

**Dependencies** come from Renovate with the [org preset](https://github.com/bluesky-social/.github/blob/main/renovate/default.json)
(`renovate.json`). Don't push to a Renovate PR or click "Update branch" on
one: that adds a human commit, so the next release needs a human. If a bump
needs code changes, make them in a separate PR.

**CI.** `main` requires `test`, `build`, `lint`, `pr-title / pr-title`, `govulncheck`,
`gitleaks` and `actionlint` to pass, and PRs must be up to date with `main`
before they merge.

## License

Dual MIT/Apache-2.0, see [LICENSE-DUAL](LICENSE-DUAL).
