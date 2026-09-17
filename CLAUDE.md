# beyond

Zero-trust network access (ZTNA) HTTP(s) reverse proxy.

## Development

```bash
just install-tools  # one-time: install golangci-lint + gotestsum
just up             # start dev stack (Authentik, Postgres, ClickHouse, echo server)
just down           # tear down dev stack
```

## Build / Test / Lint

```bash
just                                  # lint + test (default target)
just lint                             # golangci-lint run ./...
just test                             # all tests
just test-race                        # with race detector
just build                            # all binaries → ./bin/
```

Unit tests run without infrastructure. E2E tests and ClickHouse tests require the
dev stack (`just up`) and `BEYOND_CLICKHOUSE_URL` set in `.env`; they self-skip
when the stack isn't running.

The metrics/pprof server listens on `:6060` (separate from the main proxy
on `:443`). These endpoints are never exposed on the main server.

Anything touching the request path, session handling, token validation,
or the proxy/metrics-server separation is high-stakes: this is an auth
proxy, and a mistake here is an auth bypass, not a bug.

## Go toolchain floor: 1.26.5 (Green Tea GC SIGILL on Zen 4)

Go 1.26.0–1.26.4's Green Tea GC SIGILLed on Zen 4 CPUs (e.g. AWS
`m7a`/`c7a`/`r7a` instances):
[golang/go#79871](https://github.com/golang/go/issues/79871), fixed in
1.26.5 via backport #79920. `go.mod` requires 1.26.5 for exactly this
reason — never lower the directive below it when deploying to hosts
that may include Zen 4.
