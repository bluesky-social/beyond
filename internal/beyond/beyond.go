package beyond

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v3"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// NewRootCommand creates the root CLI command for beyond.
func NewRootCommand() *cli.Command {
	var configPath string

	return &cli.Command{
		Name:  "beyond",
		Usage: "Zero-trust network access proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Usage:       "Path to the YAML config file",
				Value:       "beyond.yaml",
				Sources:     cli.EnvVars("BEYOND_CONFIG"),
				Destination: &configPath,
			},
		},
		Commands: []*cli.Command{
			newServeCmd(&configPath),
			newVersionCmd(),
		},
	}
}

func newServeCmd(configPath *string) *cli.Command {
	var (
		listen            string
		metricsListen     string
		tlsCert           string
		tlsKey            string
		clickhouseURL     string
		oidcIssuer        string
		oidcClientID      string
		oidcClientSecret  string
		oidcTLSSkipVerify bool
		sessionSecrets    []string
		authentikAPIURL   string
		authentikAPIToken string
	)

	return &cli.Command{
		Name:  "serve",
		Usage: "Start the beyond proxy server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "listen",
				Usage:       "Address to listen on",
				Value:       ":443",
				Sources:     cli.EnvVars("BEYOND_LISTEN"),
				Destination: &listen,
			},
			&cli.StringFlag{
				Name:        "metrics-listen",
				Usage:       "Address for the internal metrics/debug server (pprof + Prometheus)",
				Value:       ":6060",
				Sources:     cli.EnvVars("BEYOND_METRICS_LISTEN"),
				Destination: &metricsListen,
			},
			&cli.StringFlag{
				Name:        "tls-cert",
				Usage:       "Path to TLS certificate file",
				Sources:     cli.EnvVars("BEYOND_TLS_CERT"),
				Destination: &tlsCert,
			},
			&cli.StringFlag{
				Name:        "tls-key",
				Usage:       "Path to TLS private key file",
				Sources:     cli.EnvVars("BEYOND_TLS_KEY"),
				Destination: &tlsKey,
			},
			&cli.StringFlag{
				Name:        "clickhouse-url",
				Usage:       "ClickHouse connection URL for access logs",
				Sources:     cli.EnvVars("BEYOND_CLICKHOUSE_URL"),
				Destination: &clickhouseURL,
			},
			&cli.StringFlag{
				Name:        "oidc-issuer",
				Usage:       "OIDC provider issuer URL",
				Sources:     cli.EnvVars("BEYOND_OIDC_ISSUER"),
				Destination: &oidcIssuer,
			},
			&cli.StringFlag{
				Name:        "oidc-client-id",
				Usage:       "OIDC client ID",
				Sources:     cli.EnvVars("BEYOND_OIDC_CLIENT_ID"),
				Destination: &oidcClientID,
			},
			&cli.StringFlag{
				Name:        "oidc-client-secret",
				Usage:       "OIDC client secret",
				Sources:     cli.EnvVars("BEYOND_OIDC_CLIENT_SECRET"),
				Destination: &oidcClientSecret,
			},
			&cli.BoolFlag{
				Name:        "oidc-tls-skip-verify",
				Usage:       "Skip TLS certificate verification for OIDC provider (for in-cluster self-signed certs)",
				Sources:     cli.EnvVars("BEYOND_OIDC_TLS_SKIP_VERIFY"),
				Destination: &oidcTLSSkipVerify,
			},
			&cli.StringSliceFlag{
				Name:        "session-secrets",
				Usage:       "32-byte hex-encoded session encryption key (CSV for key rotation)",
				Sources:     cli.EnvVars("BEYOND_SESSION_SECRET"),
				Destination: &sessionSecrets,
			},
			&cli.StringFlag{
				Name:        "authentik-api-url",
				Usage:       "Authentik API base URL for user validation (e.g. http://authentik:9000)",
				Sources:     cli.EnvVars("BEYOND_AUTHENTIK_API_URL"),
				Destination: &authentikAPIURL,
			},
			&cli.StringFlag{
				Name:        "authentik-api-token",
				Usage:       "Authentik API bearer token for user validation",
				Sources:     cli.EnvVars("BEYOND_AUTHENTIK_API_TOKEN"),
				Destination: &authentikAPIToken,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			// Load config.
			cfg, err := LoadConfig(*configPath)
			if err != nil {
				return err
			}

			logger.Info("beyond starting",
				"version", Version,
				"listen", listen,
				"config", *configPath,
				"apps", len(cfg.Applications),
			)

			// Parse session secrets (repeatable flag for key rotation).
			// The first key is used for encryption; all are tried for decryption
			// to support graceful key rotation.
			if len(sessionSecrets) == 0 {
				return fmt.Errorf("--session-secrets is required")
			}
			var sessionKeys [][]byte
			for _, hexKey := range sessionSecrets {
				hexKey = strings.TrimSpace(hexKey)
				key, err := hex.DecodeString(hexKey)
				if err != nil {
					return fmt.Errorf("decoding session secret: %w", err)
				}
				if len(key) != 32 {
					return fmt.Errorf("each session secret must be exactly 64 hex characters (32 bytes), got %d bytes", len(key))
				}
				sessionKeys = append(sessionKeys, key)
			}

			// Create SessionManager.
			sm, err := NewSessionManager(sessionKeys, cfg.Sessions.HTTPLifetime)
			if err != nil {
				return fmt.Errorf("creating session manager: %w", err)
			}

			if clickhouseURL == "" {
				return fmt.Errorf("--clickhouse-url is required")
			}

			// ClickHouse is the durable access-log store. Schema creation is
			// idempotent, so every replica can safely initialize at startup.
			accessLogStore, err := OpenClickHouseAccessLogStore(ctx, clickhouseURL)
			if err != nil {
				return fmt.Errorf("opening access-log store: %w", err)
			}
			defer func() { _ = accessLogStore.Close() }()

			accessLog := &AccessLogger{Logger: logger, Sink: accessLogStore}
			accessLog.StartFlusher()
			// StopFlusher is idempotent (gracefulShutdown also calls it); this
			// defer guarantees the writer is stopped before the store Close
			// defer above runs on any early startup-error return path. Those
			// paths have queued no access logs, so the drain returns at once;
			// the bounded context is a backstop, never a real shutdown wait.
			defer func() {
				stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				accessLog.StopFlusher(stopCtx)
			}()
			logger.Info("ClickHouse connected and access-log schema initialized",
				"retention_days", accessLogRetentionDays)

			// Create Handler.
			handler := NewHandler(cfg, sm, accessLog)

			//  Create user validator if Authentik API is configured.
			if authentikAPIURL != "" && authentikAPIToken != "" {
				userValidator := NewUserValidator(authentikAPIURL, authentikAPIToken)
				handler.SetUserValidator(userValidator)
				defer userValidator.Stop()
				logger.Info("user validation enabled", "api_url", authentikAPIURL)
			}

			// Create OIDCAuth if --oidc-issuer is provided.
			if oidcIssuer != "" {
				oidcAuth, err := NewOIDCAuth(ctx, OIDCConfig{
					IssuerURL:     oidcIssuer,
					ClientID:      oidcClientID,
					ClientSecret:  oidcClientSecret,
					TLSSkipVerify: oidcTLSSkipVerify,
				})
				if oidcTLSSkipVerify {
					logger.Warn("OIDC TLS certificate verification is disabled")
				}
				if err != nil {
					return fmt.Errorf("creating OIDC auth: %w", err)
				}
				handler.SetOIDCAuth(oidcAuth)
				logger.Info("OIDC authentication configured", "issuer", oidcIssuer)
			}

			// Wire a dedicated mint OIDCAuth per app configured with mint_auth.
			// This client requests the goauthentik.io/api scope and is kept
			// separate from the login client (its access token is an Authentik
			// API bearer — never put that on the shared login session). The
			// browser-facing issuer is discovered against the public URL; the
			// token exchange and API calls hit the in-cluster host (split-horizon
			// handled inside the handler). Reuse oidc-tls-skip-verify for the
			// in-cluster self-signed cert posture.
			for _, app := range cfg.Applications {
				if app.MintAuth == nil {
					continue
				}
				mintAuth, err := NewMintOIDCAuth(ctx, OIDCConfig{
					IssuerURL:     app.MintAuth.Issuer,
					ClientID:      app.MintAuth.ClientID,
					TLSSkipVerify: oidcTLSSkipVerify,
				})
				if err != nil {
					return fmt.Errorf("creating mint OIDC auth for app %q: %w", app.Name, err)
				}
				handler.SetMintAuth(app.Host, mintAuth)
				logger.Info("mint page configured", "app", app.Name, "host", app.Host, "issuer", app.MintAuth.Issuer)
			}

			// Start internal metrics/debug server.
			// pprof handlers are registered on DefaultServeMux by the
			// net/http/pprof blank import. Prometheus is added alongside.
			//
			// SECURITY: this server is UNAUTHENTICATED — /metrics and
			// /debug/pprof/* expose operational internals. It is isolated from
			// the :443 proxy mux (separate http.Server + DefaultServeMux), so
			// it never leaks onto the public surface, but the listener itself
			// has no auth. Bind --metrics-listen to localhost or a mesh-only
			// interface; never expose it publicly.
			http.Handle("/metrics", promhttp.Handler())
			debugSrv := &http.Server{
				Addr:         metricsListen,
				Handler:      nil, // DefaultServeMux: serves /metrics and /debug/pprof/*
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 60 * time.Second,
			}
			go func() {
				logger.Info("starting metrics/debug server", "addr", metricsListen)
				if err := debugSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Error("metrics server error", "err", err)
				}
			}()

			// Create HTTP server.
			srv := newProxyServer(listen, handler)

			// Start server in a goroutine.
			serverErr := make(chan error, 1)
			go func() {
				logger.Info("starting server", "addr", listen)
				if tlsCert != "" && tlsKey != "" {
					serverErr <- srv.ListenAndServeTLS(tlsCert, tlsKey)
				} else {
					serverErr <- srv.ListenAndServe()
				}
			}()

			// Wait for context cancellation or server error.
			select {
			case err := <-serverErr:
				if err != nil && err != http.ErrServerClosed {
					return fmt.Errorf("server error: %w", err)
				}
			case <-ctx.Done():
			}

			// Graceful shutdown.
			logger.Info("beyond shutting down")

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := gracefulShutdown(shutdownCtx, srv, debugSrv, accessLog); err != nil {
				return err
			}

			logger.Info("beyond shutdown complete")
			return nil
		},
	}
}

// proxyReadHeaderTimeout bounds how long a client may take to send the request
// line and headers. It is the slowloris/handshake guard. Unlike ReadTimeout /
// WriteTimeout it does NOT bound the body or the response, so it cannot sever
// a long-lived stream.
const proxyReadHeaderTimeout = 10 * time.Second

// newProxyServer builds the main proxy http.Server.
//
// Critically it sets ReadTimeout and WriteTimeout to 0 (disabled). Those are
// whole-connection absolute deadlines: a non-zero WriteTimeout force-closes
// the response connection that many seconds after the request was read,
// regardless of activity, which severs Server-Sent Events and any other
// long-lived streaming response a proxy must support (verified: an SSE stream
// is cut at exactly WriteTimeout). ReadTimeout likewise caps slow but
// legitimate request bodies (large uploads).
//
// The handshake is still bounded by ReadHeaderTimeout (slowloris guard) and
// idle keep-alive connections by IdleTimeout. Per-response liveness for the
// streaming path is enforced by an idle write deadline armed in the proxy
// handler (see responseWriter), which an active stream keeps extending and a
// stalled one does not — the right tool for streaming, where a single
// absolute deadline is not.
func newProxyServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ReadTimeout:       0, // disabled: would cap slow/large request bodies
		WriteTimeout:      0, // disabled: would sever SSE / streaming responses
		ReadHeaderTimeout: proxyReadHeaderTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
}

// serverShutdowner is the subset of *http.Server that gracefulShutdown needs.
// Declared as an interface so the shutdown ordering can be unit-tested with a
// fake that records call order, without binding a real listener.
type serverShutdowner interface {
	Shutdown(ctx context.Context) error
}

// flusherStopper is the subset of *AccessLogger that gracefulShutdown needs.
type flusherStopper interface {
	StopFlusher(ctx context.Context)
}

// gracefulShutdown drains the main proxy server, THEN the metrics server, and
// only AFTER the proxy has drained stops the access-log flusher.
//
// The ordering is load-bearing for audit completeness: srv.Shutdown blocks
// until in-flight handlers return, and each finishing handler calls
// accessLog.Log()->enqueue(). If the flusher's final flush ran before the
// drain, those late entries would be appended to the batch after the last
// write and silently lost — exactly the deploy-boundary records a SIGTERM/
// rolling-deploy produces. Stopping the flusher after the drain guarantees
// its final flush observes every entry enqueued while draining.
func gracefulShutdown(ctx context.Context, srv, debugSrv serverShutdowner, accessLog flusherStopper) error {
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}
	accessLog.StopFlusher(ctx)

	if err := debugSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("metrics server shutdown: %w", err)
	}
	return nil
}

func newVersionCmd() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print the beyond version",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			_, _ = cmd.Root().Writer.Write([]byte(Version + "\n"))
			return nil
		},
	}
}
