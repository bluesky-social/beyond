package beyond

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mcpBootstrapPaths = []string{
	"/mcp",
	"/.well-known/oauth-protected-resource/mcp",
	"/.well-known/oauth-authorization-server/mcp",
	"/.well-known/oauth-authorization-server/mcp/token",
	"/.well-known/oauth-authorization-server/mcp/client-registration",
}

func newUnauthenticatedPassthroughTestHandler(t *testing.T) (*Handler, *SessionManager, *recordingBackend) {
	t.Helper()
	backend := newRecordingBackend(t)
	cfg := testConfig()
	cfg.Applications["mcp"] = &Application{
		Name:          "mcp",
		Upstream:      backend.srv.URL,
		Host:          "mcp.example.com",
		AllowedGroups: []string{"engineering"},
		BearerAuth: &BearerAuthConfig{
			Issuer:   "https://auth.example.com/application/o/mcp/",
			JWKSURL:  "http://authentik.example/application/o/mcp/jwks/",
			Audience: "mcp",
		},
		UnauthenticatedPassthroughPaths: mcpBootstrapPaths,
	}

	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	return NewHandler(cfg, sm, al), sm, backend
}

func TestUnauthenticatedPassthrough_ExactBootstrapPathsProxy(t *testing.T) {
	t.Parallel()
	for _, requestPath := range mcpBootstrapPaths {
		t.Run(requestPath, func(t *testing.T) {
			t.Parallel()
			h, _, backend := newUnauthenticatedPassthroughTestHandler(t)
			req := httptest.NewRequest(http.MethodGet, requestPath+"?client=codex", nil)
			req.Host = "mcp.example.com"
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			require.NotNil(t, backend.last)
			assert.Empty(t, backend.last.Get("Authorization"))
		})
	}
}

func TestUnauthenticatedPassthrough_IgnoresBrowserSessionAndStripsIdentitySpoofs(t *testing.T) {
	t.Parallel()
	h, sm, backend := newUnauthenticatedPassthroughTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Host = "mcp.example.com"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	req.Header.Set("X-Beyond-Email", "attacker@example.com")
	req.Header.Set("X-Beyond-Groups", "authentik Admins")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, backend.last.Get("X-Beyond-Email"))
	assert.Empty(t, backend.last.Get("X-Beyond-Groups"))
}

func TestUnauthenticatedPassthrough_AuthorizationNeverBypassesBearerAuth(t *testing.T) {
	t.Parallel()
	h, _, backend := newUnauthenticatedPassthroughTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Host = "mcp.example.com"
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Nil(t, backend.last, "invalid bearer token must not reach the delegated upstream path")
}

func TestUnauthenticatedPassthrough_NearbyAndEscapedPathsDoNotMatch(t *testing.T) {
	t.Parallel()
	tests := []string{
		"/mcp/",
		"/mcp/tools",
		"/%6dcp",
		"/.well-known/oauth-protected-resource/mcp/extra",
	}
	for _, requestPath := range tests {
		t.Run(requestPath, func(t *testing.T) {
			t.Parallel()
			h, _, backend := newUnauthenticatedPassthroughTestHandler(t)
			req := httptest.NewRequest(http.MethodGet, requestPath, nil)
			req.Host = "mcp.example.com"
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Nil(t, backend.last)
		})
	}
}

func TestValidateUnauthenticatedPassthroughPaths(t *testing.T) {
	t.Parallel()
	bearer := &BearerAuthConfig{Issuer: "https://issuer", JWKSURL: "http://jwks", Audience: "mcp"}
	tests := []struct {
		name        string
		paths       []string
		withBearer  bool
		errContains string
	}{
		{name: "nil", paths: nil},
		{name: "canonical", paths: []string{"/mcp", "/.well-known/oauth-protected-resource/mcp"}, withBearer: true},
		{name: "requires bearer auth", paths: []string{"/mcp"}, errContains: "requires bearer_auth"},
		{name: "rejects root", paths: []string{"/"}, withBearer: true, errContains: "root"},
		{name: "rejects relative", paths: []string{"mcp"}, withBearer: true, errContains: "absolute path"},
		{name: "rejects trailing slash", paths: []string{"/mcp/"}, withBearer: true, errContains: "canonical literal path"},
		{name: "rejects traversal", paths: []string{"/oauth/../mcp"}, withBearer: true, errContains: "canonical literal path"},
		{name: "rejects query", paths: []string{"/mcp?x=1"}, withBearer: true, errContains: "canonical literal path"},
		{name: "rejects escaped path", paths: []string{"/%6dcp"}, withBearer: true, errContains: "canonical literal path"},
		{name: "rejects duplicate", paths: []string{"/mcp", "/mcp"}, withBearer: true, errContains: "duplicates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app := &Application{UnauthenticatedPassthroughPaths: tt.paths}
			if tt.withBearer {
				app.BearerAuth = bearer
			}
			err := validateUnauthenticatedPassthroughPaths("mcp", app)
			if tt.errContains == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

func TestLoadConfig_UnauthenticatedPassthroughPaths(t *testing.T) {
	t.Parallel()
	configPath := writeTempFile(t, `
applications:
  mcp:
    upstream: http://agent-gateway:4004
    host: mcp.example.com
    allowed_groups: [engineering]
    bearer_auth:
      issuer: https://auth.example.com/application/o/mcp/
      jwks_url: http://authentik/application/o/mcp/jwks/
      audience: mcp
    unauthenticated_passthrough_paths:
      - /mcp
      - /.well-known/oauth-protected-resource/mcp
`)
	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"/mcp", "/.well-known/oauth-protected-resource/mcp"},
		cfg.Applications["mcp"].UnauthenticatedPassthroughPaths)
}
