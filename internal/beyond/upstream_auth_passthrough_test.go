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

var upstreamAuthPaths = []string{
	"/mcp",
	"/.well-known/oauth-protected-resource/mcp",
	"/.well-known/oauth-authorization-server",
	"/oauth/token",
}

func newUpstreamAuthPassthroughTestHandler(t *testing.T) (*Handler, *SessionManager, *recordingBackend) {
	t.Helper()
	backend := newRecordingBackend(t)
	cfg := testConfig()
	cfg.Applications["opaque-mcp"] = &Application{
		Name:                         "opaque-mcp",
		Upstream:                     backend.srv.URL,
		Host:                         "opaque-mcp.example.com",
		AllowedGroups:                []string{"engineering"},
		UpstreamAuthPassthroughPaths: upstreamAuthPaths,
	}

	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	return NewHandler(cfg, sm, al), sm, backend
}

func TestUpstreamAuthPassthrough_ExactPathsProxyBootstrapAndBearer(t *testing.T) {
	t.Parallel()
	for _, requestPath := range upstreamAuthPaths {
		for _, authorization := range []string{"", "Bearer opaque-token"} {
			t.Run(requestPath+authorization, func(t *testing.T) {
				t.Parallel()
				h, _, backend := newUpstreamAuthPassthroughTestHandler(t)
				req := httptest.NewRequest(http.MethodPost, requestPath+"?client=codex", nil)
				req.Host = "opaque-mcp.example.com"
				if authorization != "" {
					req.Header.Set("Authorization", authorization)
				}
				rec := httptest.NewRecorder()

				h.ServeHTTP(rec, req)

				assert.Equal(t, http.StatusOK, rec.Code)
				require.NotNil(t, backend.last)
				assert.Equal(t, authorization, backend.last.Get("Authorization"))
			})
		}
	}
}

func TestUpstreamAuthPassthrough_StripsIdentityAndIgnoresSession(t *testing.T) {
	t.Parallel()
	h, sm, backend := newUpstreamAuthPassthroughTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Host = "opaque-mcp.example.com"
	req.Header.Set("Authorization", "Bearer opaque-token")
	req.Header.Set("X-Beyond-Email", "attacker@example.com")
	req.Header.Set("X-Beyond-Groups", "authentik Admins")
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, backend.last)
	assert.Empty(t, backend.last.Get("X-Beyond-Email"))
	assert.Empty(t, backend.last.Get("X-Beyond-Groups"))
	assert.Equal(t, "Bearer opaque-token", backend.last.Get("Authorization"))
}

func TestUpstreamAuthPassthrough_RejectsIneligibleRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		path          string
		authorization string
	}{
		{name: "nearby path", path: "/mcp/tools", authorization: "Bearer opaque-token"},
		{name: "trailing slash", path: "/mcp/", authorization: "Bearer opaque-token"},
		{name: "escaped path", path: "/%6dcp", authorization: "Bearer opaque-token"},
		{name: "basic", path: "/mcp", authorization: "Basic abc"},
		{name: "empty bearer", path: "/mcp", authorization: "Bearer "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, _, backend := newUpstreamAuthPassthroughTestHandler(t)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Host = "opaque-mcp.example.com"
			req.Header.Set("Authorization", tt.authorization)
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.NotEqual(t, http.StatusOK, rec.Code)
			assert.Nil(t, backend.last)
		})
	}
}

func TestValidateUpstreamAuthPassthroughPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		paths       []string
		errContains string
	}{
		{name: "nil"},
		{name: "canonical", paths: []string{"/mcp", "/oauth/token"}},
		{name: "rejects root", paths: []string{"/"}, errContains: "root"},
		{name: "rejects relative", paths: []string{"mcp"}, errContains: "absolute path"},
		{name: "rejects trailing slash", paths: []string{"/mcp/"}, errContains: "canonical literal path"},
		{name: "rejects traversal", paths: []string{"/oauth/../mcp"}, errContains: "canonical literal path"},
		{name: "rejects query", paths: []string{"/mcp?x=1"}, errContains: "canonical literal path"},
		{name: "rejects escaped path", paths: []string{"/%6dcp"}, errContains: "canonical literal path"},
		{name: "rejects duplicate", paths: []string{"/mcp", "/mcp"}, errContains: "duplicates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app := &Application{UpstreamAuthPassthroughPaths: tt.paths}
			err := validateUpstreamAuthPassthroughPaths("opaque-mcp", app)
			if tt.errContains == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}

func TestLoadConfig_UpstreamAuthPassthroughPaths(t *testing.T) {
	t.Parallel()
	configPath := writeTempFile(t, `
applications:
  opaque-mcp:
    upstream: http://agent-gateway:4011
    host: opaque-mcp.example.com
    allowed_groups: [engineering]
    upstream_auth_passthrough_paths:
      - /mcp
      - /.well-known/oauth-protected-resource/mcp
`)
	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"/mcp", "/.well-known/oauth-protected-resource/mcp"},
		cfg.Applications["opaque-mcp"].UpstreamAuthPassthroughPaths)
}
