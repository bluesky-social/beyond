package beyond

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPassthroughTestHandler builds a Handler with a "netbox" app that has
// passthrough_auth_schemes: ["Token"], plus the standard testConfig apps.
// Returns the handler and a recording backend.
func newPassthroughTestHandler(t *testing.T) (*Handler, *recordingBackend) {
	t.Helper()
	backend := newRecordingBackend(t)

	cfg := testConfig()
	cfg.Applications["netbox"] = &Application{
		Name:                   "netbox",
		Upstream:               backend.srv.URL,
		Host:                   "netbox.example.com",
		AllowedGroups:          []string{"engineering"},
		PassthroughAuthSchemes: []string{"Token"},
	}

	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	h := NewHandler(cfg, sm, al)
	return h, backend
}

func passthroughReq(host, authHeader string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/dcim/devices/", nil)
	req.Host = host
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return req
}

// TestPassthrough_TokenSchemeProxies verifies that a "Token <value>" header
// on a passthrough-enabled app reaches the upstream with the Authorization
// header intact.
func TestPassthrough_TokenSchemeProxies(t *testing.T) {
	t.Parallel()
	h, backend := newPassthroughTestHandler(t)

	req := passthroughReq("netbox.example.com", "Token abc123def456")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
	// Authorization header forwarded unchanged.
	assert.Equal(t, "Token abc123def456", backend.last.Get("Authorization"))
}

// TestPassthrough_CaseInsensitiveScheme verifies that "token" (lowercase)
// matches a configured scheme of "Token".
func TestPassthrough_CaseInsensitiveScheme(t *testing.T) {
	t.Parallel()
	h, backend := newPassthroughTestHandler(t)

	req := passthroughReq("netbox.example.com", "token abc123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
	assert.Equal(t, "token abc123", backend.last.Get("Authorization"))
}

// TestPassthrough_NoConfigFallsThrough verifies that a "Token" header on an
// app without passthrough_auth_schemes configured does not get proxied
// through the passthrough path — it falls through to the normal session/OIDC
// flow and gets a 401 (no OIDC configured in test handler).
func TestPassthrough_NoConfigFallsThrough(t *testing.T) {
	t.Parallel()
	h, _ := newPassthroughTestHandler(t)

	// grafana is in testConfig() with no passthrough_auth_schemes.
	req := passthroughReq("grafana.internal", "Token abc123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// No passthrough → no session → no OIDC → 401.
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

// TestPassthrough_AbsentHeaderFallsThrough verifies that a request with no
// Authorization header to a passthrough-enabled app falls through to the
// normal unauthenticated path (401, since no OIDC is configured).
func TestPassthrough_AbsentHeaderFallsThrough(t *testing.T) {
	t.Parallel()
	h, _ := newPassthroughTestHandler(t)

	req := passthroughReq("netbox.example.com", "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

// TestPassthrough_StripesSpoofedIdentityHeaders verifies that a client cannot
// smuggle X-Beyond-* headers through the passthrough path.
func TestPassthrough_StripsSpoofedIdentityHeaders(t *testing.T) {
	t.Parallel()
	h, backend := newPassthroughTestHandler(t)

	req := passthroughReq("netbox.example.com", "Token abc123")
	req.Header.Set("X-Beyond-Email", "attacker@evil.com")
	req.Header.Set("X-Beyond-Groups", "authentik Admins")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Result().StatusCode)
	assert.Empty(t, backend.last.Get("X-Beyond-Email"), "spoofed X-Beyond-Email must be stripped")
	assert.Empty(t, backend.last.Get("X-Beyond-Groups"), "spoofed X-Beyond-Groups must be stripped")
	// Authorization must still be forwarded.
	assert.Equal(t, "Token abc123", backend.last.Get("Authorization"))
}

// TestPassthroughScheme_ExtractsScheme tests the passthroughScheme helper.
func TestPassthroughScheme_ExtractsScheme(t *testing.T) {
	t.Parallel()

	app := &Application{
		PassthroughAuthSchemes: []string{"Token"},
	}

	tests := []struct {
		name       string
		authHeader string
		wantScheme string
	}{
		{"token matches", "Token abc123", "Token"},
		{"lowercase matches", "token abc123", "token"},
		{"bearer not matched", "Bearer eyJhb...", ""},
		{"empty header", "", ""},
		{"scheme only no space", "Token", "Token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			scheme, _ := passthroughScheme(req, app)
			assert.Equal(t, tt.wantScheme, scheme)
		})
	}
}

// TestPassthroughScheme_NilApp verifies that passthroughScheme is safe when
// the app is nil (unknown host).
func TestPassthroughScheme_NilApp(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc123")
	scheme, _ := passthroughScheme(req, nil)
	assert.Empty(t, scheme)
}

// TestPassthroughScheme_NoSchemes verifies that passthroughScheme returns ""
// when the app has no passthrough schemes configured.
func TestPassthroughScheme_NoSchemes(t *testing.T) {
	t.Parallel()
	app := &Application{PassthroughAuthSchemes: nil}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc123")
	scheme, _ := passthroughScheme(req, app)
	assert.Empty(t, scheme)
}

// TestValidatePassthroughAuthSchemes covers the config validation rules.
func TestValidatePassthroughAuthSchemes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		schemes     []string
		wantErr     bool
		errContains string
	}{
		{"nil is valid", nil, false, ""},
		{"empty slice is valid", []string{}, false, ""},
		{"Token is valid", []string{"Token"}, false, ""},
		{"multiple valid schemes", []string{"Token", "ApiKey"}, false, ""},
		{"Bearer rejected", []string{"Bearer"}, true, "Bearer"},
		{"bearer lowercase rejected", []string{"bearer"}, true, "Bearer"},
		{"empty string rejected", []string{""}, true, "empty"},
		{"whitespace in scheme rejected", []string{"My Token"}, true, "whitespace"},
		{"tab in scheme rejected", []string{"My\tToken"}, true, "whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePassthroughAuthSchemes("testapp", tt.schemes)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, strings.Contains(err.Error(), tt.errContains),
					"error %q should contain %q", err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidatePassthroughAuthSchemes_InConfig verifies the config validation
// integration: a config with passthrough_auth_schemes containing "Bearer"
// must be rejected at load time.
func TestValidatePassthroughAuthSchemes_InConfig(t *testing.T) {
	t.Parallel()

	yaml := `
applications:
  netbox:
    upstream: http://localhost:8080
    host: netbox.example.com
    allowed_groups:
      - eng
    passthrough_auth_schemes:
      - Bearer
`
	path := writeTempFile(t, yaml)
	_, err := LoadConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Bearer")
}
