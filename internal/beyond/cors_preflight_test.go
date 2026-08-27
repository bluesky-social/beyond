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

func newCORSPreflightTestHandler(t *testing.T) (*Handler, *recordingBackend) {
	t.Helper()
	backend := newRecordingBackend(t)
	cfg := testConfig()
	cfg.Applications["api"] = &Application{
		Name:                     "api",
		Upstream:                 backend.srv.URL,
		Host:                     "api.example.com",
		AllowedGroups:            []string{"engineering"},
		CORSPreflightPassthrough: true,
		BearerAuth: &BearerAuthConfig{
			Issuer:   "https://auth.example.com/application/o/api/",
			JWKSURL:  "http://authentik.example/application/o/api/jwks/",
			Audience: "api",
		},
	}
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	return NewHandler(cfg, testSessionManager(t), al), backend
}

func TestCORSPreflightPassthrough_DelegatesCredentialFreeProbe(t *testing.T) {
	t.Parallel()
	h, backend := newCORSPreflightTestHandler(t)
	req := httptest.NewRequest(http.MethodOptions, "/user", nil)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	req.Header.Set("X-Beyond-Email", "attacker@example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, backend.last)
	assert.Equal(t, "https://app.example.com", backend.last.Get("Origin"))
	assert.Empty(t, backend.last.Get("X-Beyond-Email"))
}

func TestCORSPreflightPassthrough_RejectsNonPreflightShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		method  string
		headers map[string]string
	}{
		{name: "not options", method: http.MethodGet, headers: map[string]string{"Origin": "https://app.example.com", "Access-Control-Request-Method": http.MethodGet}},
		{name: "missing origin", method: http.MethodOptions, headers: map[string]string{"Access-Control-Request-Method": http.MethodGet}},
		{name: "missing requested method", method: http.MethodOptions, headers: map[string]string{"Origin": "https://app.example.com"}},
		{name: "authorization present", method: http.MethodOptions, headers: map[string]string{"Origin": "https://app.example.com", "Access-Control-Request-Method": http.MethodGet, "Authorization": "Bearer invalid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, backend := newCORSPreflightTestHandler(t)
			req := httptest.NewRequest(tt.method, "/user", nil)
			req.Host = "api.example.com"
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.NotEqual(t, http.StatusOK, rec.Code)
			assert.Nil(t, backend.last)
		})
	}
}

func TestValidateCORSPreflightPassthroughRequiresBearerAuth(t *testing.T) {
	t.Parallel()
	configPath := writeTempFile(t, `
applications:
  api:
    upstream: http://api:3100
    host: api.example.com
    allowed_groups: [engineering]
    cors_preflight_passthrough: true
`)

	_, err := LoadConfig(configPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cors_preflight_passthrough requires bearer_auth")
}

func TestLoadConfig_CORSPreflightPassthrough(t *testing.T) {
	t.Parallel()
	configPath := writeTempFile(t, `
applications:
  api:
    upstream: http://api:3100
    host: api.example.com
    hide_from_portal: true
    allowed_groups: [engineering]
    bearer_auth:
      issuer: https://auth.example.com/application/o/api/
      jwks_url: http://authentik/application/o/api/jwks/
      audience: api
    cors_preflight_passthrough: true
`)

	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.True(t, cfg.Applications["api"].CORSPreflightPassthrough)
	assert.True(t, cfg.Applications["api"].HideFromPortal)
}
