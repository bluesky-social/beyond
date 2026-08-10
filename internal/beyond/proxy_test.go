package beyond

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseProxy_ForwardsRequest(t *testing.T) {
	t.Parallel()
	identity := &Identity{
		Email:  "alice@example.com",
		Name:   "Alice Example",
		Groups: []string{"engineering", "team-all"},
	}

	// Backend server asserts it receives the injected identity headers.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "alice@example.com", r.Header.Get("X-Beyond-User"))
		assert.Equal(t, "alice@example.com", r.Header.Get("X-Beyond-Email"))
		assert.Equal(t, "Alice Example", r.Header.Get("X-Beyond-Name"))
		assert.Equal(t, "engineering|team-all", r.Header.Get("X-Beyond-Groups"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, nil)

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello from backend", string(body))
}

func TestReverseProxy_StripsIncomingBeyondHeaders(t *testing.T) {
	t.Parallel()
	identity := &Identity{
		Email:  "real@example.com",
		Name:   "Real User",
		Groups: []string{"platform"},
	}

	// Backend must see the real identity, not the spoofed header.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "real@example.com", r.Header.Get("X-Beyond-User"))
		assert.Equal(t, "real@example.com", r.Header.Get("X-Beyond-Email"))
		assert.Equal(t, "Real User", r.Header.Get("X-Beyond-Name"))
		assert.Equal(t, "platform", r.Header.Get("X-Beyond-Groups"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Inject spoofed headers that must be stripped.
	req.Header.Set("X-Beyond-User", "attacker@evil.com")
	req.Header.Set("X-Beyond-Email", "attacker@evil.com")
	req.Header.Set("X-Beyond-Name", "Attacker Evil")
	req.Header.Set("X-Beyond-Groups", "authentik Admins")

	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, nil)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

func TestReverseProxy_InjectsApplicationRoleAfterStrippingSpoofedHeader(t *testing.T) {
	t.Parallel()
	identity := &Identity{
		Email:  "real@example.com",
		Name:   "Real User",
		Groups: []string{"engineering"},
	}
	app := &Application{
		Name: "grafana",
		GrafanaRoleProjection: &GrafanaRoleProjection{
			Header:      "X-Beyond-Role",
			DefaultRole: "Viewer",
			Rules: []GrafanaRoleRule{
				{Groups: []string{"platform"}, Role: "Admin"},
				{Groups: []string{"engineering"}, Role: "Editor"},
			},
		},
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Editor", r.Header.Get("X-Beyond-Role"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Beyond-Role", "Admin")

	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, app)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

// TestReverseProxy_ConnectionHeaderCannotEraseIdentity is the M-1 regression
// test. A client that names the injected identity headers in its `Connection:`
// token list must NOT be able to erase them: per RFC 7230 §6.1 the stdlib
// ReverseProxy deletes Connection-listed headers from the outbound request,
// but it does so BEFORE the Rewrite hook injects identity, so the upstream
// must still see the authoritative values.
func TestReverseProxy_ConnectionHeaderCannotEraseIdentity(t *testing.T) {
	t.Parallel()
	identity := &Identity{
		Email:  "alice@example.com",
		Name:   "Alice Example",
		Groups: []string{"engineering"},
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "alice@example.com", r.Header.Get("X-Beyond-User"))
		assert.Equal(t, "alice@example.com", r.Header.Get("X-Beyond-Email"))
		assert.Equal(t, "Alice Example", r.Header.Get("X-Beyond-Name"))
		assert.Equal(t, "engineering", r.Header.Get("X-Beyond-Groups"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Attacker names every injected identity header in Connection, attempting
	// to have the stdlib strip them before they reach the upstream.
	req.Header.Set("Connection", "X-Beyond-User, X-Beyond-Email, X-Beyond-Name, X-Beyond-Groups")

	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, nil)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

// TestReverseProxy_ConnectionHeaderCannotEraseProjectedRole guards the
// app-specific projected header (e.g. Grafana's X-Beyond-Role) against the
// same Connection-erasure: erasing it would silently downgrade the role and
// let Grafana fall back to auto_assign_org_role.
func TestReverseProxy_ConnectionHeaderCannotEraseProjectedRole(t *testing.T) {
	t.Parallel()
	identity := &Identity{
		Email:  "real@example.com",
		Groups: []string{"engineering"},
	}
	app := &Application{
		Name: "grafana",
		GrafanaRoleProjection: &GrafanaRoleProjection{
			Header:      "X-Beyond-Role",
			DefaultRole: "Viewer",
			Rules: []GrafanaRoleRule{
				{Groups: []string{"engineering"}, Role: "Editor"},
			},
		},
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Editor", r.Header.Get("X-Beyond-Role"))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Connection", "X-Beyond-Role")

	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, app)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

// TestReverseProxy_OverwritesForwardedHeaders is the M-9 regression test.
// beyond must forward authoritative X-Forwarded-* context (so upstreams build
// correct https URLs and Secure cookies) AND must overwrite, never preserve or
// append, a client-supplied value (anti-spoofing).
func TestReverseProxy_OverwritesForwardedHeaders(t *testing.T) {
	t.Parallel()
	identity := &Identity{Email: "alice@example.com", Groups: []string{"engineering"}}

	var gotProto, gotHost, gotFor string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotFor = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	req.RemoteAddr = "203.0.113.7:54321"
	// Client tries to spoof the forwarding chain.
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-For", "10.9.9.9")

	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, nil)

	assert.Equal(t, "https", gotProto, "X-Forwarded-Proto must be the authoritative https edge scheme")
	assert.Equal(t, "grafana.internal", gotHost, "X-Forwarded-Host must be the client-requested host")
	assert.Equal(t, "203.0.113.7", gotFor, "X-Forwarded-For must be RemoteAddr, overwriting any client value")
	assert.NotContains(t, gotFor, "10.9.9.9", "client-supplied X-Forwarded-For must not survive")
}

// TestReverseProxy_ScrubsBeyondSessionCookie is the L-5 regression test: the
// _beyond_session cookie (and the oidc-state cookie) must not reach upstreams,
// while unrelated cookies are preserved.
func TestReverseProxy_ScrubsBeyondSessionCookie(t *testing.T) {
	t.Parallel()
	identity := &Identity{Email: "alice@example.com", Groups: []string{"engineering"}}

	var gotCookie string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bp, err := newBeyondProxy(backend.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "secret-session-blob"})
	req.AddCookie(&http.Cookie{Name: "_beyond_oidc_state", Value: "state-blob"})
	req.AddCookie(&http.Cookie{Name: "app_pref", Value: "dark-mode"})

	rec := httptest.NewRecorder()
	bp.ServeHTTP(rec, req, identity, nil)

	assert.NotContains(t, gotCookie, "secret-session-blob", "_beyond_session must not reach the upstream")
	assert.NotContains(t, gotCookie, "state-blob", "_beyond_oidc_state must not reach the upstream")
	assert.Contains(t, gotCookie, "app_pref=dark-mode", "unrelated cookies must be preserved")
}

func TestProxyPool_CachesProxy(t *testing.T) {
	t.Parallel()
	pool := NewProxyPool()

	upstream := "http://localhost:9999"

	first, err := pool.Get(upstream)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := pool.Get(upstream)
	require.NoError(t, err)
	require.NotNil(t, second)

	// Same pointer must be returned – the pool caches by URL.
	assert.Same(t, first, second)
}

func TestProxyPool_Reset(t *testing.T) {
	t.Parallel()
	pool := NewProxyPool()

	first, err := pool.Get("http://localhost:9999")
	require.NoError(t, err)

	pool.Reset()

	// After reset, a new proxy instance should be created.
	second, err := pool.Get("http://localhost:9999")
	require.NoError(t, err)
	assert.NotSame(t, first, second, "Reset should evict cached proxies")
}
