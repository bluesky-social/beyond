package beyond

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestHandler creates a Handler backed by a test config. If backend is
// non-nil, application upstreams are overridden to point at backend.URL.
// Returns the handler and session manager so callers can set sessions.
func newTestHandler(t *testing.T, backend *httptest.Server) (*Handler, *SessionManager) {
	t.Helper()

	cfg := testConfig()

	// Override upstreams to point at the test backend.
	if backend != nil {
		for _, app := range cfg.Applications {
			app.Upstream = backend.URL
		}
	}

	sm := testSessionManager(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	al := &AccessLogger{Logger: logger}

	h := NewHandler(cfg, sm, al)
	return h, sm
}

// setSession saves a session cookie and adds it to req so that the handler
// will see the request as authenticated.
func setSession(t *testing.T, sm *SessionManager, req *http.Request, email string, groups []string) {
	t.Helper()

	data := &SessionData{
		Email:     email,
		Groups:    groups,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	rec := httptest.NewRecorder()
	require.NoError(t, sm.Save(rec, data))

	cookie := cookieFromRecorder(t, rec, sessionCookieName)
	require.NotNil(t, cookie, "session cookie must be set")
	req.AddCookie(cookie)
}

func TestHandler_HealthCheck(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
}

func TestHandler_UnauthenticatedRequest_Returns401(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

func TestHandler_AuthenticatedRequest(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from grafana"))
	}))
	defer backend.Close()

	h, sm := newTestHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello from grafana", string(body))
}

func TestHandler_ForbiddenRequest(t *testing.T) {
	t.Parallel()
	h, sm := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "argocd.internal"
	// engineering user cannot access argocd (only "platform" is allowed).
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
}

func TestHandler_UnknownHost(t *testing.T) {
	t.Parallel()
	h, sm := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "unknown.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Result().StatusCode)
}

func TestHandler_StripPort(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "grafana.internal", stripPort("grafana.internal:443"))
	assert.Equal(t, "grafana.internal", stripPort("grafana.internal"))
}

func TestHandler_SourceIP(t *testing.T) {
	t.Parallel()
	// X-Forwarded-For is not trusted — RemoteAddr is always used.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	// httptest.NewRequest sets RemoteAddr to "192.0.2.1:1234".
	assert.Equal(t, "192.0.2.1", sourceIP(req), "XFF must be ignored; RemoteAddr should be used")

	// Explicit RemoteAddr.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	assert.Equal(t, "192.168.1.1", sourceIP(req2))
}

func TestHandler_ReloadConfig(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	h, sm := newTestHandler(t, backend)

	// Before reload: grafana.internal is known.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)

	// Reload with a config that removes grafana.
	newCfg := &Config{
		AdminGroups: []string{"authentik Admins"},
		Sessions:    SessionConfig{HTTPLifetime: time.Hour},
		Applications: map[string]*Application{
			"argocd": {
				Name:          "argocd",
				Upstream:      backend.URL,
				Host:          "argocd.internal",
				AllowedGroups: []string{"platform"},
			},
		},
	}
	h.ReloadConfig(newCfg)

	// After reload: grafana.internal should be unknown (404).
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "grafana.internal"
	setSession(t, sm, req2, "alice@example.com", []string{"engineering"})

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusNotFound, rec2.Result().StatusCode)
}

// TestSanitizeRedirectPath is the L-1 regression test: the post-login redirect
// guard must reject protocol-relative and absolute URLs, not just non-"/"
// prefixes.
func TestSanitizeRedirectPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		// Safe same-origin paths pass through unchanged.
		{"/dashboard", "/dashboard"},
		{"/a/b?x=1#frag", "/a/b?x=1#frag"},
		{"/", "/"},
		// Protocol-relative and backslash tricks must be neutralized.
		{"//evil.com", "/"},
		{"//evil.com/steal", "/"},
		{`/\evil.com`, "/"},
		{`/\/evil.com`, "/"},
		// Absolute URLs must be neutralized.
		{"https://evil.com", "/"},
		{"http://evil.com/x", "/"},
		// Non-rooted / empty.
		{"dashboard", "/"},
		{"", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, sanitizeRedirectPath(tt.in))
		})
	}
}

// TestHandler_OIDCCallback_NilOIDCAuth is the L-13 guard: the callback route
// must not panic when OIDC is unconfigured.
func TestHandler_OIDCCallback_NilOIDCAuth(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t, nil) // no SetOIDCAuth

	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?code=x&state=y", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "callback with OIDC unconfigured must 404, not panic")
}

func TestHandler_OIDCRedirect(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	cfg := OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	auth, err := NewOIDCAuth(context.Background(), cfg)
	require.NoError(t, err)

	h, _ := newTestHandler(t, nil)
	h.SetOIDCAuth(auth)

	// Make an unauthenticated request to a known host.
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "grafana.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "Location header must be set for OIDC redirect")

	u, err := url.Parse(loc)
	require.NoError(t, err)

	q := u.Query()
	assert.Equal(t, "test-client", q.Get("client_id"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.NotEmpty(t, q.Get("code_challenge"), "code_challenge must be present")
	assert.Equal(t, "S256", q.Get("code_challenge_method"))

	// The redirect_uri must be dynamically derived from the request host.
	assert.Equal(t, "https://grafana.internal/oidc/callback", q.Get("redirect_uri"),
		"redirect_uri must be derived from the request Host header")

	// Verify the state cookie was set.
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "_beyond_oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "OIDC state cookie must be set")
	assert.True(t, stateCookie.HttpOnly)

	// The cookie value must be an encrypted blob, not plaintext.
	assert.NotContains(t, stateCookie.Value, "/dashboard",
		"state cookie must not contain plaintext original URL")
}

// TestHandler_OIDCRedirect_UnknownHostReturns404 is the M-8 regression test:
// an unauthenticated request for a host beyond does not serve must NOT start
// the OIDC flow (which would build a redirect_uri from the arbitrary Host
// header). It must 404 before any redirect or state cookie is emitted.
func TestHandler_OIDCRedirect_UnknownHostReturns404(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	h, _ := newTestHandler(t, nil)
	h.SetOIDCAuth(auth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "evil.attacker.example" // not in testConfig()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"unconfigured host must 404, not start the OIDC flow")
	assert.Empty(t, resp.Header.Get("Location"),
		"no OIDC redirect may be emitted for an unconfigured host")
	for _, c := range resp.Cookies() {
		assert.NotEqual(t, "_beyond_oidc_state", c.Name,
			"no OIDC state cookie may be set for an unconfigured host")
	}
}

// TestHandler_IdentityPropagation_OIDCToUpstreamHeaders drives the full
// Beyond request lifecycle:
//
//  1. An unauthenticated request hits beyond for a protected host.
//  2. Beyond redirects to the OIDC provider and stores encrypted state.
//  3. The (mock) OIDC provider validates the code and mints an id_token
//     with name/email/groups claims.
//  4. Beyond validates and normalizes those claims (identity.go), stores
//     them in a session cookie, and redirects back to the original URL.
//  5. A follow-up request carrying the session cookie reaches beyond,
//     which injects the identity headers onto the request before
//     proxying it to the upstream.
//
// The upstream server asserts that every expected X-Beyond-* header is
// present with the correct value. This is the only test that exercises
// the complete name-propagation chain — oidc → validateAndNormalizeIdentity
// → SessionData → Load → Identity → injectBeyondHeaders — in one go, and
// is what catches regressions at any seam between those layers.
func TestHandler_IdentityPropagation_OIDCToUpstreamHeaders(t *testing.T) {
	t.Parallel()

	// Upstream records whatever identity headers it received.
	type observed struct {
		user, email, name, groups, role string
	}
	var got observed
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = observed{
			user:   r.Header.Get("X-Beyond-User"),
			email:  r.Header.Get("X-Beyond-Email"),
			name:   r.Header.Get("X-Beyond-Name"),
			groups: r.Header.Get("X-Beyond-Groups"),
			role:   r.Header.Get("X-Beyond-Role"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Mock OIDC provider returning a known name claim. Use a per-test claims
	// map (held by reference) so we can inject the nonce beyond generated into
	// the id_token before the callback fetches it.
	claims := map[string]any{
		"email":  "alice@example.com",
		"name":   "Alice Example",
		"groups": []string{"engineering", "team-all"},
	}
	oidcSrv, _ := mockOIDCProviderWithClaims(t, claims)
	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    oidcSrv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	h, _ := newTestHandler(t, backend)
	h.SetOIDCAuth(auth)

	// 1) Unauthenticated request triggers the OIDC redirect and state cookie.
	initialReq := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	initialReq.Host = "grafana.internal"
	initialRec := httptest.NewRecorder()
	h.ServeHTTP(initialRec, initialReq)
	require.Equal(t, http.StatusFound, initialRec.Code)

	var stateCookie *http.Cookie
	for _, c := range initialRec.Result().Cookies() {
		if c.Name == "_beyond_oidc_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "OIDC state cookie must be set")

	// Decrypt the state cookie to recover the state and nonce beyond
	// generated, so we can construct a matching callback URL and have the mock
	// id_token echo the expected nonce.
	state, _, nonce, _, err := h.decryptOIDCState(stateCookie.Value)
	require.NoError(t, err)
	claims["nonce"] = nonce

	// 2) OIDC provider redirected the user back to beyond's callback.
	//    Simulate that request, including the state cookie we just got.
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		"/oidc/callback?code=valid-code&state="+url.QueryEscape(state),
		nil,
	)
	callbackReq.Host = "grafana.internal"
	callbackReq.AddCookie(stateCookie)
	callbackRec := httptest.NewRecorder()
	h.ServeHTTP(callbackRec, callbackReq)
	require.Equal(t, http.StatusFound, callbackRec.Code, "OIDC callback should redirect back to original URL")

	var sessionCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	require.NotNil(t, sessionCookie, "successful OIDC callback must set a session cookie")

	// 3) Follow-up authenticated request — should proxy to the upstream
	//    backend with all identity headers injected.
	protectedReq := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	protectedReq.Host = "grafana.internal"
	protectedReq.AddCookie(sessionCookie)
	protectedRec := httptest.NewRecorder()
	h.ServeHTTP(protectedRec, protectedReq)
	require.Equal(t, http.StatusOK, protectedRec.Code)

	assert.Equal(t, "alice@example.com", got.user, "X-Beyond-User must carry the email")
	assert.Equal(t, "alice@example.com", got.email, "X-Beyond-Email must carry the email")
	assert.Equal(t, "Alice Example", got.name,
		"X-Beyond-Name must carry the `name` claim from the id_token — if this fails, "+
			"the name is being dropped somewhere between OIDC claim extraction, session "+
			"storage, and header injection")
	assert.Equal(t, "engineering|team-all", got.groups,
		"X-Beyond-Groups must carry the joined groups claim")
	assert.Equal(t, "Editor", got.role,
		"X-Beyond-Role must carry the app-specific Grafana role projected from groups")
}

func TestHandler_OIDCRedirect_DifferentHosts(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	h, _ := newTestHandler(t, nil)
	h.SetOIDCAuth(auth)

	// Two different application hosts should produce different redirect_uri values
	// in their OIDC login redirects.
	tests := []struct {
		host        string
		expectedURI string
	}{
		{"grafana.internal", "https://grafana.internal/oidc/callback"},
		{"argocd.internal", "https://argocd.internal/oidc/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			require.Equal(t, http.StatusFound, rec.Code)
			loc := rec.Header().Get("Location")
			u, err := url.Parse(loc)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedURI, u.Query().Get("redirect_uri"))
		})
	}
}

func TestHandler_OIDCStateCookie_Encrypted(t *testing.T) {
	t.Parallel()
	h, sm := newTestHandler(t, nil)

	// Encrypt a state cookie.
	encrypted, err := h.encryptOIDCState("test-state", "test-verifier", "test-nonce", "/original")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// The value should not contain any plaintext fields.
	assert.NotContains(t, encrypted, "test-state")
	assert.NotContains(t, encrypted, "test-verifier")
	assert.NotContains(t, encrypted, "/original")

	// Decrypt should recover the original values.
	state, verifier, _, originalURL, err := h.decryptOIDCState(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "test-state", state)
	assert.Equal(t, "test-verifier", verifier)
	assert.Equal(t, "/original", originalURL)

	// Tampered ciphertext should fail.
	_, _, _, _, err = h.decryptOIDCState(encrypted + "tampered")
	assert.Error(t, err, "tampered cookie must be rejected")

	// Completely bogus value should fail.
	_, _, _, _, err = h.decryptOIDCState("not-a-real-cookie")
	assert.Error(t, err, "bogus cookie must be rejected")

	// Empty value should fail.
	_, _, _, _, err = h.decryptOIDCState("")
	assert.Error(t, err, "empty cookie must be rejected")

	// A token of a different type (cookie) must fail the OIDC-state type check.
	sessToken, err := sm.EncryptToken(&SessionData{
		Type:      tokenTypeCookie,
		Email:     "user@example.com",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	_, _, _, _, err = h.decryptOIDCState(sessToken)
	assert.Error(t, err, "a non-OIDC-state token must not be accepted as OIDC state")
}

func TestHandler_OIDCStateCookie_Expired(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t, nil)

	data := &SessionData{
		Type:            tokenTypeOIDCState,
		OIDCState:       "test-state",
		OIDCVerifier:    "test-verifier",
		OIDCOriginalURL: "/original",
		ExpiresAt:       time.Now().Add(-1 * time.Minute), // already expired
	}
	token, err := h.sessions.EncryptToken(data)
	require.NoError(t, err)

	_, _, _, _, err = h.decryptOIDCState(token)
	assert.Error(t, err, "expired OIDC state cookie must be rejected")
}

func TestHandler_SecurityHeaders(t *testing.T) {
	t.Parallel()
	h, sm := newTestHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=")
	assert.Equal(t, "default-src 'none'", resp.Header.Get("Content-Security-Policy"))
	assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
}

func TestHandler_SecurityHeaders_OnErrorResponses(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t, nil)

	// Unauthenticated request — should still have security headers.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
}

func TestHandler_DeactivatedUser_HTTP(t *testing.T) {
	t.Parallel()
	// Create a fake Authentik that says alice is deactivated.
	authentikSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := authentikUserResponse{
			Results: []authentikUserRow{{IsActive: false}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer authentikSrv.Close()

	h, sm := newTestHandler(t, nil)
	h.SetUserValidator(NewUserValidator(authentikSrv.URL, "token"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "deactivated")
}

func TestHandler_ActiveUser_PassesThrough(t *testing.T) {
	t.Parallel()
	// Fake Authentik: alice is active and in the allowed "engineering" group
	// (the re-resolved set now drives the decision, so it must reflect her
	// real membership).
	authentikSrv := fakeAuthentikServerWithGroups(t, "engineering")
	defer authentikSrv.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	h, sm := newTestHandler(t, backend)
	h.SetUserValidator(NewUserValidator(authentikSrv.URL, "token"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandler_FreshGroupGrantsAccess is an M-3 regression test: a session
// frozen with a non-allowed group is granted access when Authentik now reports
// the user in an allowed group. The authZ decision must use the re-resolved
// groups, not the stale session set.
func TestHandler_FreshGroupGrantsAccess(t *testing.T) {
	t.Parallel()
	// Authentik now reports the user in "engineering" (grafana's allowed group).
	authentikSrv := fakeAuthentikServerWithGroups(t, "engineering")
	defer authentikSrv.Close()

	var sawGroups string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawGroups = r.Header.Get("X-Beyond-Groups")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h, sm := newTestHandler(t, backend)
	h.SetUserValidator(NewUserValidator(authentikSrv.URL, "token"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	// Session was minted BEFORE the user joined engineering — frozen group is
	// not allowed for grafana.
	setSession(t, sm, req, "alice@example.com", []string{"newcomers"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "fresh engineering membership must grant access despite stale session group")
	assert.Equal(t, "engineering", sawGroups, "upstream must see the freshly-resolved groups, not the frozen session set")
}

// TestHandler_RevokedGroupDeniesAccess is the complementary M-3 case: a session
// frozen with an allowed group is denied once Authentik no longer reports that
// group, even while the account stays active.
func TestHandler_RevokedGroupDeniesAccess(t *testing.T) {
	t.Parallel()
	// Active, but no longer in "engineering" — only some unrelated group.
	authentikSrv := fakeAuthentikServerWithGroups(t, "marketing")
	defer authentikSrv.Close()

	h, sm := newTestHandler(t, nil)
	h.SetUserValidator(NewUserValidator(authentikSrv.URL, "token"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	// Session still carries the now-revoked allowed group.
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"a group revoked in Authentik must deny within the cache TTL despite the frozen session group")
}

// TestHandler_RevokedFromAllGroupsDeniesAccess is the PR-review regression
// test for the M-3 empty-groups gap: an active user removed from EVERY group
// (so Authentik returns an empty set) must be denied, not fall back to the
// login-frozen session groups that still contain the allowed group.
func TestHandler_RevokedFromAllGroupsDeniesAccess(t *testing.T) {
	t.Parallel()
	// Active, but now in zero groups.
	authentikSrv := fakeAuthentikServerWithGroups(t) // no groups
	defer authentikSrv.Close()

	h, sm := newTestHandler(t, nil)
	h.SetUserValidator(NewUserValidator(authentikSrv.URL, "token"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	// Session still carries the allowed group from login.
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"removal from all groups must deny within the cache TTL, not fall back to frozen session groups")
}

// TestHandler_AuthentikErrorFailsClosed documents the API-error path: a
// transient Authentik error makes Resolve report (active=false, ok=false), so
// the active gate (the load-bearing revocation control) denies with a
// "deactivated" response. The handler's ok==false group-fallback branch is
// defensive — it is not reached here because the active gate fires first — but
// this pins the user-visible fail-closed behavior on a blip.
func TestHandler_AuthentikErrorFailsClosed(t *testing.T) {
	t.Parallel()
	authentikSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer authentikSrv.Close()

	h, sm := newTestHandler(t, nil)
	h.SetUserValidator(NewUserValidator(authentikSrv.URL, "token"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "deactivated")
}

func TestHandler_MetricsNotServed(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("from upstream"))
	}))
	defer backend.Close()

	h, sm := newTestHandler(t, backend)

	// Unauthenticated: should get 401, not Prometheus metrics.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.NotContains(t, rec.Body.String(), "promhttp", "/metrics must not expose Prometheus data")

	// Authenticated on a known host: /metrics is proxied to upstream, not
	// served by beyond.
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req2.Host = "grafana.internal"
	setSession(t, sm, req2, "alice@example.com", []string{"engineering"})
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "from upstream", rec2.Body.String(), "/metrics on known host should proxy to upstream")
}

func TestHandler_SecurityHeaders_NotOnProxiedResponse(t *testing.T) {
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream sets its own security headers.
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	h, sm := newTestHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Upstream headers must be preserved, not overwritten by beyond.
	assert.Equal(t, "SAMEORIGIN", resp.Header.Get("X-Frame-Options"),
		"upstream X-Frame-Options must be preserved")
	assert.Equal(t, "default-src 'self'", resp.Header.Get("Content-Security-Policy"),
		"upstream CSP must be preserved")

	// HSTS is set by beyond on all responses (transport-level).
	assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=")
}

func TestHandler_OIDCRateLimit(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)
	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	h, _ := newTestHandler(t, nil)
	h.SetOIDCAuth(auth)
	h.oidcLimiter = newIPRateLimiter(2, time.Minute) // low limit for testing

	// First two requests should redirect.
	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "grafana.internal"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusFound, rec.Code, "request %d should redirect", i+1)
	}

	// Third request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestOIDCRedirectURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host     string
		expected string
	}{
		{"grafana.example.com", "https://grafana.example.com/oidc/callback"},
		{"argocd.example.com", "https://argocd.example.com/oidc/callback"},
		{"beyond.example.net", "https://beyond.example.net/oidc/callback"},
		// Host with port — preserved as-is in the redirect URL.
		{"grafana.example.com:8443", "https://grafana.example.com:8443/oidc/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = tt.host
			assert.Equal(t, tt.expected, oidcRedirectURL(r))
		})
	}
}

func TestResponseWriter_Unwrap(t *testing.T) {
	t.Parallel()
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}
	assert.Equal(t, inner, rw.Unwrap(), "Unwrap must return the underlying ResponseWriter")
}
