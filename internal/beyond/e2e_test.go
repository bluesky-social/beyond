package beyond

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// ---------------------------------------------------------------------------
// Shared OIDC provider — discovery is the slowest part of E2E test setup
// (~190ms per call to Authentik). We do it once and reuse the provider.
// ---------------------------------------------------------------------------

const authentikURL = "http://localhost:9000"

var (
	sharedOIDCProvider     *oidc.Provider
	sharedOIDCProviderOnce sync.Once
	authentikAvailable     bool
)

func initOIDCProvider() {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(authentikURL + "/-/health/ready/")
	if err != nil {
		return
	}
	_ = resp.Body.Close()

	provider, err := oidc.NewProvider(context.Background(), authentikURL+"/application/o/beyond-dev/")
	if err != nil {
		return
	}
	sharedOIDCProvider = provider
	authentikAvailable = true
}

// ---------------------------------------------------------------------------
// beyondServer — spins up an in-process beyond backed by real Authentik.
// ---------------------------------------------------------------------------

func beyondServer(t *testing.T) *httptest.Server {
	t.Helper()

	sharedOIDCProviderOnce.Do(initOIDCProvider)
	if !authentikAvailable {
		t.Skipf("Authentik not reachable at %s (run `just up`)", authentikURL)
	}

	sm, err := NewSessionManager([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 12*time.Hour)
	require.NoError(t, err)

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	accessLog := &AccessLogger{Logger: logger}
	if os.Getenv("BEYOND_DB_URL") != "" {
		// Reuse the shared DB migration from ensureDB.
		db := ensureDB(t)
		accessLog.DB = db
	}

	cfg := &Config{
		Sessions:    SessionConfig{HTTPLifetime: 12 * time.Hour},
		AdminGroups: []string{"authentik Admins"},
		Applications: map[string]*Application{
			"echo": {Name: "echo", Upstream: "http://localhost:18080", Host: "PLACEHOLDER", AllowedGroups: []string{"engineering"}},
		},
	}

	handler := NewHandler(cfg, sm, accessLog)

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	srvURL, _ := url.Parse(srv.URL)
	cfg.Applications["echo"].Host = srvURL.Hostname()
	handler.ReloadConfig(cfg)

	// Build OIDCAuth using the shared provider to avoid redundant discovery.
	oauthCfg := oauth2.Config{
		ClientID:     "beyond-dev-client-id",
		ClientSecret: "beyond-dev-client-secret",
		Endpoint:     sharedOIDCProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	verifier := sharedOIDCProvider.Verifier(&oidc.Config{ClientID: "beyond-dev-client-id"})
	handler.SetOIDCAuth(&OIDCAuth{
		provider: sharedOIDCProvider,
		config:   oauthCfg,
		verifier: verifier,
	})

	return srv
}

func portalServer(t *testing.T) *httptest.Server {
	t.Helper()

	sharedOIDCProviderOnce.Do(initOIDCProvider)
	if !authentikAvailable {
		t.Skipf("Authentik not reachable at %s (run `just up`)", authentikURL)
	}

	sm, err := NewSessionManager([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 12*time.Hour)
	require.NoError(t, err)
	cfg := &Config{
		Sessions:    SessionConfig{HTTPLifetime: 12 * time.Hour},
		Portal:      &PortalConfig{Host: "PLACEHOLDER", Title: "Internal services"},
		AdminGroups: []string{"authentik Admins"},
		Applications: map[string]*Application{
			"grafana": {
				Name: "grafana", Host: "grafana.internal", Upstream: "http://localhost:3000",
				DisplayName: "Grafana", Description: "Metrics and dashboards",
				LaunchURL: "https://grafana.internal/", AllowedGroups: []string{"engineering"},
			},
			"argocd": {
				Name: "argocd", Host: "argocd.internal", Upstream: "http://localhost:8080",
				DisplayName: "Argo CD", LaunchURL: "https://argocd.internal/", AllowedGroups: []string{"platform"},
			},
		},
	}
	handler := NewHandler(cfg, sm, &AccessLogger{Logger: testLogger()})
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	cfg.Portal.Host = srvURL.Hostname()
	handler.ReloadConfig(cfg)
	handler.SetOIDCAuth(&OIDCAuth{
		provider: sharedOIDCProvider,
		config: oauth2.Config{
			ClientID: "beyond-dev-client-id", ClientSecret: "beyond-dev-client-secret",
			Endpoint: sharedOIDCProvider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		verifier: sharedOIDCProvider.Verifier(&oidc.Config{ClientID: "beyond-dev-client-id"}),
	})
	return srv
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestE2E_HealthCheck(t *testing.T) {
	t.Parallel()
	srv := beyondServer(t)

	resp, err := srv.Client().Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(body))
}

func TestE2E_UnauthenticatedRedirect(t *testing.T) {
	t.Parallel()
	srv := beyondServer(t)

	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(srv.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, 302, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, authentikURL, "should redirect to Authentik")
	assert.Contains(t, loc, "client_id=beyond-dev-client-id")
	assert.Contains(t, loc, "response_type=code")
	assert.Contains(t, loc, "code_challenge=")
	assert.Contains(t, loc, "code_challenge_method=S256")

	// The redirect_uri must be derived from the request host (HTTPS).
	srvURL, _ := url.Parse(srv.URL)
	expectedRedirect := "https://" + srvURL.Host + "/oidc/callback"
	assert.Contains(t, loc, url.QueryEscape(expectedRedirect),
		"redirect_uri must be dynamically derived from request host")

	// State cookie must be set.
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "_beyond_oidc_state" {
			found = true
		}
	}
	assert.True(t, found, "should set _beyond_oidc_state cookie")
}

func TestE2E_FullOIDCFlow(t *testing.T) {
	t.Parallel()
	srv := beyondServer(t)
	resp, body := completeDevOIDCLogin(t, srv, "/")
	assert.Equal(t, 200, resp.StatusCode, "should get proxied echo response; body: %s", string(body[:min(len(body), 500)]))
}

func TestE2E_PortalFullOIDCFlowFiltersApplications(t *testing.T) {
	t.Parallel()
	srv := portalServer(t)
	resp, body := completeDevOIDCLogin(t, srv, "/")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	html := string(body)
	assert.Contains(t, html, "Internal services")
	assert.Contains(t, html, "Grafana")
	assert.NotContains(t, html, "Argo CD")
	assert.NotContains(t, html, "platform")
}

func completeDevOIDCLogin(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	// Use the test server's TLS-aware transport so clients trust its self-signed cert.
	transport := srv.Client().Transport

	noFollow := &http.Client{
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	follow := &http.Client{
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 20 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// 1. Hit beyond → get OIDC redirect.
	resp, err := noFollow.Get(srv.URL + path)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 302, resp.StatusCode)

	oidcRedirect := resp.Header.Get("Location")
	parsed, err := url.Parse(oidcRedirect)
	require.NoError(t, err)

	// 2. Authenticate with Authentik via flow executor (shares cookie jar).
	flowSlug := "default-authentication-flow"
	nextParam := fmt.Sprintf("/application/o/authorize/?%s", parsed.RawQuery)
	flowURL := fmt.Sprintf("%s/api/v3/flows/executor/%s/?query=%s",
		authentikURL, flowSlug, url.QueryEscape("next="+url.QueryEscape(nextParam)))

	// Identification stage.
	resp, err = follow.Get(flowURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var challenge map[string]any
	require.NoError(t, json.Unmarshal(body, &challenge))

	uidJSON, _ := json.Marshal(map[string]string{"uid_field": "test@beyond.local"})
	req, _ := http.NewRequest("POST", flowURL, strings.NewReader(string(uidJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = follow.Do(req)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, json.Unmarshal(body, &challenge))

	// Password stage.
	pwJSON, _ := json.Marshal(map[string]string{"password": "test"})
	req, _ = http.NewRequest("POST", flowURL, strings.NewReader(string(pwJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = follow.Do(req)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, json.Unmarshal(body, &challenge))

	// 3. Follow redirect through Authentik authorize → beyond callback.
	redirectTo, ok := challenge["to"].(string)
	require.True(t, ok, "expected redirect URL")
	if strings.HasPrefix(redirectTo, "/") {
		redirectTo = authentikURL + redirectTo
	}

	resp, err = noFollow.Get(redirectTo)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 302, resp.StatusCode, "Authentik should redirect to beyond callback")

	callbackURL := resp.Header.Get("Location")

	resp, err = follow.Get(callbackURL)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	t.Logf("final: %s status=%d", resp.Request.URL.String(), resp.StatusCode)
	return resp, body
}

// mintServer spins up an in-process beyond configured as a mint app, backed by
// the real dev Authentik. Unlike beyondServer (a proxy app), this app has no
// upstream — it runs the app-password mint flow itself. It wires a mint
// OIDCAuth from the shared provider using the dedicated beyond-mint-dev client
// (public, carrying goauthentik.io/api), and points token_url/api_url at the
// dev Authentik. Returns the server; the app host is the server's own host.
func mintServer(t *testing.T) *httptest.Server {
	t.Helper()

	sharedOIDCProviderOnce.Do(initOIDCProvider)
	if !authentikAvailable {
		t.Skipf("Authentik not reachable at %s (run `just up`)", authentikURL)
	}

	sm, err := NewSessionManager([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 12*time.Hour)
	require.NoError(t, err)

	accessLog := &AccessLogger{Logger: testLogger()}

	cfg := &Config{
		Sessions:    SessionConfig{HTTPLifetime: 12 * time.Hour},
		AdminGroups: []string{"authentik Admins"},
		Applications: map[string]*Application{
			"mint": {
				Name:          "mint",
				Host:          "PLACEHOLDER",
				AllowedGroups: []string{"engineering"}, // the dev test user is in engineering
				MintAuth: &MintAuthConfig{
					ClientID:         "beyond-mint-dev-client-id",
					Issuer:           authentikURL + "/application/o/beyond-mint-dev/",
					APIURL:           authentikURL + "/api/v3",
					TokenLifetime:    365 * 24 * time.Hour,
					TokenLifetimeRaw: "365d",
					TokenScopeName:   "goauthentik.io/api",
				},
			},
		},
	}

	handler := NewHandler(cfg, sm, accessLog)

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	srvURL, _ := url.Parse(srv.URL)
	cfg.Applications["mint"].Host = srvURL.Hostname()
	handler.ReloadConfig(cfg)

	// Build the mint OIDCAuth from the shared provider (avoids redundant
	// discovery), matching what NewMintOIDCAuth produces: the mint client and
	// the mint scopes (openid/profile/email/groups/goauthentik.io/api).
	oauthCfg := oauth2.Config{
		ClientID: "beyond-mint-dev-client-id",
		Endpoint: sharedMintProvider(t).Endpoint(),
		Scopes:   mintScopes,
	}
	verifier := sharedMintProvider(t).Verifier(&oidc.Config{ClientID: "beyond-mint-dev-client-id"})
	handler.SetMintAuth(srvURL.Hostname(), &OIDCAuth{
		provider: sharedMintProvider(t),
		config:   oauthCfg,
		verifier: verifier,
	})

	// The mint index is session-gated like every beyond browser surface, so
	// the ordinary login flow (beyond-dev client) must be wired too.
	loginCfg := oauth2.Config{
		ClientID:     "beyond-dev-client-id",
		ClientSecret: "beyond-dev-client-secret",
		Endpoint:     sharedOIDCProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	loginVerifier := sharedOIDCProvider.Verifier(&oidc.Config{ClientID: "beyond-dev-client-id"})
	handler.SetOIDCAuth(&OIDCAuth{
		provider: sharedOIDCProvider,
		config:   loginCfg,
		verifier: loginVerifier,
	})

	return srv
}

// sharedMintProvider discovers the beyond-mint-dev OIDC provider once. It is a
// distinct issuer from beyond-dev (per-application issuer URLs in Authentik),
// so it needs its own discovery.
var (
	mintProvider     *oidc.Provider
	mintProviderOnce sync.Once
)

func sharedMintProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	mintProviderOnce.Do(func() {
		p, err := oidc.NewProvider(context.Background(), authentikURL+"/application/o/beyond-mint-dev/")
		require.NoError(t, err, "discovering beyond-mint-dev provider (did `just up` provision it?)")
		mintProvider = p
	})
	return mintProvider
}

// TestE2E_MintFullFlow drives the real app-password mint flow against the dev
// Authentik: confirmation page -> POST /start-mint -> Authentik login (flow
// executor) -> callback mints a real app password -> the composite is rendered
// once. It then proves the minted credential actually works by validating it
// through the credential_auth token endpoint the same way beyond does — closing
// the gap the mocked unit tests structurally cannot (real token-create /
// view_key wire format, real Authentik validation of the minted key).
func TestE2E_MintFullFlow(t *testing.T) {
	t.Parallel()
	srv := mintServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	transport := srv.Client().Transport
	noFollow := &http.Client{
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	follow := &http.Client{
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 20 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// 1. Anonymous GET / -> the mint index is session-gated like every beyond
	// browser surface, so it redirects into the ordinary login flow. Nothing
	// is rendered and nothing is minted for an anonymous visitor.
	resp, err := noFollow.Get(srv.URL + "/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 302, resp.StatusCode, "anonymous GET / must redirect to login")
	loginRedirect := resp.Header.Get("Location")
	parsed, err := url.Parse(loginRedirect)
	require.NoError(t, err)
	assert.Contains(t, loginRedirect, "client_id=beyond-dev-client-id",
		"the redirect is the LOGIN flow, not the mint flow")

	// 2. Authenticate with Authentik via the flow executor (shares cookie jar).
	flowSlug := "default-authentication-flow"
	nextParam := fmt.Sprintf("/application/o/authorize/?%s", parsed.RawQuery)
	flowURL := fmt.Sprintf("%s/api/v3/flows/executor/%s/?query=%s",
		authentikURL, flowSlug, url.QueryEscape("next="+url.QueryEscape(nextParam)))

	resp, err = follow.Get(flowURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	uidJSON, _ := json.Marshal(map[string]string{"uid_field": "test@beyond.local"})
	req, _ := http.NewRequest("POST", flowURL, strings.NewReader(string(uidJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = follow.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	pwJSON, _ := json.Marshal(map[string]string{"password": "test"})
	req, _ = http.NewRequest("POST", flowURL, strings.NewReader(string(pwJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = follow.Do(req)
	require.NoError(t, err)
	challengeBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var challenge map[string]any
	require.NoError(t, json.Unmarshal(challengeBody, &challenge))

	// 3. Follow the authorize redirect through beyond's login callback; the
	// browser lands back on GET / with a session and gets the confirmation
	// page with a CSRF token. Still mints nothing.
	redirectTo, ok := challenge["to"].(string)
	require.True(t, ok, "expected redirect URL from flow; got: %s", string(challengeBody))
	if strings.HasPrefix(redirectTo, "/") {
		redirectTo = authentikURL + redirectTo
	}
	resp, err = noFollow.Get(redirectTo)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 302, resp.StatusCode, "Authentik should redirect to beyond's login callback")
	loginCallbackURL := resp.Header.Get("Location")
	require.Contains(t, loginCallbackURL, "/oidc/callback")

	resp, err = follow.Get(loginCallbackURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode, "confirmation page after login; body: %s",
		truncate(string(body), 500))
	csrf := extractCSRFToken(string(body))
	require.NotEmpty(t, csrf, "confirmation page must carry a CSRF token")

	// 4. POST /start-mint with the CSRF token -> redirect to Authentik with
	// the dedicated mint client. The Authentik session from step 2 satisfies
	// the authorize endpoint (implicit consent), which bounces straight back
	// to beyond's mint callback.
	form := url.Values{"csrf_token": {csrf}}
	resp, err = noFollow.PostForm(srv.URL+"/start-mint", form)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 302, resp.StatusCode, "start-mint should redirect to Authentik")
	oidcRedirect := resp.Header.Get("Location")
	assert.Contains(t, oidcRedirect, "client_id=beyond-mint-dev-client-id")
	assert.Contains(t, oidcRedirect, "code_challenge=", "PKCE challenge present")

	resp, err = noFollow.Get(oidcRedirect)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 302, resp.StatusCode, "Authentik should redirect to the mint callback")
	callbackURL := resp.Header.Get("Location")
	require.Contains(t, callbackURL, "/mint/callback")

	// 5. Hit the callback -> beyond mints a real app password and renders it.
	resp, err = follow.Get(callbackURL)
	require.NoError(t, err)
	resultBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode, "mint callback; body: %s", truncate(string(resultBody), 500))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "result must not be cached")

	composite := extractComposite(string(resultBody))
	require.NotEmpty(t, composite, "result page must render the user:key composite")
	assert.True(t, strings.HasPrefix(composite, "test@beyond.local:"),
		"composite should be <email>:<key>, got %q", composite)

	// 6. Prove the minted credential actually validates — the same
	// client-credentials check credential_auth performs per request. This is
	// the real payoff: it confirms the key beyond minted is genuinely usable,
	// not just a well-formed string.
	username, password, ok := splitCredential(composite)
	require.True(t, ok, "minted composite must split into user:key")
	assert.Equal(t, "test@beyond.local", username)
	validateForm := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"beyond-mint-dev-client-id"},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid goauthentik.io/api"},
	}
	vResp, err := http.PostForm(authentikURL+"/application/o/token/", validateForm)
	require.NoError(t, err)
	vBody, _ := io.ReadAll(vResp.Body)
	_ = vResp.Body.Close()
	require.Equal(t, 200, vResp.StatusCode, "minted key should validate; body: %s", truncate(string(vBody), 300))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(vBody, &tok))
	assert.NotEmpty(t, tok.AccessToken, "validation should yield an access token")
}

// extractComposite pulls the rendered user:key composite from the result page
// (inside <code id="composite">...</code>).
func extractComposite(html string) string {
	// Find the composite <code> by its id, then the start of its content (the
	// next '>'), tolerating other attributes like class="cred" in any order.
	i := strings.Index(html, `id="composite"`)
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(html[i:], '>')
	if gt < 0 {
		return ""
	}
	rest := html[i+gt+1:]
	j := strings.Index(rest, "</code>")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func TestE2E_ForbiddenApp(t *testing.T) {
	t.Parallel()
	// A user without the right group gets 403.
	srv := beyondServer(t)

	sm, err := NewSessionManager([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 12*time.Hour)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	require.NoError(t, sm.Save(rec, &SessionData{
		Email:     "outsider@example.com",
		Groups:    []string{"marketing"}, // not in "engineering"
		ExpiresAt: time.Now().Add(12 * time.Hour),
	}))

	jar, _ := cookiejar.New(nil)
	srvURL, _ := url.Parse(srv.URL)
	jar.SetCookies(srvURL, rec.Result().Cookies())

	client := &http.Client{
		Transport:     srv.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get(srv.URL + "/some-page")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, 403, resp.StatusCode)
}

func TestE2E_UnknownHost(t *testing.T) {
	t.Parallel()
	sm, err := NewSessionManager([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 12*time.Hour)
	require.NoError(t, err)

	cfg := &Config{
		Sessions:    SessionConfig{HTTPLifetime: 12 * time.Hour},
		AdminGroups: []string{"authentik Admins"},
		Applications: map[string]*Application{
			"echo": {Name: "echo", Upstream: "http://localhost:18080", Host: "known.example.com", AllowedGroups: []string{"engineering"}},
		},
	}
	handler := NewHandler(cfg, sm, &AccessLogger{Logger: testLogger()})

	rec := httptest.NewRecorder()
	require.NoError(t, sm.Save(rec, &SessionData{
		Email:     "user@example.com",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(12 * time.Hour),
	}))

	req := httptest.NewRequest("GET", "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	req.AddCookie(rec.Result().Cookies()[0])

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, 404, w.Code)
}

func TestE2E_AccessLogsWrittenToDB(t *testing.T) {
	t.Parallel()
	db := ensureDB(t)

	sm, err := NewSessionManager([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 12*time.Hour)
	require.NoError(t, err)

	accessLog := &AccessLogger{Logger: testLogger(), DB: db}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := &Config{
		Sessions:    SessionConfig{HTTPLifetime: 12 * time.Hour},
		AdminGroups: []string{"authentik Admins"},
		Applications: map[string]*Application{
			"echo": {Name: "echo", Upstream: backend.URL, Host: "PLACEHOLDER", AllowedGroups: []string{"engineering"}},
		},
	}
	handler := NewHandler(cfg, sm, accessLog)

	srv := httptest.NewServer(handler)
	defer srv.Close()

	srvURL, _ := url.Parse(srv.URL)
	cfg.Applications["echo"].Host = srvURL.Hostname()
	handler.ReloadConfig(cfg)

	rec := httptest.NewRecorder()
	require.NoError(t, sm.Save(rec, &SessionData{
		Email:     "logtest@beyond.local",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(12 * time.Hour),
	}))

	jar, _ := cookiejar.New(nil)
	jar.SetCookies(srvURL, rec.Result().Cookies())

	client := &http.Client{Jar: jar}
	resp, err := client.Get(srv.URL + "/test-path")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	accessLog.Flush()

	var count int
	err = db.QueryRow("SELECT count(*) FROM access_logs WHERE user_email = 'logtest@beyond.local'").Scan(&count)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "should have at least one access log entry")
}
