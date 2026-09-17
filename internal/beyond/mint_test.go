package beyond

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSingleUseOIDCProvider is like mockOIDCProviderWithClaims but enforces
// SINGLE-USE authorization codes, faithfully modeling Authentik. This is the
// real replay guard the mint A3 design leans on: the state cookie is cleared on
// the first callback (defeating a normal browser refresh), and a deliberately
// replayed code fails the token exchange at the IdP. The code "valid-code" is
// accepted exactly once; any subsequent exchange with it returns 401.
func mockSingleUseOIDCProvider(t *testing.T, userClaims map[string]any) *httptest.Server {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generating RSA test key")

	var mu sync.Mutex
	usedCodes := map[string]bool{}

	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                s.URL,
				"authorization_endpoint":                s.URL + "/authorize",
				"token_endpoint":                        s.URL + "/token",
				"jwks_uri":                              s.URL + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})

		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{{
					Key:       &privKey.PublicKey,
					KeyID:     "test-key",
					Algorithm: string(jose.RS256),
					Use:       "sig",
				}},
			})

		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			code := r.FormValue("code")
			mu.Lock()
			used := usedCodes[code]
			usedCodes[code] = true
			mu.Unlock()
			if code != "valid-code" || used {
				// Single-use: an already-redeemed (or unknown) code fails, just
				// as Authentik's real token endpoint does.
				http.Error(w, "invalid or used code", http.StatusUnauthorized)
				return
			}

			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
				(&jose.SignerOptions{}).WithHeader("kid", "test-key"),
			)
			if err != nil {
				http.Error(w, "signer error", http.StatusInternalServerError)
				return
			}
			clientID := r.FormValue("client_id")
			if clientID == "" {
				if u, _, ok := r.BasicAuth(); ok {
					clientID = u
				}
			}
			now := time.Now()
			claims := jwt.Claims{
				Issuer:   s.URL,
				Subject:  "test-user",
				Audience: jwt.Audience{clientID},
				Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt: jwt.NewNumericDate(now),
			}
			idToken, err := jwt.Signed(signer).Claims(claims).Claims(userClaims).Serialize()
			if err != nil {
				http.Error(w, "jwt error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			})

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

const mintTestClientID = "beyond-mint-client-id"

// mintTestHost is the configured mint application host used across these tests.
const mintTestHost = "mint.example.com"

// fakeAuthentikAPI records the token-create / view_key / delete calls the mint
// callback makes so tests can assert exact counts (e.g. ZERO creates on a
// group-denied user) and drive failure paths.
type fakeAuthentikAPI struct {
	srv           *httptest.Server
	creates       atomic.Int64
	viewKeys      atomic.Int64
	deletes       atomic.Int64
	lists         atomic.Int64
	lastAuthHdr   atomic.Value // string: the bearer seen on the create call
	createStatus  int          // status to return on POST /core/tokens/ (default 201)
	createBody    string       // body to return on create (default "{}")
	viewKeyOK     bool         // whether view_key returns a key
	viewKeyStatus int          // status for view_key when not OK (default 500)
	mintedKey     string       // key returned by view_key

	mu            sync.Mutex
	existing      []string        // identifiers returned by GET /core/tokens/ (the sweep list)
	foreignOwned  map[string]bool // ids owned by another user (default: test user owns all)
	deletedIDs    []string        // identifiers passed to DELETE, in order
	lastListQuery string          // raw query of the most recent token-list GET
}

func newFakeAuthentikAPI(t *testing.T) *fakeAuthentikAPI {
	t.Helper()
	fa := &fakeAuthentikAPI{
		createStatus:  http.StatusCreated,
		createBody:    `{}`,
		viewKeyOK:     true,
		viewKeyStatus: http.StatusInternalServerError,
		foreignOwned:  map[string]bool{},
		mintedKey:     "the-app-password",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /core/tokens/", func(w http.ResponseWriter, r *http.Request) {
		fa.creates.Add(1)
		fa.lastAuthHdr.Store(r.Header.Get("Authorization"))
		w.WriteHeader(fa.createStatus)
		_, _ = io.WriteString(w, fa.createBody)
	})
	mux.HandleFunc("GET /core/tokens/{id}/view_key/", func(w http.ResponseWriter, r *http.Request) {
		fa.viewKeys.Add(1)
		if !fa.viewKeyOK {
			w.WriteHeader(fa.viewKeyStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(viewKeyResponse{Key: fa.mintedKey})
	})
	mux.HandleFunc("DELETE /core/tokens/{id}/", func(w http.ResponseWriter, r *http.Request) {
		fa.deletes.Add(1)
		fa.mu.Lock()
		fa.deletedIDs = append(fa.deletedIDs, r.PathValue("id"))
		fa.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	// List endpoint drives the re-mint overwrite sweep. Returns the configured
	// existing identifiers so a test can assert which get reaped. Each token is
	// owned by the standard test user unless the fixture id is listed in
	// foreignOwned (owner "someone.else@example.com"), letting tests prove
	// the client-side ownership check. The real API filters by user__username;
	// the fake deliberately does NOT, so foreign tokens reach the client-side
	// check instead of being filtered server-side. The filter itself is
	// asserted via lastListQuery.
	mux.HandleFunc("GET /core/tokens/", func(w http.ResponseWriter, r *http.Request) {
		fa.lists.Add(1)
		fa.mu.Lock()
		fa.lastListQuery = r.URL.RawQuery
		items := make([]mintTokenListItem, 0, len(fa.existing))
		for _, id := range fa.existing {
			it := mintTokenListItem{Identifier: id}
			it.UserObj.Username = "alice@example.com"
			if fa.foreignOwned[id] {
				it.UserObj.Username = "someone.else@example.com"
			}
			items = append(items, it)
		}
		fa.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mintTokenList{Results: items})
	})
	fa.srv = httptest.NewServer(mux)
	t.Cleanup(fa.srv.Close)
	return fa
}

// authHeader returns the Authorization header seen on the last create call.
func (fa *fakeAuthentikAPI) authHeader() string {
	v, _ := fa.lastAuthHdr.Load().(string)
	return v
}

// newMintTestHandler builds a Handler with a mint app wired to a mock Authentik
// OIDC provider (for the code exchange + id_token) and a mock Authentik API
// (for token-create/view_key/delete). allowedGroups sets the mint app's
// allowed_groups. The returned oidcClaims map is held by reference so a test can
// inject the nonce before driving the callback.
func newMintTestHandler(t *testing.T, fa *fakeAuthentikAPI, allowedGroups []string, oidcClaims map[string]any, logBuf io.Writer) *Handler {
	t.Helper()

	oidcSrv := mockSingleUseOIDCProvider(t, oidcClaims)

	cfg := testConfig()
	cfg.Applications["mint"] = &Application{
		Name:          "mint",
		Host:          mintTestHost,
		AllowedGroups: allowedGroups,
		MintAuth: &MintAuthConfig{
			ClientID:       mintTestClientID,
			Issuer:         oidcSrv.URL,
			APIURL:         fa.srv.URL,
			TokenLifetime:  365 * 24 * time.Hour,
			TokenScopeName: defaultMintTokenScopeName,
		},
	}

	sm := testSessionManager(t)
	if logBuf == nil {
		logBuf = io.Discard
	}
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(logBuf, nil))}
	h := NewHandler(cfg, sm, al)

	mintAuth, err := NewMintOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL: oidcSrv.URL,
		ClientID:  mintTestClientID,
	})
	require.NoError(t, err)
	h.SetMintAuth(mintTestHost, mintAuth)

	// The mint index is session-gated, so an anonymous GET / falls through to
	// beyond's ordinary login flow. Wire that up too (distinct client id — in
	// prod these are separate Authentik providers, and only the mint one
	// carries the goauthentik.io/api scope).
	loginAuth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    oidcSrv.URL,
		ClientID:     "beyond-login-client-id",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)
	h.SetOIDCAuth(loginAuth)

	return h
}

func mintClaims(groups []string) map[string]any {
	return map[string]any{
		"email":  "alice@example.com",
		"name":   "Alice",
		"groups": groups,
	}
}

// mintSessionCookie builds a valid beyond session cookie for the mint tests.
// The mint index and /start-mint are session-gated like any other
// beyond-fronted app, so every test that drives the flow needs one.
func mintSessionCookie(t *testing.T, h *Handler, groups []string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, h.sessions.Save(w, &SessionData{
		Email:     "alice@example.com",
		Name:      "Alice",
		Groups:    groups,
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	c := cookieFromRecorder(t, w, sessionCookieName)
	require.NotNil(t, c, "session cookie must be issued")
	return c
}

// getMintIndex fetches GET / as a session-authenticated member of the mint
// app's allowed_groups, and returns the recorder plus the CSRF cookie and the
// form's csrf_token value, so a follow-up POST /start-mint can be built.
func getMintIndex(t *testing.T, h *Handler) (*httptest.ResponseRecorder, *http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == mintCSRFCookieName {
			csrfCookie = c
		}
	}
	token := extractCSRFToken(rec.Body.String())
	return rec, csrfCookie, token
}

// extractCSRFToken pulls the hidden csrf_token value out of the rendered index.
func extractCSRFToken(body string) string {
	const marker = `name="csrf_token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// driveMintToCallback runs GET / -> POST /start-mint and returns the mint-state
// cookie plus the (state, nonce) beyond generated, so a test can construct the
// callback request. It injects the nonce into oidcClaims so the mock id_token
// echoes it.
func driveMintToCallback(t *testing.T, h *Handler, oidcClaims map[string]any) (stateCookie *http.Cookie, state, nonce string) {
	t.Helper()

	_, csrfCookie, token := getMintIndex(t, h)
	require.NotNil(t, csrfCookie, "CSRF cookie must be set by GET /")
	require.NotEmpty(t, token, "form CSRF token must be present")

	form := url.Values{"csrf_token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code, "start-mint should redirect to Authentik")

	for _, c := range rec.Result().Cookies() {
		if c.Name == mintStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "mint state cookie must be set")

	state, _, nonce, _, err := h.decryptMintState(stateCookie.Value)
	require.NoError(t, err)
	oidcClaims["nonce"] = nonce
	return stateCookie, state, nonce
}

// callback builds and serves a GET /mint/callback with the given state and
// state cookie.
func mintCallback(t *testing.T, h *Handler, stateCookie *http.Cookie, state string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/mint/callback?code=valid-code&state="+url.QueryEscape(state), nil)
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	if stateCookie != nil {
		req.AddCookie(stateCookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The mint host is internet-facing, so an anonymous GET must not render the
// form. It gets the ordinary beyond login redirect instead — and critically,
// still no OIDC *mint* flow and no Authentik write.
func TestMint_IndexAnonymousRedirectsToLogin(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	h := newMintTestHandler(t, fa, []string{"platform"}, mintClaims([]string{"platform"}), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code, "anonymous GET / must redirect to login")
	assert.NotContains(t, rec.Body.String(), "Create an access key",
		"the form must not be rendered to an anonymous visitor")
	assert.NotContains(t, rec.Body.String(), "csrf_token",
		"no CSRF token may be issued to an anonymous visitor")

	// The redirect is the LOGIN flow (/oidc/callback), never the mint flow.
	loc := rec.Header().Get("Location")
	require.NotEmpty(t, loc)
	assert.Contains(t, loc, url.QueryEscape("/oidc/callback"),
		"must be the ordinary login flow, not the mint flow: %s", loc)
	assert.NotContains(t, loc, url.QueryEscape("/mint/callback"))

	// The login state cookie is set; the mint CSRF/state cookies are not.
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, mintCSRFCookieName, c.Name, "mint CSRF cookie must not be issued")
		assert.NotEqual(t, mintStateCookieName, c.Name, "mint state cookie must not be issued")
	}

	assert.Zero(t, fa.creates.Load(), "no token may be created")
}

// A session that fails the app's allowed_groups gets a 403 page up front,
// rather than the form followed by a 403 after a pointless OIDC round-trip.
func TestMint_IndexWrongGroupForbidden(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	h := newMintTestHandler(t, fa, []string{"platform"}, mintClaims([]string{"platform"}), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.AddCookie(mintSessionCookie(t, h, []string{"contractors"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), `action="/start-mint"`, "no form for a denied user")
	assert.Zero(t, fa.creates.Load(), "no token may be created")
}

// A session that expires while the confirmation page sits open must get a
// start-again notice, NOT a login redirect: redirecting a POST would discard
// the form body and land the browser on GET /start-mint, which is a 404.
func TestMint_StartWithoutSessionRendersNotice(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	h := newMintTestHandler(t, fa, []string{"platform"}, mintClaims([]string{"platform"}), nil)

	_, csrfCookie, token := getMintIndex(t, h)
	require.NotNil(t, csrfCookie)

	form := url.Values{"csrf_token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie) // CSRF still valid; session cookie deliberately absent
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"), "a POST must not be redirected into login")
	assert.Contains(t, rec.Body.String(), "Session expired")
	assert.Zero(t, fa.creates.Load(), "no token may be created")
}

func TestMint_IndexRendersButtonNoMintNoOIDC(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	h := newMintTestHandler(t, fa, []string{"platform"}, mintClaims([]string{"platform"}), nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = mintTestHost
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	body := rec.Body.String()
	assert.Contains(t, body, "Create an access key")
	assert.Contains(t, body, `action="/start-mint"`)
	assert.Contains(t, body, `name="csrf_token"`)
	assert.Contains(t, body, `name="purpose"`, "index page must include the purpose input field")
	assert.Contains(t, body, `value="aigw"`, "purpose field must default to aigw")

	// ?purpose=<label> pre-fills the field (per-consumer mint links); an
	// invalid query value falls back to the default instead of erroring.
	for query, want := range map[string]string{
		"/?purpose=gcx":      `value="gcx"`,
		"/?purpose=GCX":      `value="gcx"`,
		"/?purpose=bad_char": `value="aigw"`,
	} {
		req := httptest.NewRequest(http.MethodGet, query, nil)
		req.Host = mintTestHost
		req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "GET %s", query)
		assert.Contains(t, rec.Body.String(), want, "GET %s must prefill %s", query, want)
	}

	// CSP form-action MUST allow the Authentik origin. The form POSTs to
	// same-origin /start-mint, but that 302s to Authentik's authorize endpoint,
	// and form-action governs the redirect target of a form submission — so
	// without the issuer origin here the browser silently blocks the hop and the
	// button "does nothing". Regression guard for exactly that bug.
	csp := resp.Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "form-action 'self' http://127.0.0.1",
		"confirmation-page CSP must allow the Authentik origin in form-action, or the redirect is blocked; got %q", csp)

	// No OIDC redirect, no Authentik writes.
	assert.Empty(t, resp.Header.Get("Location"), "a bare GET must not start OIDC")
	assert.Equal(t, int64(0), fa.creates.Load(), "a bare GET must never mint")

	// CSRF cookie set.
	var csrf *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == mintCSRFCookieName {
			csrf = c
		}
	}
	require.NotNil(t, csrf)
	assert.True(t, csrf.HttpOnly)
}

func TestMint_StartWithoutCSRFRejected(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	h := newMintTestHandler(t, fa, []string{"platform"}, mintClaims([]string{"platform"}), nil)

	t.Run("no cookie, no form token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(""))
		req.Host = mintTestHost
		req.RemoteAddr = "10.0.0.1:1111"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("Location"))
	})

	t.Run("cookie present but wrong form token", func(t *testing.T) {
		_, csrfCookie, _ := getMintIndex(t, h)
		require.NotNil(t, csrfCookie)
		form := url.Values{"csrf_token": {"not-the-real-token"}}
		req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
		req.Host = mintTestHost
		req.RemoteAddr = "10.0.0.1:1111"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("Location"))
	})
}

func TestMint_StartWithValidCSRFRedirects(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, nonce := driveMintToCallback(t, h, claims)
	assert.NotEmpty(t, state)
	assert.NotEmpty(t, nonce)
	assert.NotNil(t, stateCookie)
	assert.Equal(t, int64(0), fa.creates.Load(), "reaching the redirect must not mint")
}

func TestMint_CallbackGroupDeniedNoTokenCreate(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	// User is in "outsiders"; mint app allows only "platform" (and no admin).
	claims := mintClaims([]string{"outsiders"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int64(0), fa.creates.Load(), "a group-denied user must trigger ZERO token-create calls")
	assert.Equal(t, int64(0), fa.viewKeys.Load())
}

func TestMint_CallbackHappyPath(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := rec.Body.String()
	// Composite rendered: <email>:<key>.
	assert.Contains(t, body, "alice@example.com:the-app-password")
	// Cache-Control: no-store present.
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	// history.replaceState so a refresh reloads "/".
	assert.Contains(t, body, "history.replaceState")

	// Exactly one token-create and one view_key.
	assert.Equal(t, int64(1), fa.creates.Load())
	assert.Equal(t, int64(1), fa.viewKeys.Load())
	assert.Equal(t, int64(0), fa.deletes.Load())

	// The create call carried a bearer (the user's access token from exchange).
	assert.Equal(t, "Bearer test-access-token", fa.authHeader())
}

func TestMint_ReMintRevokesOldKeys(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	// Same-purpose aigw keys in both new format and legacy format, plus a gcx
	// key (different purpose — must be preserved) and a hand-made token (not a
	// beyond-mint key — must be preserved).
	legacyAigwID := "beyond-mint-" + strings.Repeat("a", 32) // 32 hex chars, legacy format
	newAigwID := "beyond-mint-aigw-" + strings.Repeat("b", 32)
	gcxID := "beyond-mint-gcx-" + strings.Repeat("c", 32)
	fa.existing = []string{
		legacyAigwID,       // legacy aigw key — must be reaped when purpose == aigw
		newAigwID,          // new-format aigw key — must be reaped
		gcxID,              // gcx key — different purpose, must be preserved
		"my-own-cli-token", // hand-made token (no beyond-mint prefix) — must be preserved
	}
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	// driveMintToCallback uses the form default purpose "aigw".
	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)

	// One create (the new key), one list (the sweep), and exactly two deletes:
	// the legacy aigw key and the new-format aigw key. The gcx key, the
	// hand-made token, and the just-created key are all spared.
	assert.Equal(t, int64(1), fa.creates.Load())
	assert.Equal(t, int64(1), fa.lists.Load())
	fa.mu.Lock()
	deleted := append([]string(nil), fa.deletedIDs...)
	fa.mu.Unlock()
	assert.ElementsMatch(t, []string{legacyAigwID, newAigwID}, deleted,
		"sweep must revoke same-purpose aigw keys (both legacy and new format), sparing gcx and hand-made tokens")
}

func TestMint_CallbackReplayNoSecondCreate(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)

	// First callback mints.
	rec1 := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec1.Code)
	require.Equal(t, int64(1), fa.creates.Load())

	// Replay the SAME callback (same state cookie + same code). The test client
	// still holds the old cookie (a browser would too on back/refresh). Two
	// guards defeat this: the server cleared its state cookie on the first pass
	// (a normal browser refresh sends nothing), and even a client that resends
	// the cookie replays the authorization code, which the IdP has already
	// consumed — so the token exchange fails and NO second token is minted.
	rec2 := mintCallback(t, h, stateCookie, state)
	assert.Equal(t, int64(1), fa.creates.Load(), "a replayed callback must not mint a second token")
	// No secret is shown on the replay: the exchange failed.
	assert.NotContains(t, rec2.Body.String(), "the-app-password")
}

func TestMint_CallbackNoStateCookieIsReplayPage(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	// Hit the callback URL directly, no state cookie.
	req := httptest.NewRequest(http.MethodGet, "/mint/callback?code=x&state=y", nil)
	req.Host = mintTestHost
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, int64(0), fa.creates.Load())
	assert.Contains(t, rec.Body.String(), "already been used")
}

func TestMint_PartialSuccessDeletesToken(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	fa.viewKeyOK = false // view_key fails AFTER a successful create
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, int64(1), fa.creates.Load(), "token was created")
	assert.Equal(t, int64(1), fa.viewKeys.Load(), "view_key was attempted")
	assert.Equal(t, int64(1), fa.deletes.Load(), "the orphaned token must be deleted")
	// No secret leaked in the error page.
	assert.NotContains(t, rec.Body.String(), "the-app-password")
}

func TestMint_CapExceededSurfacesCleanError(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	fa.createStatus = http.StatusBadRequest
	fa.createBody = `{"expires":["Token expires exceeds maximum lifetime."]}`
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, int64(1), fa.creates.Load())
	assert.Equal(t, int64(0), fa.viewKeys.Load(), "no view_key after a rejected create")
	// The apostrophe is HTML-escaped by html/template, so match on a substring
	// that avoids it.
	assert.Contains(t, rec.Body.String(), "exceeds your account")
}

func TestMint_AuthentikUnavailableFailsClosed(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	fa.createStatus = http.StatusInternalServerError
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, int64(1), fa.creates.Load())
	assert.Equal(t, int64(0), fa.viewKeys.Load())
}

// TestMint_NoSecretInLogs captures the package slog output during a happy-path
// mint and asserts neither the access token nor the minted key appears.
func TestMint_NoSecretInLogs(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	fa.mintedKey = "SUPER-SECRET-KEY-value"
	claims := mintClaims([]string{"platform"})
	var logBuf bytes.Buffer
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, &logBuf)

	stateCookie, state, _ := driveMintToCallback(t, h, claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)
	// Sanity: the secret WAS rendered to the user.
	require.Contains(t, rec.Body.String(), "SUPER-SECRET-KEY-value")

	logs := logBuf.String()
	assert.NotContains(t, logs, "SUPER-SECRET-KEY-value", "the minted key must never appear in logs")
	assert.NotContains(t, logs, "test-access-token", "the access token must never appear in logs")
}

func TestMintAuthConfig_Validation(t *testing.T) {
	t.Parallel()

	base := `
applications:
  mint:
    host: mint.example.com
    allowed_groups: [ai-gateway-users]
`
	full := `    mint_auth:
      client_id: mint-client
      issuer: https://auth.example.com/application/o/beyond-mint/
      token_url: http://authentik.svc/application/o/token/
      api_url: http://authentik.svc/api/v3
      token_lifetime: 365d
`
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			"mint_auth without upstream accepted",
			base + full,
			"", // no error
		},
		{
			"missing client_id",
			base + `    mint_auth:
      issuer: https://auth.example.com/o/beyond-mint/
      token_url: http://authentik.svc/application/o/token/
      api_url: http://authentik.svc/api/v3
      token_lifetime: 365d
`,
			"client_id",
		},
		{
			"missing token_lifetime",
			base + `    mint_auth:
      client_id: mint-client
      issuer: https://auth.example.com/o/beyond-mint/
      token_url: http://authentik.svc/application/o/token/
      api_url: http://authentik.svc/api/v3
`,
			"token_lifetime",
		},
		{
			"http issuer rejected",
			base + `    mint_auth:
      client_id: mint-client
      issuer: http://auth.example.com/o/beyond-mint/
      token_url: http://authentik.svc/application/o/token/
      api_url: http://authentik.svc/api/v3
      token_lifetime: 365d
`,
			"https URL",
		},
		{
			"relative api_url",
			base + `    mint_auth:
      client_id: mint-client
      issuer: https://auth.example.com/o/beyond-mint/
      token_url: http://authentik.svc/application/o/token/
      api_url: /api/v3
      token_lifetime: 365d
`,
			"absolute http",
		},
		{
			"mint_auth + credential_auth conflict",
			base + full + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
`,
			"mutually exclusive",
		},
		{
			"mint_auth + bearer_auth conflict",
			base + full + `    bearer_auth:
      issuer: https://auth.example.com/o/x/
      jwks_url: http://jwks.svc/keys
      audience: x
`,
			"mutually exclusive",
		},
		{
			"mint_auth + passthrough conflict",
			base + full + `    passthrough_auth_schemes:
      - Token
`,
			"mutually exclusive",
		},
		{
			"mint_auth + upstream rejected",
			base + `    upstream: http://something:80
` + full,
			"must not set upstream",
		},
		{
			"invalid token_lifetime",
			base + `    mint_auth:
      client_id: mint-client
      issuer: https://auth.example.com/o/beyond-mint/
      token_url: http://authentik.svc/application/o/token/
      api_url: http://authentik.svc/api/v3
      token_lifetime: banana
`,
			"token_lifetime",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := writeTempFile(t, tc.yaml)
			cfg, err := LoadConfig(f)
			if tc.wantErr == "" {
				require.NoError(t, err)
				ma := cfg.Applications["mint"].MintAuth
				require.NotNil(t, ma)
				assert.Equal(t, 365*24*time.Hour, ma.TokenLifetime)
				assert.Equal(t, defaultMintTokenScopeName, ma.TokenScopeName)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// driveMintToCallbackWithPurpose is like driveMintToCallback but posts the
// given purpose value to /start-mint. An empty purposeVal sends no purpose
// field at all, exercising the default-to-aigw path.
func driveMintToCallbackWithPurpose(t *testing.T, h *Handler, purposeVal string, oidcClaims map[string]any) (stateCookie *http.Cookie, state, nonce string) {
	t.Helper()

	_, csrfCookie, token := getMintIndex(t, h)
	require.NotNil(t, csrfCookie, "CSRF cookie must be set by GET /")
	require.NotEmpty(t, token, "form CSRF token must be present")

	form := url.Values{"csrf_token": {token}}
	if purposeVal != "" {
		form.Set("purpose", purposeVal)
	}
	req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code, "start-mint should redirect; got body: %s", rec.Body.String())

	for _, c := range rec.Result().Cookies() {
		if c.Name == mintStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "mint state cookie must be set")

	state, _, nonce, _, err := h.decryptMintState(stateCookie.Value)
	require.NoError(t, err)
	oidcClaims["nonce"] = nonce
	return stateCookie, state, nonce
}

// --- new tests for purpose labeling ---

func TestMint_PurposeDefaultsToAigwWhenEmpty(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	// Post with no purpose field: should default to aigw and redirect.
	_, csrfCookie, token := getMintIndex(t, h)
	require.NotNil(t, csrfCookie)
	form := url.Values{"csrf_token": {token}} // no "purpose" key
	req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code, "empty purpose should be accepted as aigw")

	// Verify the state cookie encodes purpose "aigw".
	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == mintStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	_, _, _, purpose, err := h.decryptMintState(stateCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, "aigw", purpose, "empty purpose must round-trip as aigw")
}

func TestMint_PurposeLowercaseNormalized(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	// "AIGW" must be lowercased to "aigw" before validation/storage.
	_, csrfCookie, token := getMintIndex(t, h)
	require.NotNil(t, csrfCookie)
	form := url.Values{"csrf_token": {token}, "purpose": {"AIGW"}}
	req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
	req.Host = mintTestHost
	req.RemoteAddr = "10.0.0.1:1111"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code, "uppercase purpose should be accepted after lowercasing")

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == mintStateCookieName {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	_, _, _, purpose, err := h.decryptMintState(stateCookie.Value)
	require.NoError(t, err)
	assert.Equal(t, "aigw", purpose, "uppercase purpose must be lowercased to aigw")
}

func TestMint_PurposeInvalidReturns400WithInlineError(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	cases := []struct {
		name    string
		purpose string
	}{
		{"starts with hyphen", "-bad"},
		{"underscore", "my_key"}, // underscore is not in [a-z0-9-] even after lowercase
		{"space", "my key"},
		{"too long", strings.Repeat("a", 33)},
		{"special char", "my/key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each sub-test needs a fresh CSRF round-trip.
			_, csrfCookie, token := getMintIndex(t, h)
			require.NotNil(t, csrfCookie)
			form := url.Values{"csrf_token": {token}, "purpose": {tc.purpose}}
			req := httptest.NewRequest(http.MethodPost, "/start-mint", strings.NewReader(form.Encode()))
			req.Host = mintTestHost
			req.RemoteAddr = "10.0.0.1:1111"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(csrfCookie)
			req.AddCookie(mintSessionCookie(t, h, []string{"platform"}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code, "purpose %q should be rejected", tc.purpose)
			// Re-renders the index page with the inline error — no OIDC redirect.
			assert.Empty(t, rec.Header().Get("Location"), "invalid purpose must not redirect to OIDC")
			body := rec.Body.String()
			assert.Contains(t, body, "Invalid purpose", "error message must appear in the rendered page")
			assert.Contains(t, body, `action="/start-mint"`, "re-rendered index must include the form")
			// Zero Authentik writes.
			assert.Equal(t, int64(0), fa.creates.Load(), "invalid purpose must not reach Authentik")
		})
	}
}

func TestMint_PurposeRoundTripThroughStateCookie(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	// Encrypt with purpose "gcx", then decrypt and verify round-trip.
	h := &Handler{sessions: sm}
	cookie, err := h.encryptMintState("state-val", "verifier-val", "nonce-val", "gcx")
	require.NoError(t, err)

	state, verifier, nonce, purpose, err := h.decryptMintState(cookie)
	require.NoError(t, err)
	assert.Equal(t, "state-val", state)
	assert.Equal(t, "verifier-val", verifier)
	assert.Equal(t, "nonce-val", nonce)
	assert.Equal(t, "gcx", purpose)
}

func TestMint_PurposeEmptyInCookieDefaultsToAigw(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	// Simulate a stale cookie (minted before purpose labeling) by encrypting a
	// state with empty MintPurpose — as if a pre-deploy cookie is decoded.
	h := &Handler{sessions: sm}
	cookie, err := sm.EncryptToken(&SessionData{
		Type:         tokenTypeMintState,
		OIDCState:    "s",
		OIDCVerifier: "v",
		OIDCNonce:    "n",
		MintPurpose:  "", // pre-deploy: no purpose stored
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})
	require.NoError(t, err)

	_, _, _, purpose, err := h.decryptMintState(cookie)
	require.NoError(t, err)
	assert.Equal(t, "aigw", purpose, "empty MintPurpose in decrypted cookie must default to aigw")
}

func TestMint_IdentifierIncludesPurpose(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	// Mint with purpose "gcx" and verify the identifier passed to Authentik has
	// the right prefix. The fakeAuthentikAPI records the Authorization header on
	// creates; the identifier is not directly observable there, but we can
	// confirm the result page shows the purpose label and the create succeeded.
	stateCookie, state, _ := driveMintToCallbackWithPurpose(t, h, "gcx", claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)

	body := rec.Body.String()
	assert.Contains(t, body, "<code>gcx</code>", "result page must show the purpose label")
	assert.Equal(t, int64(1), fa.creates.Load())
}

func TestMint_SweepSamePurposeOnlyGcx(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	// Two gcx keys plus an aigw key. Re-minting with purpose gcx must reap
	// only the gcx keys; the aigw key must survive.
	gcx1 := "beyond-mint-gcx-" + strings.Repeat("1", 32)
	gcx2 := "beyond-mint-gcx-" + strings.Repeat("2", 32)
	aigwKey := "beyond-mint-aigw-" + strings.Repeat("3", 32)
	fa.existing = []string{gcx1, gcx2, aigwKey}
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallbackWithPurpose(t, h, "gcx", claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)

	fa.mu.Lock()
	deleted := append([]string(nil), fa.deletedIDs...)
	fa.mu.Unlock()
	assert.ElementsMatch(t, []string{gcx1, gcx2}, deleted,
		"sweep must revoke only gcx-purpose keys, leaving the aigw key untouched")
}

func TestMint_LegacyIDsNotRevokedForNonAigwPurpose(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	// A legacy-format id plus a gcx key. Re-minting with purpose gcx must NOT
	// reap the legacy id (legacy ids are only de-facto aigw, not gcx).
	legacyID := "beyond-mint-" + strings.Repeat("a", 32)
	gcxOld := "beyond-mint-gcx-" + strings.Repeat("b", 32)
	fa.existing = []string{legacyID, gcxOld}
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallbackWithPurpose(t, h, "gcx", claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)

	fa.mu.Lock()
	deleted := append([]string(nil), fa.deletedIDs...)
	fa.mu.Unlock()
	assert.ElementsMatch(t, []string{gcxOld}, deleted,
		"legacy identifiers must only be reaped when purpose is aigw, not for other purposes")
}

func TestMint_SweepDoesNotReapLongerPurposeSharingPrefix(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	// Purposes may contain hyphens, so "gcx" is a string prefix of "gcx-prod".
	// A gcx mint must reap only exact gcx keys — the gcx-prod key's identifier
	// starts with "beyond-mint-gcx-" but its suffix is not 32 bare hex chars.
	gcxOld := "beyond-mint-gcx-" + strings.Repeat("1", 32)
	gcxProd := "beyond-mint-gcx-prod-" + strings.Repeat("2", 32)
	fa.existing = []string{gcxOld, gcxProd}
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallbackWithPurpose(t, h, "gcx", claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)

	fa.mu.Lock()
	deleted := append([]string(nil), fa.deletedIDs...)
	fa.mu.Unlock()
	assert.ElementsMatch(t, []string{gcxOld}, deleted,
		"a purpose that prefixes another purpose must not sweep the longer purpose's keys")
}

func TestMint_SweepNeverDeletesForeignOwnedTokens(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentikAPI(t)
	// Regression for the 2026-07-10 prod incident: an authentik superuser's
	// unfiltered token list includes OTHER users' tokens, and the sweep
	// deleted a coworker's same-purpose key. Same-purpose + foreign owner
	// must be skipped even when the (fake, unfiltered) list returns it.
	mine := "beyond-mint-gcx-" + strings.Repeat("1", 32)
	theirs := "beyond-mint-gcx-" + strings.Repeat("2", 32)
	fa.existing = []string{mine, theirs}
	fa.foreignOwned = map[string]bool{theirs: true}
	claims := mintClaims([]string{"platform"})
	h := newMintTestHandler(t, fa, []string{"platform"}, claims, nil)

	stateCookie, state, _ := driveMintToCallbackWithPurpose(t, h, "gcx", claims)
	rec := mintCallback(t, h, stateCookie, state)
	require.Equal(t, http.StatusOK, rec.Code)

	fa.mu.Lock()
	deleted := append([]string(nil), fa.deletedIDs...)
	query := fa.lastListQuery
	fa.mu.Unlock()
	assert.ElementsMatch(t, []string{mine}, deleted,
		"sweep must never delete a token owned by another user")
	assert.Contains(t, query, "user__username="+url.QueryEscape("alice@example.com"),
		"token-list query must filter by the caller's username (first ownership layer)")
}

func TestParseExtendedDuration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"365d", 365 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"0d", 0, true},
		{"-5d", 0, true},
		{"banana", 0, true},
		{"", 0, true},
	}
	for _, tc := range cases {
		got, err := parseExtendedDuration(tc.in)
		if tc.err {
			assert.Error(t, err, "in=%q", tc.in)
			continue
		}
		require.NoError(t, err, "in=%q", tc.in)
		assert.Equal(t, tc.want, got, "in=%q", tc.in)
	}
}
