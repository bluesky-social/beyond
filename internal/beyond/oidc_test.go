package beyond

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

// defaultMockClaims are the user claims every mock OIDC provider emits
// unless overridden via mockOIDCProviderWithClaims. Kept as a free
// variable so individual tests can copy + mutate it.
var defaultMockClaims = map[string]any{
	"email":  "alice@example.com",
	"name":   "Alice Example",
	"groups": []string{"engineering", "team-all"},
}

// mockOIDCProvider starts an httptest.Server that speaks just enough OIDC for
// tests: discovery, JWKS, token exchange, and userinfo. Uses defaultMockClaims.
func mockOIDCProvider(t *testing.T) (srv *httptest.Server, privKey *rsa.PrivateKey) {
	return mockOIDCProviderWithClaims(t, defaultMockClaims)
}

// mockOIDCProviderWithClaims is like mockOIDCProvider but lets callers
// specify the user claims returned in both the id_token and userinfo.
// Use this to exercise malformed claims without touching the default
// case everyone else depends on.
func mockOIDCProviderWithClaims(t *testing.T, userClaims map[string]any) (srv *httptest.Server, privKey *rsa.PrivateKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generating RSA test key")

	// srv is declared before the handler so the closure can reference it.
	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 s.URL,
				"authorization_endpoint": s.URL + "/authorize",
				"token_endpoint":         s.URL + "/token",
				"userinfo_endpoint":      s.URL + "/userinfo",
				"jwks_uri":               s.URL + "/jwks",
				"response_types_supported": []string{"code"},
				"subject_types_supported":  []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})

		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			jwks := jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       &privKey.PublicKey,
						KeyID:     "test-key",
						Algorithm: string(jose.RS256),
						Use:       "sig",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jwks)

		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.FormValue("code") != "valid-code" {
				http.Error(w, "invalid code", http.StatusUnauthorized)
				return
			}

			// Build a signed JWT id_token.
			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
				(&jose.SignerOptions{}).WithHeader("kid", "test-key"),
			)
			if err != nil {
				http.Error(w, "signer error", http.StatusInternalServerError)
				return
			}

			// client_id may arrive as a form field or as HTTP Basic Auth user.
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
			idToken, err := jwt.Signed(signer).Claims(claims).Claims(userClaims).CompactSerialize()
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

		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{"sub": "test-user"}
			for k, v := range userClaims {
				resp[k] = v
			}
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(s.Close)
	return s, privKey
}

func TestOIDCAuth_LoginRedirect(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	cfg := OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	auth, err := NewOIDCAuth(context.Background(), cfg)
	require.NoError(t, err)

	// Call HandleLogin with a dynamic redirect URL.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	r.Host = "grafana.example.com"
	state, verifier, nonce := auth.GenerateAuthParams()
	redirectURL := "https://grafana.example.com/oidc/callback"
	auth.HandleLogin(w, r, state, verifier, nonce, redirectURL)

	resp := w.Result()
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc, "Location header must be set")

	u, err := url.Parse(loc)
	require.NoError(t, err)

	q := u.Query()
	assert.Equal(t, "test-client", q.Get("client_id"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, state, q.Get("state"), "state in redirect must match returned state")
	assert.NotEmpty(t, q.Get("code_challenge"), "code_challenge must be present")
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, nonce, q.Get("nonce"), "nonce must be present in the auth request")
	assert.Equal(t, redirectURL, q.Get("redirect_uri"),
		"redirect_uri must match the dynamically derived URL")
}

func TestOIDCAuth_LoginRedirect_DifferentHosts(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	// Two different hosts should produce different redirect_uri values.
	hosts := []string{"grafana.example.com", "argocd.example.com"}
	for _, host := range hosts {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		state, verifier, nonce := auth.GenerateAuthParams()
		redirectURL := "https://" + host + "/oidc/callback"
		auth.HandleLogin(w, r, state, verifier, nonce, redirectURL)

		loc := w.Result().Header.Get("Location")
		u, err := url.Parse(loc)
		require.NoError(t, err)
		assert.Equal(t, redirectURL, u.Query().Get("redirect_uri"),
			"redirect_uri must use the host %q", host)
	}
}

func TestOIDCAuth_Callback(t *testing.T) {
	t.Parallel()
	// Per-test claims map so we can inject the generated nonce into the
	// id_token (the mock reads the map by reference at token time).
	claims := map[string]any{
		"email":  "alice@example.com",
		"name":   "Alice Example",
		"groups": []string{"engineering", "team-all"},
	}
	srv, _ := mockOIDCProviderWithClaims(t, claims)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	state, codeVerifier, nonce := auth.GenerateAuthParams()
	claims["nonce"] = nonce
	redirectURL := "https://grafana.example.com/oidc/callback"

	// Build the callback request with valid code and matching state.
	callbackURL := "/oidc/callback?code=valid-code&state=" + url.QueryEscape(state)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	r.Host = "grafana.example.com"

	identity, err := auth.HandleCallback(context.Background(), w, r, state, codeVerifier, nonce, redirectURL)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "alice@example.com", identity.Email)
	assert.Equal(t, "Alice Example", identity.Name)
	assert.Equal(t, []string{"engineering", "team-all"}, identity.Groups)
}

// TestOIDCAuth_Callback_RejectsNonceMismatch is the L-3 regression test: an
// id_token whose nonce does not match the one we sent must be rejected.
func TestOIDCAuth_Callback_RejectsNonceMismatch(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"email":  "alice@example.com",
		"name":   "Alice Example",
		"groups": []string{"engineering"},
		"nonce":  "attacker-supplied-nonce", // not the one we generate
	}
	srv, _ := mockOIDCProviderWithClaims(t, claims)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	state, codeVerifier, nonce := auth.GenerateAuthParams()
	require.NotEqual(t, "attacker-supplied-nonce", nonce)
	redirectURL := "https://grafana.example.com/oidc/callback"

	callbackURL := "/oidc/callback?code=valid-code&state=" + url.QueryEscape(state)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	r.Host = "grafana.example.com"

	_, err = auth.HandleCallback(context.Background(), w, r, state, codeVerifier, nonce, redirectURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce")
}

func TestOIDCAuth_Callback_WrongState(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	cfg := OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	auth, err := NewOIDCAuth(context.Background(), cfg)
	require.NoError(t, err)

	_, codeVerifier, nonce := auth.GenerateAuthParams()
	redirectURL := "https://grafana.example.com/oidc/callback"

	// Provide a different state than the expected one.
	callbackURL := "/oidc/callback?code=valid-code&state=wrong-state"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	r.Host = "grafana.example.com"

	_, err = auth.HandleCallback(context.Background(), w, r, "expected-state", codeVerifier, nonce, redirectURL)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "state"), "error should mention state mismatch")
}

func TestOIDCAuth_GenerateAuthParams(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	cfg := OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	auth, err := NewOIDCAuth(context.Background(), cfg)
	require.NoError(t, err)

	state1, verifier1, nonce1 := auth.GenerateAuthParams()
	state2, verifier2, nonce2 := auth.GenerateAuthParams()

	// Each call must produce unique values.
	assert.NotEmpty(t, state1)
	assert.NotEmpty(t, verifier1)
	assert.NotEmpty(t, nonce1)
	assert.NotEqual(t, state1, state2, "states must be unique across calls")
	assert.NotEqual(t, verifier1, verifier2, "verifiers must be unique across calls")
	assert.NotEqual(t, nonce1, nonce2, "nonces must be unique across calls")
}

func TestOIDCAuth_Callback_InvalidCode(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	state, verifier, nonce := auth.GenerateAuthParams()
	redirectURL := "https://grafana.example.com/oidc/callback"

	callbackURL := "/oidc/callback?code=invalid-code&state=" + url.QueryEscape(state)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	r.Host = "grafana.example.com"

	_, err = auth.HandleCallback(context.Background(), w, r, state, verifier, nonce, redirectURL)
	require.Error(t, err, "invalid code should fail token exchange")
}

func TestOIDCAuth_Callback_MissingCode(t *testing.T) {
	t.Parallel()
	srv, _ := mockOIDCProvider(t)

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	state, verifier, nonce := auth.GenerateAuthParams()
	redirectURL := "https://grafana.example.com/oidc/callback"

	// No code parameter at all.
	callbackURL := "/oidc/callback?state=" + url.QueryEscape(state)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	r.Host = "grafana.example.com"

	_, err = auth.HandleCallback(context.Background(), w, r, state, verifier, nonce, redirectURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing code")
}

// runCallbackWithClaims is a helper that completes a successful-shape OIDC
// callback against a mock provider returning the given user claims, and
// returns the (identity, error) from HandleCallback. Used by the negative
// tests below to verify that bad claims cause HandleCallback to return an
// error rather than silently producing a malformed identity.
func runCallbackWithClaims(t *testing.T, userClaims map[string]any) (*Identity, error) {
	t.Helper()

	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL:    mustMockIssuer(t, userClaims),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	state, codeVerifier, nonce := auth.GenerateAuthParams()
	// The id_token must echo the nonce we sent in the auth request; the mock
	// merges userClaims into the token, so inject it there (the mock holds the
	// map by reference and reads it at token time).
	userClaims["nonce"] = nonce
	redirectURL := "https://grafana.example.com/oidc/callback"

	callbackURL := "/oidc/callback?code=valid-code&state=" + url.QueryEscape(state)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	r.Host = "grafana.example.com"

	return auth.HandleCallback(context.Background(), w, r, state, codeVerifier, nonce, redirectURL)
}

// mustMockIssuer builds a mock provider with the given claims and returns its
// issuer URL. Split out so callers that need the claims map by reference (to
// inject a per-call nonce) can keep using it after construction.
func mustMockIssuer(t *testing.T, userClaims map[string]any) string {
	t.Helper()
	srv, _ := mockOIDCProviderWithClaims(t, userClaims)
	return srv.URL
}

func TestOIDCAuth_Callback_RejectsMissingEmail(t *testing.T) {
	t.Parallel()
	// An id_token without an email claim is unusable — beyond uses email
	// as the stable identifier for authorization and logging. Reject the
	// login rather than silently producing an identity with Email="".
	_, err := runCallbackWithClaims(t, map[string]any{
		"name":   "Alice Example",
		"groups": []string{"engineering"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}

func TestOIDCAuth_Callback_RejectsMalformedEmail(t *testing.T) {
	t.Parallel()
	_, err := runCallbackWithClaims(t, map[string]any{
		"email":  "not-an-email",
		"name":   "Alice Example",
		"groups": []string{"engineering"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid address")
}

func TestOIDCAuth_Callback_RejectsControlCharInEmail(t *testing.T) {
	t.Parallel()
	_, err := runCallbackWithClaims(t, map[string]any{
		"email":  "alice\r\nX-Evil: yes@example.com",
		"name":   "Alice",
		"groups": []string{"engineering"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "control characters")
}

func TestOIDCAuth_Callback_RejectsControlCharInName(t *testing.T) {
	t.Parallel()
	_, err := runCallbackWithClaims(t, map[string]any{
		"email":  "alice@example.com",
		"name":   "Alice\r\nX-Injected: yes",
		"groups": []string{"engineering"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name claim")
}

func TestOIDCAuth_Callback_RejectsPipeInGroup(t *testing.T) {
	t.Parallel()
	_, err := runCallbackWithClaims(t, map[string]any{
		"email":  "alice@example.com",
		"name":   "Alice",
		"groups": []string{"engineering", "plat|form"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delimiter")
}

func TestOIDCAuth_Callback_FallsBackToPreferredUsername(t *testing.T) {
	t.Parallel()
	id, err := runCallbackWithClaims(t, map[string]any{
		"email":              "alice@example.com",
		"preferred_username": "alice.e",
		"groups":             []string{"engineering"},
	})
	require.NoError(t, err)
	assert.Equal(t, "alice.e", id.Name, "should fall back to preferred_username when name is absent")
}

func TestOIDCAuth_Callback_FallsBackToEmailLocalPart(t *testing.T) {
	t.Parallel()
	// No `name`, no `preferred_username` — display name derived from email.
	id, err := runCallbackWithClaims(t, map[string]any{
		"email":  "alice@example.com",
		"groups": []string{"engineering"},
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", id.Name)
}

func TestOIDCAuth_Callback_TruncatesLongName(t *testing.T) {
	t.Parallel()
	// An absurdly long name should be truncated, not rejected. Display
	// names are cosmetic; we don't want to lock users out over an IdP
	// attribute that might be outside their control.
	longName := strings.Repeat("A", maxNameLen+200)
	id, err := runCallbackWithClaims(t, map[string]any{
		"email":  "alice@example.com",
		"name":   longName,
		"groups": []string{"engineering"},
	})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(id.Name), maxNameLen)
}
