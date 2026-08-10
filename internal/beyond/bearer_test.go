package beyond

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bearerTestIDP is a minimal fake Authentik: an RSA key, a JWKS endpoint
// serving its public half, and a mint helper producing signed access tokens.
type bearerTestIDP struct {
	key     *rsa.PrivateKey
	signer  jose.Signer
	jwksSrv *httptest.Server
}

const bearerTestKid = "bearer-test-key"

func newBearerTestIDP(t *testing.T) *bearerTestIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     bearerTestKid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksSrv.Close)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", bearerTestKid),
	)
	require.NoError(t, err)

	return &bearerTestIDP{key: key, signer: signer, jwksSrv: jwksSrv}
}

func (idp *bearerTestIDP) mint(t *testing.T, iss, aud string, exp time.Time, groups []string) string {
	t.Helper()
	claims := map[string]any{
		"iss":                iss,
		"aud":                aud,
		"sub":                "op-1",
		"exp":                exp.Unix(),
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"groups":             groups,
	}
	s, err := jwt.Signed(idp.signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return s
}

const (
	bearerTestIssuer   = "https://auth.example.com/application/o/skipper/"
	bearerTestAudience = "skipper-client-id"
)

// newBearerTestHandler builds a Handler whose "skipper" app has bearer_auth
// wired to the fake IdP, plus a cookie-only "argocd" app for cross-checks.
// Returns the handler, the IdP, and the backend that records what it saw.
func newBearerTestHandler(t *testing.T) (*Handler, *bearerTestIDP, *recordingBackend) {
	t.Helper()
	idp := newBearerTestIDP(t)
	backend := newRecordingBackend(t)

	cfg := testConfig()
	cfg.Applications["skipper"] = &Application{
		Name:          "skipper",
		Upstream:      backend.srv.URL,
		Host:          "skipper.example.com",
		AllowedGroups: []string{"platform"},
		BearerAuth: &BearerAuthConfig{
			Issuer:   bearerTestIssuer,
			JWKSURL:  idp.jwksSrv.URL,
			Audience: bearerTestAudience,
		},
	}

	sm := testSessionManager(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	al := &AccessLogger{Logger: logger}
	h := NewHandler(cfg, sm, al)
	return h, idp, backend
}

// recordingBackend captures the headers of the last proxied request.
type recordingBackend struct {
	srv  *httptest.Server
	last http.Header
}

func newRecordingBackend(t *testing.T) *recordingBackend {
	t.Helper()
	rb := &recordingBackend{}
	rb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb.last = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	t.Cleanup(rb.srv.Close)
	return rb
}

func bearerReq(host, token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestBearer_ValidTokenProxies(t *testing.T) {
	t.Parallel()
	h, idp, backend := newBearerTestHandler(t)

	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"platform"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "backend ok", string(body))

	// Identity headers injected from claims.
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Equal(t, "platform", backend.last.Get("X-Beyond-Groups"))
	// Original bearer forwarded so the upstream can re-verify.
	assert.Equal(t, "Bearer "+tok, backend.last.Get("Authorization"))
}

func TestBearer_GroupsFeedSameAuthorizer(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	// Authenticated but in the wrong group -> 403 from the same
	// allowed_groups check the cookie path uses.
	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))
	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
}

// TestBearer_StripsSpoofedIdentityHeaders covers a testing gap: the bearer
// path must strip client-supplied X-Beyond-* headers and replace them with the
// verified token identity, just like the cookie path.
func TestBearer_StripsSpoofedIdentityHeaders(t *testing.T) {
	t.Parallel()
	h, idp, backend := newBearerTestHandler(t)

	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"platform"})
	req := bearerReq("skipper.example.com", tok)
	// Client tries to smuggle spoofed identity headers.
	req.Header.Set("X-Beyond-User", "attacker@evil.com")
	req.Header.Set("X-Beyond-Email", "attacker@evil.com")
	req.Header.Set("X-Beyond-Groups", "authentik Admins")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Result().StatusCode)

	// Upstream must see the verified token identity, not the spoofed values.
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-User"))
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Equal(t, "platform", backend.last.Get("X-Beyond-Groups"))
}

// TestBearer_DecisionUsesNormalizedGroups is the L-4 regression test: the
// allow/deny decision must run on the SAME normalized group set that gets
// injected upstream, not the raw claim groups. Normalization caps the list at
// maxGroups; if the allowed group sits beyond that cap it is dropped, so a
// decision on the raw claims would ALLOW while the upstream would never see
// the group. The decision must instead deny, matching the injected set.
func TestBearer_DecisionUsesNormalizedGroups(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	// maxGroups filler groups, then the allowed "platform" beyond the cap.
	groups := make([]string, 0, maxGroups+1)
	for i := range maxGroups {
		groups = append(groups, fmt.Sprintf("filler-%d", i))
	}
	groups = append(groups, "platform") // index maxGroups -> dropped by the cap

	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), groups)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))

	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode,
		"an allowed group dropped by the maxGroups cap must deny: the decision must use the normalized set, not raw claims")
}

func TestBearer_AdminGroupBypass(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	// admin_groups bypass applies to bearer identities exactly as to
	// cookie identities.
	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

func TestBearer_InvalidTokensRejectedNoRedirect(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	cases := []struct {
		name string
		tok  string
	}{
		{"garbage", "not-a-jwt"},
		{"expired", idp.mint(t, bearerTestIssuer, bearerTestAudience,
			time.Now().Add(-time.Hour), []string{"platform"})},
		{"wrong issuer", idp.mint(t, "https://evil.example.com/", bearerTestAudience,
			time.Now().Add(time.Hour), []string{"platform"})},
		{"wrong audience", idp.mint(t, bearerTestIssuer, "other-client",
			time.Now().Add(time.Hour), []string{"platform"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, bearerReq("skipper.example.com", tc.tok))
			resp := rec.Result()
			// Plain 401: never a 302 to the IdP, never a session cookie.
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"))
			assert.Empty(t, resp.Cookies())
		})
	}
}

func TestBearer_AppWithoutBearerAuthRejectsBearers(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	// argocd has no bearer_auth: a bearer-carrying request must get an
	// explicit 401, NOT fall through to the cookie/redirect flow.
	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"platform"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("argocd.internal", tok))
	resp := rec.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
}

func TestBearer_CookiePathUnaffected(t *testing.T) {
	t.Parallel()
	h, _, backend := newBearerTestHandler(t)
	_ = backend

	// No Authorization header on a bearer_auth app -> the normal
	// unauthenticated flow (401 here because the test handler has no
	// OIDCAuth configured, mirroring TestHandler_UnauthenticatedRequest).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("skipper.example.com", ""))
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

// TestBearer_ValidSessionTakesPrecedenceOverBearer is the L-12 regression test:
// a browser that sends BOTH a valid session cookie and an Authorization Bearer
// header to a cookie-only app must be served via the cookie path, not forced
// down the bearer path (which would 401 since the app isn't bearer-enabled).
func TestBearer_ValidSessionTakesPrecedenceOverBearer(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("via cookie"))
	}))
	defer backend.Close()

	// grafana is a cookie-only app (no bearer_auth) in testConfig.
	h, sm := newTestHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "grafana.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	// Also attach a (irrelevant) bearer token, as a misconfigured client might.
	req.Header.Set("Authorization", "Bearer some-token")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"a valid session must win over a stray bearer header on a cookie-only app")
	body, _ := io.ReadAll(rec.Result().Body)
	assert.Equal(t, "via cookie", string(body))
}

func TestBearer_DeactivatedUserRejected(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	// Fake Authentik says the user is deactivated. A still-valid JWT must
	// not outlive the account (same gate the cookie path applies).
	authentikSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := authentikUserResponse{
			Results: []authentikUserRow{{IsActive: false}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(authentikSrv.Close)
	uv := NewUserValidator(authentikSrv.URL, "token")
	t.Cleanup(uv.Stop)
	h.SetUserValidator(uv)

	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"platform"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))

	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
	assert.Contains(t, rec.Body.String(), "deactivated")
}

func TestBearer_FailureRateLimited(t *testing.T) {
	t.Parallel()
	h, _, _ := newBearerTestHandler(t)

	// Hammer with garbage bearers from one IP: after the limit, requests
	// get 429 instead of reaching the verifier (JWKS-fetch DoS guard).
	var saw429 bool
	for i := 0; i < bearerFailureRateLimit+5; i++ {
		rec := httptest.NewRecorder()
		req := bearerReq("skipper.example.com", "garbage-token")
		req.RemoteAddr = "10.9.8.7:55555"
		h.ServeHTTP(rec, req)
		if rec.Result().StatusCode == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	assert.True(t, saw429, "garbage-bearer flood must eventually 429")
}

func TestBearer_SuccessesNotRateLimited(t *testing.T) {
	t.Parallel()
	h, idp, _ := newBearerTestHandler(t)

	// A healthy CLI polling well past the failure limit must never see a
	// 429: only failed verifications consume rate-limit budget.
	tok := idp.mint(t, bearerTestIssuer, bearerTestAudience,
		time.Now().Add(time.Hour), []string{"platform"})
	for i := 0; i < bearerFailureRateLimit*2; i++ {
		rec := httptest.NewRecorder()
		req := bearerReq("skipper.example.com", tok)
		req.RemoteAddr = "10.1.2.3:44444"
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Result().StatusCode, "request %d", i)
	}
}

func TestBearerAuthConfig_Validation(t *testing.T) {
	t.Parallel()
	base := `
applications:
  skipper:
    upstream: http://skipper.svc:80
    host: skipper.example.com
    allowed_groups: [platform]
    bearer_auth:
`
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			"missing issuer",
			base + `      jwks_url: http://jwks.svc/keys
      audience: client-id
`,
			"issuer",
		},
		{
			"missing jwks_url",
			base + `      issuer: https://auth.example.com/o/skipper/
      audience: client-id
`,
			"jwks_url",
		},
		{
			"missing audience",
			base + `      issuer: https://auth.example.com/o/skipper/
      jwks_url: http://jwks.svc/keys
`,
			"audience",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := writeTempFile(t,tc.yaml)
			_, err := LoadConfig(f)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("complete bearer_auth parses", func(t *testing.T) {
		f := writeTempFile(t,base+`      issuer: https://auth.example.com/o/skipper/
      jwks_url: http://jwks.svc/keys
      audience: client-id
`)
		cfg, err := LoadConfig(f)
		require.NoError(t, err)
		ba := cfg.Applications["skipper"].BearerAuth
		require.NotNil(t, ba)
		assert.Equal(t, "https://auth.example.com/o/skipper/", ba.Issuer)
		assert.Equal(t, "http://jwks.svc/keys", ba.JWKSURL)
		assert.Equal(t, "client-id", ba.Audience)
	})
}
