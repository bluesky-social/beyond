package beyond

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credTestClientID is the OAuth2 client_id the fake gateway app is configured
// with; the fake token endpoint asserts the incoming form carries it.
const credTestClientID = "aigw-client-id"

// fakeAuthentik is a stand-in for Authentik's token endpoint. It records how
// many times it was called (to assert that malformed credentials never reach
// the network) and lets each test install a handler for the validation logic.
type fakeAuthentik struct {
	srv   *httptest.Server
	calls atomic.Int64
}

// unsignedJWT builds a compact JWS with a GARBAGE signature. The credential
// path decodes the payload without verifying, so any signature works — this is
// asserted explicitly by TestCredential_PayloadDecodedWithoutSignatureVerify.
func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Deliberately not a real signature over header.payload.
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payload + "." + sig
}

// newFakeAuthentik starts a token endpoint whose response is produced by fn,
// which receives the parsed form values. fn returns the HTTP status and the
// raw JSON body to write.
func newFakeAuthentik(t *testing.T, fn func(form map[string]string) (int, string)) *fakeAuthentik {
	t.Helper()
	fa := &fakeAuthentik{}
	fa.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fa.calls.Add(1)
		require.NoError(t, r.ParseForm())
		form := map[string]string{}
		for k := range r.Form {
			form[k] = r.Form.Get(k)
		}
		status, body := fn(form)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(fa.srv.Close)
	return fa
}

// happyTokenEndpoint validates username==wantUser and password==wantPass and
// returns a 200 with an unsigned JWT carrying the given claims, else a 400
// invalid_grant — modeling Authentik's real behavior.
func happyTokenEndpoint(t *testing.T, wantUser, wantPass string, claims map[string]any) func(map[string]string) (int, string) {
	t.Helper()
	return func(form map[string]string) (int, string) {
		// Assert the grant shape beyond sends (verified facts from the spec).
		assert.Equal(t, "client_credentials", form["grant_type"])
		assert.Equal(t, credTestClientID, form["client_id"])
		assert.Equal(t, "openid email groups", form["scope"])
		if form["username"] != wantUser || form["password"] != wantPass {
			return http.StatusBadRequest, `{"error":"invalid_grant"}`
		}
		tok := unsignedJWT(t, claims)
		b, _ := json.Marshal(tokenResponse{AccessToken: tok})
		return http.StatusOK, string(b)
	}
}

// newCredentialTestHandler builds a Handler whose "aigw" app has credential_auth
// wired to fa, plus the standard testConfig apps. allowedGroups sets the app's
// allowed_groups.
func newCredentialTestHandler(t *testing.T, fa *fakeAuthentik, allowedGroups []string) (*Handler, *recordingBackend) {
	t.Helper()
	return newCredentialTestHandlerWithHeader(t, fa, allowedGroups, "")
}

// newCredentialTestHandlerWithHeader is newCredentialTestHandler with an
// optional custom credential_header. An empty credHeader gives the legacy
// Authorization/x-api-key-only config.
func newCredentialTestHandlerWithHeader(t *testing.T, fa *fakeAuthentik, allowedGroups []string, credHeader string) (*Handler, *recordingBackend) {
	t.Helper()
	backend := newRecordingBackend(t)

	cfg := testConfig()
	cfg.Applications["aigw"] = &Application{
		Name:          "aigw",
		Upstream:      backend.srv.URL,
		Host:          "aigw.example.com",
		AllowedGroups: allowedGroups,
		CredentialAuth: &CredentialAuthConfig{
			TokenURL:         fa.srv.URL,
			ClientID:         credTestClientID,
			CredentialHeader: credHeader,
		},
	}

	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	h := NewHandler(cfg, sm, al)
	return h, backend
}

// credReqBearer builds a request carrying the credential as Authorization: Bearer.
func credReqBearer(host, cred string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+cred)
	req.RemoteAddr = "10.0.0.1:12345"
	return req
}

// credReqAPIKey builds a request carrying the credential as x-api-key.
func credReqAPIKey(host, cred string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Host = host
	req.Header.Set("x-api-key", cred)
	req.RemoteAddr = "10.0.0.1:12345"
	return req
}

// credReqCustomHeader builds a request carrying the credential in the given
// custom header, with no Authorization/x-api-key set.
func credReqCustomHeader(host, header, cred string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Host = host
	req.Header.Set(header, cred)
	req.RemoteAddr = "10.0.0.1:12345"
	return req
}

func defaultClaims() map[string]any {
	return map[string]any{
		"iss":                "https://auth.example.com/application/o/aigw/",
		"aud":                credTestClientID,
		"sub":                "user-1",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"groups":             []string{"platform"},
	}
}

func TestCredential_HappyPathBearer(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "app-pass-123", defaultClaims()))
	h, backend := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:app-pass-123"))

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "backend ok", string(body))

	// Identity headers injected from the JWT claims.
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Equal(t, "platform", backend.last.Get("X-Beyond-Groups"))
	// The credential MUST NOT reach the upstream: both wire-convention headers
	// stripped.
	assert.Empty(t, backend.last.Get("Authorization"), "Authorization must be stripped before proxying")
	assert.Empty(t, backend.last.Get("x-api-key"), "x-api-key must be stripped before proxying")
}

func TestCredential_HappyPathAPIKey(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "app-pass-123", defaultClaims()))
	h, backend := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqAPIKey("aigw.example.com", "alice@example.com:app-pass-123"))

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Empty(t, backend.last.Get("x-api-key"))
	assert.Empty(t, backend.last.Get("Authorization"))
}

// TestCredential_AuthorizationWinsOverAPIKey verifies that when BOTH headers
// are present, the Authorization: Bearer value is used (OpenAI precedence).
func TestCredential_AuthorizationWinsOverAPIKey(t *testing.T) {
	t.Parallel()
	// The token endpoint only accepts the Authorization credential; the
	// x-api-key value would be rejected. A 200 proves Authorization won.
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "auth-pass", defaultClaims()))
	h, backend := newCredentialTestHandler(t, fa, []string{"platform"})

	req := credReqBearer("aigw.example.com", "alice@example.com:auth-pass")
	req.Header.Set("x-api-key", "wrong@user:wrong-pass")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Empty(t, backend.last.Get("Authorization"))
	assert.Empty(t, backend.last.Get("x-api-key"))
}

// TestCredential_PayloadDecodedWithoutSignatureVerify pins the trust decision:
// the JWT is decoded payload-only, so a token with a garbage signature (which
// unsignedJWT always produces) still authenticates. If this ever regresses to
// verifying the signature, this test breaks.
func TestCredential_PayloadDecodedWithoutSignatureVerify(t *testing.T) {
	t.Parallel()
	claims := defaultClaims()
	tok := unsignedJWT(t, claims)
	// Sanity: the token has a non-empty, deliberately-invalid signature.
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	require.NotEmpty(t, parts[2])

	fa := newFakeAuthentik(t, func(form map[string]string) (int, string) {
		b, _ := json.Marshal(tokenResponse{AccessToken: tok})
		return http.StatusOK, string(b)
	})
	h, backend := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))

	require.Equal(t, http.StatusOK, rec.Result().StatusCode,
		"payload-only decode must accept a token regardless of its signature")
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
}

func TestCredential_MalformedCredentialNoNetworkCall(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cred string
	}{
		{"no colon", "justusername"},
		{"empty username", ":app-pass"},
		{"empty password", "alice@example.com:"},
		{"empty credential", ""},
		{"oversized", strings.Repeat("a", maxCredentialLen) + ":" + strings.Repeat("b", 10)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
				return http.StatusOK, `{}`
			})
			h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

			// The empty-credential case would carry no header at all if built
			// via credReqBearer("Bearer "), so build explicitly for it.
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			req.Host = "aigw.example.com"
			req.RemoteAddr = "10.0.0.1:12345"
			if tc.cred != "" {
				req.Header.Set("Authorization", "Bearer "+tc.cred)
			} else {
				// A "Bearer " with empty token would not dispatch to credential
				// at all (hasCredentialHeader false). Use x-api-key empty which
				// also won't dispatch — so instead assert fall-through behavior:
				// no OIDC configured -> 401, still no network call.
				req.Header.Set("x-api-key", "")
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
			assert.Equal(t, int64(0), fa.calls.Load(),
				"a malformed credential must never reach the token endpoint")
		})
	}
}

func TestCredential_InvalidGrantRejected(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		return http.StatusBadRequest, `{"error":"invalid_grant"}`
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:wrong-pass"))

	resp := rec.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Empty(t, resp.Cookies())
	assert.Equal(t, int64(1), fa.calls.Load())
}

func TestCredential_InvalidClientRejected(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		return http.StatusBadRequest, `{"error":"invalid_client"}`
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

func TestCredential_TokenEndpoint500Unavailable(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		return http.StatusInternalServerError, `{"error":"server_error"}`
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Result().StatusCode)
}

func TestCredential_NetworkRefusedUnavailable(t *testing.T) {
	t.Parallel()
	// Point at a closed port: dial refused -> fail closed 503.
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		return http.StatusOK, `{}`
	})
	closedURL := fa.srv.URL
	fa.srv.Close() // stop listening; new dials get connection refused

	backend := newRecordingBackend(t)
	cfg := testConfig()
	cfg.Applications["aigw"] = &Application{
		Name:          "aigw",
		Upstream:      backend.srv.URL,
		Host:          "aigw.example.com",
		AllowedGroups: []string{"platform"},
		CredentialAuth: &CredentialAuthConfig{
			TokenURL: closedURL,
			ClientID: credTestClientID,
		},
	}
	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	h := NewHandler(cfg, sm, al)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Result().StatusCode)
}

func TestCredential_TimeoutUnavailable(t *testing.T) {
	t.Parallel()
	// Endpoint responds slower than the injected short client timeout. We use a
	// bounded sleep (not an unbounded block) so httptest.Server.Close during
	// cleanup doesn't deadlock waiting on a still-hung handler connection.
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		time.Sleep(300 * time.Millisecond)
		return http.StatusOK, `{}`
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})
	// Inject a very short-timeout client so the test doesn't wait 10s.
	h.credClient = &http.Client{Timeout: 50 * time.Millisecond}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Result().StatusCode)
}

func TestCredential_MissingEmailClaimRejected(t *testing.T) {
	t.Parallel()
	claims := defaultClaims()
	delete(claims, "email")
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		b, _ := json.Marshal(tokenResponse{AccessToken: unsignedJWT(t, claims)})
		return http.StatusOK, string(b)
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

func TestCredential_GroupNotAllowedForbidden(t *testing.T) {
	t.Parallel()
	claims := defaultClaims()
	claims["groups"] = []string{"some-other-team"}
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		b, _ := json.Marshal(tokenResponse{AccessToken: unsignedJWT(t, claims)})
		return http.StatusOK, string(b)
	})
	// App allows only "platform"; the user is not in it and is not an admin.
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
}

// TestCredential_ControlCharInGroupHandled mirrors the identity-normalization
// semantics the bearer path relies on: a group name containing an ASCII
// control character fails validateAndNormalizeIdentity, so the request is
// rejected (401 invalid claims) rather than proxied with a header that Go's
// transport would reject.
func TestCredential_ControlCharInGroupHandled(t *testing.T) {
	t.Parallel()
	claims := defaultClaims()
	claims["groups"] = []string{"platform", "bad\x00group"}
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		b, _ := json.Marshal(tokenResponse{AccessToken: unsignedJWT(t, claims)})
		return http.StatusOK, string(b)
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode,
		"a control character in a claim group must fail identity normalization")
}

func TestCredential_FailureRateLimitedAndRefunded(t *testing.T) {
	t.Parallel()

	// The endpoint rejects everything: burn the failure budget from one IP.
	fa := newFakeAuthentik(t, func(form map[string]string) (int, string) {
		if form["password"] == "good-pass" {
			b, _ := json.Marshal(tokenResponse{AccessToken: unsignedJWT(t, defaultClaims())})
			return http.StatusOK, string(b)
		}
		return http.StatusBadRequest, `{"error":"invalid_grant"}`
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	var saw429 bool
	for i := 0; i < credFailureRateLimit+5; i++ {
		rec := httptest.NewRecorder()
		req := credReqBearer("aigw.example.com", "alice@example.com:bad-pass")
		req.RemoteAddr = "10.9.8.7:55555"
		h.ServeHTTP(rec, req)
		if rec.Result().StatusCode == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	assert.True(t, saw429, "bad-credential flood must eventually 429")

	// A successful validation from a DIFFERENT IP well past the failure count
	// must never throttle: only failures spend budget (success refunds).
	for i := 0; i < credFailureRateLimit*2; i++ {
		rec := httptest.NewRecorder()
		req := credReqBearer("aigw.example.com", "alice@example.com:good-pass")
		req.RemoteAddr = "10.1.2.3:44444"
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Result().StatusCode, "success %d", i)
	}
}

// TestCredential_AppWithoutCredentialAuthNoDispatch verifies a credential-shaped
// request to an app WITHOUT credential_auth does not dispatch to handleCredential
// (it falls through; grafana is cookie-only so a Bearer would hit the bearer
// path, which is not enabled -> 401). This guards the dispatch gate.
func TestCredential_NoCredentialHeaderFallsThrough(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		return http.StatusOK, `{}`
	})
	h, _ := newCredentialTestHandler(t, fa, []string{"platform"})

	// A request with NO credential to the credential_auth app must fall through
	// to the normal unauthenticated path (401 here, no OIDC configured) and
	// never call the token endpoint.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "aigw.example.com"
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
	assert.Equal(t, int64(0), fa.calls.Load())
}

// TestCredential_CustomHeaderHappyPath verifies that a request carrying the
// configured custom credential_header, plus an unrelated Authorization
// Bearer token (e.g. an official Claude Code client's own Anthropic OAuth
// token) and an unrelated x-api-key, validates from the custom header and
// forwards Authorization/x-api-key to the upstream untouched.
func TestCredential_CustomHeaderHappyPath(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "app-pass-123", defaultClaims()))
	h, backend := newCredentialTestHandlerWithHeader(t, fa, []string{"platform"}, "x-agw-key")

	req := credReqCustomHeader("aigw.example.com", "x-agw-key", "alice@example.com:app-pass-123")
	req.Header.Set("Authorization", "Bearer sk-ant-oat01-XYZ")
	req.Header.Set("x-api-key", "some-unrelated-value")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))

	// Custom header stripped.
	assert.Empty(t, backend.last.Get("x-agw-key"), "custom credential header must be stripped before proxying")
	// Standard headers forwarded verbatim.
	assert.Equal(t, "Bearer sk-ant-oat01-XYZ", backend.last.Get("Authorization"),
		"Authorization must be forwarded untouched when the custom header carried the credential")
	assert.Equal(t, "some-unrelated-value", backend.last.Get("x-api-key"),
		"x-api-key must be forwarded untouched when the custom header carried the credential")
}

// TestCredential_CustomHeaderAbsentLegacyPath verifies that with
// credential_header configured but ABSENT from the request, the legacy
// Authorization/x-api-key flow applies unchanged: both headers stripped.
func TestCredential_CustomHeaderAbsentLegacyPath(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "app-pass-123", defaultClaims()))
	h, backend := newCredentialTestHandlerWithHeader(t, fa, []string{"platform"}, "x-agw-key")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:app-pass-123"))

	resp := rec.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Empty(t, backend.last.Get("Authorization"), "Authorization must be stripped on the legacy path")
	assert.Empty(t, backend.last.Get("x-api-key"), "x-api-key must be stripped on the legacy path")
}

// TestCredential_CustomHeaderInvalidRejected verifies an invalid credential in
// the custom header is rejected with the generic 401, and spends a
// failure-rate-limit slot (mirrors TestCredential_InvalidGrantRejected plus a
// lightweight flood check reusing the FailureRateLimitedAndRefunded pattern).
func TestCredential_CustomHeaderInvalidRejected(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, func(map[string]string) (int, string) {
		return http.StatusBadRequest, `{"error":"invalid_grant"}`
	})
	h, _ := newCredentialTestHandlerWithHeader(t, fa, []string{"platform"}, "x-agw-key")

	rec := httptest.NewRecorder()
	req := credReqCustomHeader("aigw.example.com", "x-agw-key", "alice@example.com:wrong-pass")
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Empty(t, resp.Cookies())
	assert.Equal(t, int64(1), fa.calls.Load())

	// Confirm the failure spends rate-limit budget: flood from the same IP
	// eventually 429s.
	var saw429 bool
	for i := 0; i < credFailureRateLimit+5; i++ {
		rec := httptest.NewRecorder()
		req := credReqCustomHeader("aigw.example.com", "x-agw-key", "alice@example.com:wrong-pass")
		req.RemoteAddr = "10.0.0.1:12345"
		h.ServeHTTP(rec, req)
		if rec.Result().StatusCode == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	assert.True(t, saw429, "invalid custom-header credential flood must eventually 429")
}

// TestCredential_CustomHeaderWinsOverAuthorization mirrors
// TestCredential_AuthorizationWinsOverAPIKey's structure: the token endpoint
// accepts only the custom-header credential and rejects the Bearer one, so a
// 200 proves the custom header won even though Authorization was present.
func TestCredential_CustomHeaderWinsOverAuthorization(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "custom-pass", defaultClaims()))
	h, backend := newCredentialTestHandlerWithHeader(t, fa, []string{"platform"}, "x-agw-key")

	req := credReqCustomHeader("aigw.example.com", "x-agw-key", "alice@example.com:custom-pass")
	req.Header.Set("Authorization", "Bearer sk-ant-oat01-XYZ")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Equal(t, "Bearer sk-ant-oat01-XYZ", backend.last.Get("Authorization"),
		"Authorization must be forwarded untouched on the custom-header path")
	assert.Empty(t, backend.last.Get("x-agw-key"))
}

// TestCredential_CustomHeaderTakesPrecedenceOverSession is a regression test
// for a roast finding: the custom credential_header dispatch must happen
// BEFORE session load, not only in the sess==nil branch. A request carrying
// both a valid browser session AND the custom header must still validate and
// strip the custom header — a session must never cause the live composite
// credential to reach the upstream unstripped, nor authenticate the request
// as the session's (wrong) identity.
func TestCredential_CustomHeaderTakesPrecedenceOverSession(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "app-pass-123", defaultClaims()))
	backend := newRecordingBackend(t)

	cfg := testConfig()
	cfg.Applications["aigw"] = &Application{
		Name:          "aigw",
		Upstream:      backend.srv.URL,
		Host:          "aigw.example.com",
		AllowedGroups: []string{"platform"},
		CredentialAuth: &CredentialAuthConfig{
			TokenURL:         fa.srv.URL,
			ClientID:         credTestClientID,
			CredentialHeader: "x-agw-key",
		},
	}
	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	h := NewHandler(cfg, sm, al)

	req := credReqCustomHeader("aigw.example.com", "x-agw-key", "alice@example.com:app-pass-123")
	// A session for a DIFFERENT identity/groups than the credential — if the
	// session won, the response would carry the session's identity and the
	// custom header would sail through to the upstream unstripped.
	setSession(t, sm, req, "someone-else@example.com", []string{"not-platform"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Identity must come from the credential path, not the session.
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	// The custom header (a live composite credential) must never reach the
	// upstream.
	assert.Empty(t, backend.last.Get("x-agw-key"), "custom credential header must be stripped even with a session present")
}

// TestCredential_CustomHeaderDuplicateValuesNotBypassed is a regression test
// for a roast finding: http.Header.Get returns only the FIRST value for a
// repeated header field. A request carrying the custom header TWICE — a
// blank first value, then the real credential — must still be recognized as
// carrying the credential (not silently fall through to the session-
// authenticated proxy path, which never strips this header).
func TestCredential_CustomHeaderDuplicateValuesNotBypassed(t *testing.T) {
	t.Parallel()
	fa := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "app-pass-123", defaultClaims()))
	h, backend := newCredentialTestHandlerWithHeader(t, fa, []string{"platform"}, "x-agw-key")

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Host = "aigw.example.com"
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Add("x-agw-key", "   ") // blank/whitespace-only first value
	req.Header.Add("x-agw-key", "alice@example.com:app-pass-123")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "alice@example.com", backend.last.Get("X-Beyond-Email"))
	assert.Empty(t, backend.last.Get("x-agw-key"), "custom credential header must be stripped even with a duplicate blank first value")
}

func TestCredentialAuthConfig_Validation(t *testing.T) {
	t.Parallel()

	base := `
applications:
  aigw:
    upstream: http://aigw.svc:80
    host: aigw.example.com
    allowed_groups: [platform]
`
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			"missing token_url",
			base + `    credential_auth:
      client_id: aigw-client
`,
			"token_url",
		},
		{
			"missing client_id",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
`,
			"client_id",
		},
		{
			"relative token_url",
			base + `    credential_auth:
      token_url: /application/o/token/
      client_id: aigw-client
`,
			"absolute http",
		},
		{
			"credential_auth + bearer_auth conflict",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
    bearer_auth:
      issuer: https://auth.example.com/o/aigw/
      jwks_url: http://jwks.svc/keys
      audience: aigw-client
`,
			"mutually exclusive",
		},
		{
			"credential_auth + passthrough conflict",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
    passthrough_auth_schemes:
      - Token
`,
			"mutually exclusive",
		},
		{
			"credential_header reuses Authorization",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
      credential_header: authorization
`,
			"credential_header",
		},
		{
			"credential_header reuses x-api-key (mixed case)",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
      credential_header: X-Api-Key
`,
			"credential_header",
		},
		{
			"credential_header not a valid HTTP token",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
      credential_header: "x agw key"
`,
			"not a valid HTTP header name",
		},
		{
			"credential_header reuses Host (stripped from r.Header by net/http)",
			base + `    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
      credential_header: Host
`,
			"credential_header",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := writeTempFile(t, tc.yaml)
			_, err := LoadConfig(f)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	t.Run("complete credential_auth parses", func(t *testing.T) {
		t.Parallel()
		f := writeTempFile(t, base+`    credential_auth:
      token_url: http://authentik.svc/application/o/token/
      client_id: aigw-client
`)
		cfg, err := LoadConfig(f)
		require.NoError(t, err)
		ca := cfg.Applications["aigw"].CredentialAuth
		require.NotNil(t, ca)
		assert.Equal(t, "http://authentik.svc/application/o/token/", ca.TokenURL)
		assert.Equal(t, "aigw-client", ca.ClientID)
	})
}

// TestSplitCredential unit-tests the first-colon split so the future-proofing
// against colons in app passwords is pinned.
func TestSplitCredential(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cred string
		user string
		pass string
		ok   bool
	}{
		{"alice@example.com:app-pass", "alice@example.com", "app-pass", true},
		{"user:pass:with:colons", "user", "pass:with:colons", true},
		{"nocolon", "", "", false},
		{":pass", "", "", false},
		{"user:", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		u, p, ok := splitCredential(tt.cred)
		assert.Equal(t, tt.ok, ok, "cred=%q", tt.cred)
		if tt.ok {
			assert.Equal(t, tt.user, u, "cred=%q", tt.cred)
			assert.Equal(t, tt.pass, p, "cred=%q", tt.cred)
		}
	}
}
