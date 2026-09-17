package beyond

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func portalTestHandler(t *testing.T) (*Handler, *SessionManager) {
	t.Helper()
	cfg := testConfig()
	cfg.Portal = &PortalConfig{Host: "access.internal", Title: "Internal services"}
	cfg.Applications["grafana"].DisplayName = "Grafana"
	cfg.Applications["grafana"].Description = "Metrics and dashboards"
	cfg.Applications["grafana"].LaunchURL = "https://grafana.internal/"
	cfg.Applications["argocd"].DisplayName = "Argo CD"
	cfg.Applications["argocd"].Description = "Deployments"
	cfg.Applications["argocd"].LaunchURL = "https://argocd.internal/"

	sm := testSessionManager(t)
	h := NewHandler(cfg, sm, &AccessLogger{Logger: testLogger()})
	return h, sm
}

func TestPortal_AuthenticatedUserSeesOnlyAllowedApplications(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	html := string(body)
	assert.Contains(t, html, "Internal services")
	assert.Contains(t, html, "alice@example.com")
	assert.Contains(t, html, "Grafana")
	assert.Contains(t, html, "Metrics and dashboards")
	assert.Contains(t, html, `href="https://grafana.internal/"`)
	assert.NotContains(t, html, `href="/admin/access-logs"`)
	assert.NotContains(t, html, "Argo CD")
	assert.NotContains(t, html, "Deployments")
	assert.NotContains(t, html, "platform")
	assert.NotContains(t, html, "http://localhost:8080")
}

func TestPortal_AdminSeesAllApplicationsInStableOrder(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	h.SetAccessLogQueryStore(&recordingAccessLogQueryStore{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)

	html := string(body)
	assert.Less(t, len(html), 16*1024, "the portal should remain a small document")
	assert.Contains(t, html, `href="/admin/access-logs"`)
	assert.Less(t, stringIndex(t, html, "Argo CD"), stringIndex(t, html, "Grafana"))
}

func TestPortal_AdminDoesNotSeeAccessLogsWithoutClickHouse(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), `href="/admin/access-logs"`)
}

func TestPortal_EmptyState(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "guest@example.com", []string{"unrelated"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, string(body), "No applications are available for your account.")
	assert.NotContains(t, string(body), "Grafana")
}

func TestPortal_SecurityHeaders(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'none'")
	assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestPortal_UsesFreshGroupsFromUserValidator(t *testing.T) {
	t.Parallel()
	authentikSrv := fakeAuthentikServerWithGroups(t, "platform")
	defer authentikSrv.Close()

	h, sm := portalTestHandler(t)
	validator := NewUserValidator(authentikSrv.URL, "token")
	t.Cleanup(validator.Stop)
	h.SetUserValidator(validator)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Argo CD")
	assert.NotContains(t, rec.Body.String(), "Grafana")
}

func TestPortal_DeactivatedUserIsDeniedAndSessionCleared(t *testing.T) {
	t.Parallel()
	authentikSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authentikUserResponse{Results: []authentikUserRow{{IsActive: false}}})
	}))
	defer authentikSrv.Close()

	h, sm := portalTestHandler(t)
	validator := NewUserValidator(authentikSrv.URL, "token")
	t.Cleanup(validator.Stop)
	h.SetUserValidator(validator)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "deactivated")
	cookie := cookieFromRecorder(t, rec, sessionCookieName)
	require.NotNil(t, cookie)
	assert.Equal(t, -1, cookie.MaxAge)
}

func TestPortal_EscapesPresentationData(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	h.authorizer.mu.Lock()
	h.authorizer.applications[0].DisplayName = `<script>alert("x")</script>`
	h.authorizer.applications[0].Description = `<img src=x onerror=alert("x")>`
	h.authorizer.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "<script>")
	assert.NotContains(t, rec.Body.String(), "<img")
	assert.Contains(t, rec.Body.String(), "&lt;script&gt;")
}

func TestPortal_UnauthenticatedRequestStartsOIDCLogin(t *testing.T) {
	t.Parallel()
	h, _ := portalTestHandler(t)
	srv, _ := mockOIDCProvider(t)
	auth, err := NewOIDCAuth(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "test-client", ClientSecret: "test-secret",
	})
	require.NoError(t, err)
	h.SetOIDCAuth(auth)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "access.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://access.internal/oidc/callback", location.Query().Get("redirect_uri"))
}

func TestPortal_RejectsOtherPathsAndMethods(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)

	pathReq := httptest.NewRequest(http.MethodGet, "/private", nil)
	pathReq.Host = "access.internal"
	setSession(t, sm, pathReq, "alice@example.com", []string{"engineering"})
	pathRec := httptest.NewRecorder()
	h.ServeHTTP(pathRec, pathReq)
	assert.Equal(t, http.StatusNotFound, pathRec.Code)

	methodReq := httptest.NewRequest(http.MethodPost, "/", nil)
	methodReq.Host = "access.internal"
	setSession(t, sm, methodReq, "alice@example.com", []string{"engineering"})
	methodRec := httptest.NewRecorder()
	h.ServeHTTP(methodRec, methodReq)
	assert.Equal(t, http.StatusMethodNotAllowed, methodRec.Code)
	assert.Equal(t, "GET", methodRec.Header().Get("Allow"))
}

func TestPortal_ReloadMovesPortalHost(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	cfg := testConfig()
	cfg.Portal = &PortalConfig{Host: "new-access.internal", Title: "Services"}
	h.ReloadConfig(cfg)

	oldReq := httptest.NewRequest(http.MethodGet, "/", nil)
	oldReq.Host = "access.internal"
	setSession(t, sm, oldReq, "alice@example.com", []string{"engineering"})
	oldRec := httptest.NewRecorder()
	h.ServeHTTP(oldRec, oldReq)
	assert.Equal(t, http.StatusNotFound, oldRec.Code)

	newReq := httptest.NewRequest(http.MethodGet, "/", nil)
	newReq.Host = "new-access.internal"
	setSession(t, sm, newReq, "alice@example.com", []string{"engineering"})
	newRec := httptest.NewRecorder()
	h.ServeHTTP(newRec, newReq)
	assert.Equal(t, http.StatusOK, newRec.Code)
}

func stringIndex(t *testing.T, haystack, needle string) int {
	t.Helper()
	i := strings.Index(haystack, needle)
	require.NotEqual(t, -1, i, "%q not found", needle)
	return i
}
