package beyond

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingAccessLogQueryStore struct {
	mu      sync.Mutex
	query   AccessLogQuery
	records []AccessLogRecord
	err     error
	calls   int
}

func (s *recordingAccessLogQueryStore) QueryAccessLogs(_ context.Context, query AccessLogQuery) ([]AccessLogRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.query = query
	return append([]AccessLogRecord(nil), s.records...), s.err
}

func (s *recordingAccessLogQueryStore) snapshot() (AccessLogQuery, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.query, s.calls
}

func accessLogViewerURL(values url.Values) string {
	now := time.Now().UTC()
	if values.Get("from") == "" {
		values.Set("from", now.Add(-2*time.Hour).Format(time.RFC3339))
	}
	if values.Get("to") == "" {
		values.Set("to", now.Add(-time.Minute).Format(time.RFC3339))
	}
	return accessLogsPath + "?" + values.Encode()
}

func TestAccessLogViewerAdminCanQueryAndOutputIsEscaped(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	store := &recordingAccessLogQueryStore{records: []AccessLogRecord{{
		Type: "http", Entry: AccessLogEntry{
			Timestamp: time.Now().UTC(), Decision: "deny", UserEmail: "alice@example.com",
			UserGroups: []string{"engineering", `<script>alert("group")</script>`},
			Resource:   "grafana", Method: "GET", Path: `<script>alert("path")</script>`,
			Host: "grafana.internal", SourceIP: "192.0.2.10", UserAgent: `<img src=x onerror=alert(1)>`,
			StatusCode: 403, DurationMS: 17, BytesSent: 512, Error: "forbidden",
		},
	}}}
	h.SetAccessLogQueryStore(store)
	values := url.Values{
		"user":        {"alice@example.com"},
		"application": {"grafana"},
		"group":       {"engineering"},
		"source_ip":   {"192.0.2.10"},
		"decision":    {"deny"},
		"method":      {"get"},
		"path":        {"/api"},
		"status":      {"403"},
		"host":        {"grafana.internal"},
		"type":        {"http"},
		"limit":       {"250"},
	}
	req := httptest.NewRequest(http.MethodGet, accessLogViewerURL(values), nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Access logs")
	assert.Contains(t, body, "alice@example.com")
	assert.Contains(t, body, "engineering")
	assert.Contains(t, body, "HTTP 403")
	assert.NotContains(t, body, "<script>")
	assert.NotContains(t, body, "<img")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'none'")
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "form-action 'self'")

	query, calls := store.snapshot()
	require.Equal(t, 1, calls)
	assert.Equal(t, "alice@example.com", query.UserEmail)
	assert.Equal(t, "grafana", query.Resource)
	assert.Equal(t, "engineering", query.Group)
	assert.Equal(t, "192.0.2.10", query.SourceIP)
	assert.Equal(t, "deny", query.Decision)
	assert.Equal(t, "GET", query.Method)
	assert.Equal(t, "/api", query.Path)
	require.NotNil(t, query.StatusCode)
	assert.Equal(t, 403, *query.StatusCode)
	assert.Equal(t, 250, query.Limit)
}

func TestAccessLogViewerNonAdminIsDeniedWithoutQuery(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	store := &recordingAccessLogQueryStore{}
	h.SetAccessLogQueryStore(store)
	req := httptest.NewRequest(http.MethodGet, accessLogsPath, nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	_, calls := store.snapshot()
	assert.Zero(t, calls)
}

func TestAccessLogViewerUsesFreshGroupsForAdminCheck(t *testing.T) {
	t.Parallel()
	authentikSrv := fakeAuthentikServerWithGroups(t, "engineering")
	defer authentikSrv.Close()
	h, sm := portalTestHandler(t)
	store := &recordingAccessLogQueryStore{}
	h.SetAccessLogQueryStore(store)
	validator := NewUserValidator(authentikSrv.URL, "token")
	t.Cleanup(validator.Stop)
	h.SetUserValidator(validator)
	req := httptest.NewRequest(http.MethodGet, accessLogsPath, nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	_, calls := store.snapshot()
	assert.Zero(t, calls, "stale admin groups from the cookie must not authorize a query")
}

func TestAccessLogViewerRejectsInvalidQueryBeforeStore(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	store := &recordingAccessLogQueryStore{}
	h.SetAccessLogQueryStore(store)
	now := time.Now().UTC()
	values := url.Values{
		"from": {now.Add(-32 * 24 * time.Hour).Format(time.RFC3339)},
		"to":   {now.Format(time.RFC3339)},
	}
	req := httptest.NewRequest(http.MethodGet, accessLogsPath+"?"+values.Encode(), nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Time range cannot exceed 31 days")
	_, calls := store.snapshot()
	assert.Zero(t, calls)
}

func TestAccessLogViewerStoreFailureIsGeneric(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	store := &recordingAccessLogQueryStore{err: errors.New("secret backend detail")}
	h.SetAccessLogQueryStore(store)
	req := httptest.NewRequest(http.MethodGet, accessLogViewerURL(url.Values{}), nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "temporarily unavailable")
	assert.NotContains(t, rec.Body.String(), "secret backend detail")
}

func TestAccessLogViewerUnavailableWithoutQueryStore(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, accessLogViewerURL(url.Values{}), nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "temporarily unavailable")
}

func TestAccessLogViewerUnauthenticatedDoesNotQuery(t *testing.T) {
	t.Parallel()
	h, _ := portalTestHandler(t)
	store := &recordingAccessLogQueryStore{}
	h.SetAccessLogQueryStore(store)
	req := httptest.NewRequest(http.MethodGet, accessLogsPath, nil)
	req.Host = "access.internal"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	_, calls := store.snapshot()
	assert.Zero(t, calls)
}

func TestAccessLogViewerRequiresGET(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, accessLogsPath, nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "GET", rec.Header().Get("Allow"))
}

func TestAccessLogViewerQueryIsItselfAudited(t *testing.T) {
	t.Parallel()
	h, sm := portalTestHandler(t)
	h.SetAccessLogQueryStore(&recordingAccessLogQueryStore{})
	h.accessLog.Sink = &recordingAccessLogSink{}
	req := httptest.NewRequest(http.MethodGet, accessLogViewerURL(url.Values{}), nil)
	req.Host = "access.internal"
	setSession(t, sm, req, "admin@example.com", []string{"authentik Admins"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	h.accessLog.mu.Lock()
	require.Len(t, h.accessLog.batch, 1)
	record := h.accessLog.batch[0]
	h.accessLog.mu.Unlock()
	assert.Equal(t, "admin@example.com", record.Entry.UserEmail)
	assert.Equal(t, "portal", record.Entry.Resource)
	assert.Equal(t, accessLogsPath, record.Entry.Path)
	assert.Equal(t, "allow", record.Entry.Decision)
}

func TestParseAccessLogQueryDefaultsAndValidation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 17, 18, 0, 0, 0, time.UTC)
	query, err := parseAccessLogQuery(url.Values{}, now)
	require.NoError(t, err)
	assert.Equal(t, now.Add(-time.Hour), query.From)
	assert.Equal(t, now, query.To)
	assert.Equal(t, accessLogDefaultLimit, query.Limit)

	tests := []struct {
		name   string
		values url.Values
		error  string
	}{
		{"reversed time", url.Values{"from": {"2026-09-17T17:00:00Z"}, "to": {"2026-09-17T16:00:00Z"}}, "earlier"},
		{"outside retention", url.Values{"from": {"2026-06-01T00:00:00Z"}, "to": {"2026-06-02T00:00:00Z"}}, "retention"},
		{"future", url.Values{"to": {"2026-09-18T00:00:00Z"}}, "future"},
		{"bad IP", url.Values{"source_ip": {"not-an-ip"}}, "valid IP"},
		{"bad decision", url.Values{"decision": {"maybe"}}, "decision"},
		{"bad status", url.Values{"status": {"1000"}}, "status"},
		{"bad limit", url.Values{"limit": {"10000"}}, "limit"},
		{"control character", url.Values{"user": {"alice\nadmin"}}, "user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAccessLogQuery(tt.values, now)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.error)
		})
	}
}

func TestBuildAccessLogQueryUsesParameters(t *testing.T) {
	t.Parallel()
	status := 403
	injection := `alice@example.com' OR 1=1 --`
	query := AccessLogQuery{
		From: time.Now().Add(-time.Hour), To: time.Now(), UserEmail: injection,
		Resource: "grafana", Group: "engineering", SourceIP: "192.0.2.1",
		Decision: "deny", Method: "GET", Host: "grafana.internal", Path: injection,
		Type: "http", StatusCode: &status, Limit: 100,
	}
	statement, args := buildAccessLogQuery(query)
	assert.NotContains(t, statement, injection)
	assert.Contains(t, statement, "user_email = ?")
	assert.Contains(t, statement, "has(user_groups, ?)")
	assert.Contains(t, statement, "positionCaseInsensitive(path, ?) > 0")
	assert.Contains(t, statement, "status_code = ?")
	assert.Contains(t, statement, "LIMIT ?")
	assert.Contains(t, args, injection)
	assert.Equal(t, uint64(100), args[len(args)-1])
	assert.Equal(t, strings.Count(statement, "?"), len(args))
}
