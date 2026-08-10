package beyond

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeAuthentikServer returns a test server that responds to user lookup requests.
func fakeAuthentikServer(t *testing.T, users map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify bearer token.
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		email := r.URL.Query().Get("email")
		active, exists := users[email]

		var resp authentikUserResponse
		if exists {
			resp.Results = append(resp.Results, authentikUserRow{IsActive: active})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// fakeAuthentikServerWithGroups returns a server that responds with one active
// user carrying the given group names (in groups_obj), for testing group
// re-resolution.
func fakeAuthentikServerWithGroups(t *testing.T, groups ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		row := authentikUserRow{IsActive: true}
		for _, g := range groups {
			row.GroupsObj = append(row.GroupsObj, authentikGroupName{Name: g})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authentikUserResponse{Results: []authentikUserRow{row}})
	}))
}

func TestUserValidator_ActiveUser(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServer(t, map[string]bool{
		"alice@example.com": true,
	})
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "test-token")
	assert.True(t, uv.IsActive("alice@example.com"))
}

func TestUserValidator_InactiveUser(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServer(t, map[string]bool{
		"bob@example.com": false,
	})
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "test-token")
	assert.False(t, uv.IsActive("bob@example.com"))
}

func TestUserValidator_UserNotFound(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServer(t, map[string]bool{})
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "test-token")
	assert.False(t, uv.IsActive("nobody@example.com"), "unknown user should be treated as inactive")
}

func TestUserValidator_APIError_FailClosed(t *testing.T) {
	t.Parallel()
	// Server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "test-token")
	assert.False(t, uv.IsActive("alice@example.com"), "API error must fail closed (return false)")
}

func TestUserValidator_Unreachable_FailClosed(t *testing.T) {
	t.Parallel()
	// Point at a non-existent server.
	uv := NewUserValidator("http://127.0.0.1:1", "test-token")
	assert.False(t, uv.IsActive("alice@example.com"), "unreachable API must fail closed")
}

func TestUserValidator_BadToken_FailClosed(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServer(t, map[string]bool{
		"alice@example.com": true,
	})
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "wrong-token")
	assert.False(t, uv.IsActive("alice@example.com"), "bad token must fail closed")
}

func TestUserValidator_InvalidJSON_FailClosed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "test-token")
	assert.False(t, uv.IsActive("alice@example.com"), "invalid JSON must fail closed")
}

// multiRowAuthentikServer returns a server that responds to any email lookup
// with the given is_active values, in order. Used to exercise the
// duplicate-email (non-unique email) path.
func multiRowAuthentikServer(t *testing.T, actives ...bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var resp authentikUserResponse
		for _, a := range actives {
			resp.Results = append(resp.Results, authentikUserRow{IsActive: a})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// TestUserValidator_DuplicateEmail_FailsClosed is the H-2 regression test.
// When an exact-email lookup returns multiple accounts (email is not unique in
// Authentik) and ANY of them is deactivated, the gate must deny — regardless
// of row order — rather than trusting whichever row sorts first.
func TestUserValidator_DuplicateEmail_FailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("inactive sorts first", func(t *testing.T) {
		t.Parallel()
		srv := multiRowAuthentikServer(t, false, true)
		defer srv.Close()
		uv := NewUserValidator(srv.URL, "ignored")
		assert.False(t, uv.IsActive("dup@example.com"),
			"any deactivated same-email account must deny")
	})

	t.Run("active sorts first", func(t *testing.T) {
		t.Parallel()
		srv := multiRowAuthentikServer(t, true, false)
		defer srv.Close()
		uv := NewUserValidator(srv.URL, "ignored")
		assert.False(t, uv.IsActive("dup@example.com"),
			"a deactivated same-email account must deny even when an active one sorts first")
	})

	t.Run("all active allows", func(t *testing.T) {
		t.Parallel()
		srv := multiRowAuthentikServer(t, true, true)
		defer srv.Close()
		uv := NewUserValidator(srv.URL, "ignored")
		assert.True(t, uv.IsActive("dup@example.com"),
			"multiple same-email accounts that are all active should still allow")
	})
}

// TestUserValidator_ResolveReturnsGroupNames proves Resolve surfaces the
// current group NAMES (from groups_obj) for the cookie-path re-resolution.
func TestUserValidator_ResolveReturnsGroupNames(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServerWithGroups(t, "engineering", "platform")
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")
	active, groups, ok := uv.Resolve("alice@example.com")
	assert.True(t, active)
	assert.True(t, ok, "a successful lookup must report ok=true")
	assert.Equal(t, []string{"engineering", "platform"}, groups,
		"Resolve must return the group names from groups_obj")
}

// TestUserValidator_ResolveActiveNoGroups is the PR-review regression test: an
// active user with zero groups must resolve as (active, empty, ok), NOT as the
// (false, nil) shape used for API errors — so the cookie path honors the empty
// set instead of falling back to stale session groups.
func TestUserValidator_ResolveActiveNoGroups(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServerWithGroups(t) // active, no groups
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")
	active, groups, ok := uv.Resolve("alice@example.com")
	assert.True(t, active, "user is active")
	assert.True(t, ok, "a definitive 'active with no groups' answer must report ok=true")
	assert.Empty(t, groups, "an active user with no groups must resolve to an empty set")
}

// TestUserValidator_ResolveUnionsDuplicateEmailGroups proves that when an email
// maps to multiple active accounts, Resolve returns the UNION of their groups.
func TestUserValidator_ResolveUnionsDuplicateEmailGroups(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := authentikUserResponse{Results: []authentikUserRow{
			{IsActive: true, GroupsObj: []authentikGroupName{{Name: "engineering"}}},
			{IsActive: true, GroupsObj: []authentikGroupName{{Name: "platform"}, {Name: "engineering"}}},
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")
	active, groups, ok := uv.Resolve("dup@example.com")
	assert.True(t, active)
	assert.True(t, ok)
	assert.ElementsMatch(t, []string{"engineering", "platform"}, groups,
		"groups across active duplicate-email accounts must be unioned and de-duplicated")
}

// TestUserValidator_ResolveFailClosedReturnsNotOK proves that on an API error
// Resolve returns (false, nil, false): the active gate fails closed and ok=false
// signals the caller to fall back to frozen session groups (vs an empty-but-ok
// set, which means "revoked from all groups").
func TestUserValidator_ResolveFailClosedReturnsNotOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")
	active, groups, ok := uv.Resolve("alice@example.com")
	assert.False(t, active, "API error must fail closed")
	assert.False(t, ok, "API error must report ok=false so the caller falls back to session groups")
	assert.Nil(t, groups, "API error must return nil groups")
}

func TestUserValidator_CacheHit(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		resp := authentikUserResponse{
			Results: []authentikUserRow{{IsActive: true}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")

	// First call hits the API.
	assert.True(t, uv.IsActive("alice@example.com"))
	assert.Equal(t, int32(1), callCount.Load())

	// Second call should use cache, not hit API again.
	assert.True(t, uv.IsActive("alice@example.com"))
	assert.Equal(t, int32(1), callCount.Load(), "second call should use cache")

	// Different user should trigger a new API call.
	assert.True(t, uv.IsActive("bob@example.com"))
	assert.Equal(t, int32(2), callCount.Load(), "different user should trigger API call")
}

func TestUserValidator_CacheExpiry(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		resp := authentikUserResponse{
			Results: []authentikUserRow{{IsActive: true}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")

	// Seed the cache with a stale entry.
	uv.mu.Lock()
	uv.cache["alice@example.com"] = cachedUser{
		active:    true,
		checkedAt: time.Now().Add(-userCacheTTL - time.Second), // expired
	}
	uv.mu.Unlock()

	// Should re-query because the cache entry is stale.
	assert.True(t, uv.IsActive("alice@example.com"))
	assert.Equal(t, int32(1), callCount.Load(), "stale cache entry should trigger API call")
}

func TestUserValidator_CachesNegativeResults(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		resp := authentikUserResponse{
			Results: []authentikUserRow{{IsActive: false}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "ignored")

	assert.False(t, uv.IsActive("deactivated@example.com"))
	assert.False(t, uv.IsActive("deactivated@example.com"))
	assert.Equal(t, int32(1), callCount.Load(), "negative result should be cached too")
}

func TestUserValidator_CacheEviction(t *testing.T) {
	t.Parallel()
	srv := fakeAuthentikServer(t, map[string]bool{
		"alice@example.com": true,
	})
	defer srv.Close()

	uv := NewUserValidator(srv.URL, "test-token")
	defer uv.Stop()

	// Prime the cache.
	assert.True(t, uv.IsActive("alice@example.com"))
	uv.mu.RLock()
	assert.Len(t, uv.cache, 1)
	uv.mu.RUnlock()

	// Manually age the entry past the TTL.
	uv.mu.Lock()
	uv.cache["alice@example.com"] = cachedUser{
		active:    true,
		checkedAt: time.Now().Add(-userCacheTTL - time.Second),
	}
	uv.mu.Unlock()

	// Evict expired entries.
	uv.evictExpired()

	uv.mu.RLock()
	assert.Empty(t, uv.cache, "expired entries should be evicted")
	uv.mu.RUnlock()
}
