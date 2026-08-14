package beyond

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const userCacheTTL = 30 * time.Second

// UserValidator checks whether a user is still active in the identity provider
// (Authentik). Results are cached in memory for userCacheTTL to avoid hitting
// the API on every request.
type UserValidator struct {
	apiURL string // e.g. "http://authentik:9000"
	token  string // Authentik API bearer token
	client *http.Client

	mu    sync.RWMutex
	cache map[string]cachedUser
	stop  chan struct{}
}

type cachedUser struct {
	active    bool
	groups    []string // current group NAMES (from groups_obj), nil when inactive
	ok        bool     // true when this entry came from a successful API lookup (not an error)
	checkedAt time.Time
}

// NewUserValidator creates a UserValidator that checks users against the
// Authentik API at apiURL using the given bearer token. It starts a background
// goroutine that periodically evicts expired cache entries; call Stop to shut
// it down.
func NewUserValidator(apiURL, token string) *UserValidator {
	uv := &UserValidator{
		apiURL: apiURL,
		token:  token,
		client: &http.Client{Timeout: 5 * time.Second},
		cache:  make(map[string]cachedUser),
		stop:   make(chan struct{}),
	}
	go uv.evictLoop()
	return uv
}

// Stop shuts down the cache eviction goroutine.
func (uv *UserValidator) Stop() {
	close(uv.stop)
}

// evictLoop periodically removes expired cache entries to prevent unbounded
// memory growth from accumulated unique email addresses.
func (uv *UserValidator) evictLoop() {
	ticker := time.NewTicker(userCacheTTL)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			uv.evictExpired()
		case <-uv.stop:
			return
		}
	}
}

// evictExpired removes cache entries older than userCacheTTL.
func (uv *UserValidator) evictExpired() {
	uv.mu.Lock()
	defer uv.mu.Unlock()
	now := time.Now()
	for email, cached := range uv.cache {
		if now.Sub(cached.checkedAt) >= userCacheTTL {
			delete(uv.cache, email)
		}
	}
}

// IsActive returns true if the user with the given email is active in Authentik.
// Results are cached for 30 seconds. On API error, returns false (fail closed).
func (uv *UserValidator) IsActive(email string) bool {
	active, _, _ := uv.Resolve(email)
	return active
}

// Resolve returns whether the email is active, the user's current group NAMES,
// and an ok flag indicating the lookup actually succeeded — all from a single
// cached Authentik lookup. The cookie path uses the fresh groups so an authZ
// decision reflects group/role changes within userCacheTTL rather than being
// frozen at the group set captured in the session cookie at login (NIST
// 800-207 Tenet 6, dynamic authorization).
//
// The three return values disambiguate the cases the caller must treat
// differently:
//
//   - (false, nil, false) — API error. Callers fail closed on the active gate.
//   - (false, nil, true)  — definitively inactive. Deny.
//   - (true, groups, true) — active; groups is the CURRENT set and may be
//     EMPTY (an active user removed from every group). The caller MUST use
//     this empty set, NOT fall back to stale session groups — falling back
//     would keep granting access on a group that was just revoked.
func (uv *UserValidator) Resolve(email string) (active bool, groups []string, ok bool) {
	start := time.Now()

	// Check cache first.
	uv.mu.RLock()
	if cached, found := uv.cache[email]; found && time.Since(cached.checkedAt) < userCacheTTL {
		uv.mu.RUnlock()
		userValidationDuration.WithLabelValues("cache", activeLabel(cached.active)).Observe(time.Since(start).Seconds())
		return cached.active, cached.groups, cached.ok
	}
	uv.mu.RUnlock()

	// Cache miss or stale — query Authentik.
	active, groups, ok = uv.queryAuthentik(email)

	uv.mu.Lock()
	uv.cache[email] = cachedUser{active: active, groups: groups, ok: ok, checkedAt: time.Now()}
	uv.mu.Unlock()

	userValidationDuration.WithLabelValues("api", activeLabel(active)).Observe(time.Since(start).Seconds())
	return active, groups, ok
}

func activeLabel(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

// authentikUserResponse is the relevant subset of the Authentik user list API
// response. Note: the top-level `groups` field holds group UUIDs; the group
// NAMES that beyond's policy matches on live in `groups_obj[].name`.
type authentikUserResponse struct {
	Results []authentikUserRow `json:"results"`
}

// authentikUserRow is one user record from the Authentik user list API.
type authentikUserRow struct {
	IsActive  bool                 `json:"is_active"`
	GroupsObj []authentikGroupName `json:"groups_obj"`
}

// authentikGroupName carries the group NAME (the policy-match key) from
// groups_obj; the rest of the group object is intentionally ignored.
type authentikGroupName struct {
	Name string `json:"name"`
}

// queryAuthentik checks the Authentik API for whether a user is active and
// returns the user's current group names plus an ok flag. ok is false ONLY on
// a transient/API error (network, non-200, decode failure) — a fail-closed
// "couldn't check". A definitive answer (not found, inactive, or active) has
// ok=true, even when the active user has zero groups.
func (uv *UserValidator) queryAuthentik(email string) (active bool, groups []string, ok bool) {
	reqURL := fmt.Sprintf("%s/api/v3/core/users/?email=%s", uv.apiURL, url.QueryEscape(email))
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return false, nil, false
	}
	req.Header.Set("Authorization", "Bearer "+uv.token)

	resp, err := uv.client.Do(req)
	if err != nil {
		return false, nil, false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil, false
	}

	var result authentikUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, nil, false
	}

	if len(result.Results) == 0 {
		return false, nil, true // definitively not found -> deny
	}

	// Fail closed on ambiguity. email is NOT unique in Authentik (username is
	// the unique key), so an exact-email filter can return multiple accounts —
	// e.g. a social-source link, a shared mailbox, or a botched migration. The
	// old code trusted Results[0], whichever sorted first by username, so
	// deactivating one of several same-email accounts could leave IsActive
	// returning true (the revocation gate failing OPEN). Require EVERY returned
	// account for this email to be active before granting access: if any row is
	// deactivated, deny. This is the conservative reading of "is this email's
	// access still valid?" for the proxy's deactivation gate.
	for _, u := range result.Results {
		if !u.IsActive {
			return false, nil, true // definitively inactive -> deny
		}
	}

	// Union the group names across all matching active accounts. With a single
	// account (the norm) this is just that account's groups. The union is the
	// pragmatic choice for the rare duplicate-email case until identity is
	// keyed on a unique sub (see beyond-cr-followups): an intersection could
	// strip a legitimate user's access, while the deactivation gate above
	// already denies if ANY same-email account is disabled.
	seen := make(map[string]bool)
	for _, u := range result.Results {
		for _, g := range u.GroupsObj {
			if g.Name != "" && !seen[g.Name] {
				seen[g.Name] = true
				groups = append(groups, g.Name)
			}
		}
	}
	// active with ok=true; groups may be empty for a user removed from every
	// group — the caller must honor that empty set, not fall back to stale
	// session groups.
	return true, groups, true
}
