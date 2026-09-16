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

const groupGraphPageSize = 100

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

	groupMu      sync.Mutex
	groupGraph   *authentikGroupGraph
	groupChecked time.Time
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

type authentikGroupListResponse struct {
	Pagination struct {
		Current    int `json:"current"`
		TotalPages int `json:"total_pages"`
	} `json:"pagination"`
	Results []authentikGroupRow `json:"results"`
}

type authentikGroupRow struct {
	PK      string   `json:"pk"`
	Name    string   `json:"name"`
	Parents []string `json:"parents"`
}

type authentikGroupGraph struct {
	byPK   map[string]authentikGroupRow
	byName map[string]string
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

	// Union the direct group names across all matching active accounts. With a
	// single account (the norm) this is just that account's groups. The union is the
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

	// groups_obj contains direct memberships only. Expand them through the
	// separately cached group graph so policy checks use Authentik's effective
	// membership semantics (the same semantics as request.user.all_groups()).
	if len(groups) > 0 {
		groups, err = uv.expandGroupAncestors(groups)
		if err != nil {
			return false, nil, false
		}
	}

	// active with ok=true; groups may be empty for a user removed from every
	// group — the caller must honor that empty set, not fall back to stale
	// session groups.
	return true, groups, true
}

// expandGroupAncestors returns direct groups plus every transitive parent.
// Authentik prevents parent cycles, but seenPK also makes expansion safe if a
// malformed graph reaches us.
func (uv *UserValidator) expandGroupAncestors(direct []string) ([]string, error) {
	graph, err := uv.loadGroupGraph()
	if err != nil {
		return nil, err
	}

	groups := make([]string, 0, len(direct))
	seenPK := make(map[string]bool)
	for _, name := range direct {
		pk, found := graph.byName[name]
		if !found {
			return nil, fmt.Errorf("direct group %q missing from Authentik group graph", name)
		}

		stack := []string{pk}
		for len(stack) > 0 {
			last := len(stack) - 1
			currentPK := stack[last]
			stack = stack[:last]
			if seenPK[currentPK] {
				continue
			}
			seenPK[currentPK] = true

			group, found := graph.byPK[currentPK]
			if !found {
				return nil, fmt.Errorf("group %q missing from Authentik group graph", currentPK)
			}
			groups = append(groups, group.Name)
			stack = append(stack, group.Parents...)
		}
	}
	return groups, nil
}

// loadGroupGraph returns a complete group graph cached for the same short TTL
// as user membership. Holding groupMu across refresh prevents a cache-miss
// stampede when many user entries expire together.
func (uv *UserValidator) loadGroupGraph() (*authentikGroupGraph, error) {
	uv.groupMu.Lock()
	defer uv.groupMu.Unlock()

	if uv.groupGraph != nil && time.Since(uv.groupChecked) < userCacheTTL {
		return uv.groupGraph, nil
	}

	graph := &authentikGroupGraph{
		byPK:   make(map[string]authentikGroupRow),
		byName: make(map[string]string),
	}
	for page := 1; ; page++ {
		reqURL := fmt.Sprintf("%s/api/v3/core/groups/?include_parents=true&include_users=false&page_size=%d&page=%d", uv.apiURL, groupGraphPageSize, page)
		req, err := http.NewRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+uv.token)

		resp, err := uv.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("authentik group list returned HTTP %d", resp.StatusCode)
		}

		var result authentikGroupListResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		closeErr := resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if result.Pagination.Current != page || result.Pagination.TotalPages < page {
			return nil, fmt.Errorf("invalid Authentik group pagination: page %d of %d", result.Pagination.Current, result.Pagination.TotalPages)
		}

		for _, group := range result.Results {
			if group.PK == "" || group.Name == "" {
				return nil, fmt.Errorf("authentik group graph contains an empty pk or name")
			}
			if existing, found := graph.byPK[group.PK]; found && existing.Name != group.Name {
				return nil, fmt.Errorf("authentik group pk %q has conflicting names", group.PK)
			}
			if existingPK, found := graph.byName[group.Name]; found && existingPK != group.PK {
				return nil, fmt.Errorf("authentik group name %q has conflicting pks", group.Name)
			}
			graph.byPK[group.PK] = group
			graph.byName[group.Name] = group.PK
		}

		if page == result.Pagination.TotalPages {
			break
		}
	}

	// An incomplete graph would silently drop inherited access. Treat it as an
	// API failure instead so the existing active gate fails closed.
	for _, group := range graph.byPK {
		for _, parentPK := range group.Parents {
			if _, found := graph.byPK[parentPK]; !found {
				return nil, fmt.Errorf("parent group %q missing from Authentik group graph", parentPK)
			}
		}
	}

	uv.groupGraph = graph
	uv.groupChecked = time.Now()
	return graph, nil
}
