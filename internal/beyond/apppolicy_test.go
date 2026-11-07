package beyond

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakePolicyToken = "policy-token"

type fakePolicyApp struct {
	pk       string
	mode     string
	bindings []map[string]any
}

// fakePolicyAuthentik serves the slice of Authentik's API Beyond reads:
// application retrieve-by-slug, policy bindings by target, and the user and
// group endpoints UserValidator uses. Like the real API, an unknown slug is a
// JSON 404 and the bindings list paginates.
type fakePolicyAuthentik struct {
	srv *httptest.Server

	mu   sync.Mutex
	apps map[string]*fakePolicyApp
	// down answers every request with 503.
	down bool
	// ignoreTarget returns every application's bindings regardless of
	// ?target=, as Authentik does for a filter it does not recognize.
	ignoreTarget bool
	// plain404 answers unknown slugs with a non-Authentik 404 body.
	plain404 bool
	// notFoundDetail, when set, answers unknown slugs with a JSON 404 whose
	// detail is this string instead of Authentik's application-not-found one.
	notFoundDetail string
	users    map[string][]string // email -> direct group names
	parents  map[string][]string // group name -> parent group names

	appRequests atomic.Int32
	// delay, in nanoseconds, is added to every response.
	delay atomic.Int64
}

func newFakePolicyAuthentik(t *testing.T) *fakePolicyAuthentik {
	t.Helper()
	fa := &fakePolicyAuthentik{
		apps:    map[string]*fakePolicyApp{},
		users:   map[string][]string{},
		parents: map[string][]string{},
	}
	fa.srv = httptest.NewServer(http.HandlerFunc(fa.serve))
	t.Cleanup(fa.srv.Close)
	return fa
}

func (fa *fakePolicyAuthentik) setApp(slug, mode string, bindings ...map[string]any) {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	fa.apps[slug] = &fakePolicyApp{pk: slug + "-pk", mode: mode, bindings: bindings}
}

func (fa *fakePolicyAuthentik) deleteApp(slug string) {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	delete(fa.apps, slug)
}

func (fa *fakePolicyAuthentik) setDown(down bool) {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	fa.down = down
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (fa *fakePolicyAuthentik) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+fakePolicyToken {
		writeTestJSON(w, http.StatusForbidden, map[string]string{"detail": "Token invalid/expired"})
		return
	}
	time.Sleep(time.Duration(fa.delay.Load()))
	fa.mu.Lock()
	defer fa.mu.Unlock()
	if fa.down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	const appPrefix = "/api/v3/core/applications/"
	q := r.URL.Query()
	switch {
	case strings.HasPrefix(r.URL.Path, appPrefix):
		fa.appRequests.Add(1)
		slug := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, appPrefix), "/")
		app := fa.apps[slug]
		if app == nil {
			if fa.plain404 {
				http.NotFound(w, r)
				return
			}
			if fa.notFoundDetail != "" {
				writeTestJSON(w, http.StatusNotFound, map[string]string{"detail": fa.notFoundDetail})
				return
			}
			writeTestJSON(w, http.StatusNotFound, map[string]string{"detail": authentikApplicationNotFound})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]any{
			"pk": app.pk, "slug": slug, "name": slug, "policy_engine_mode": app.mode,
		})

	case r.URL.Path == "/api/v3/policies/bindings/":
		var all []map[string]any
		for _, app := range fa.apps {
			if !fa.ignoreTarget && app.pk != q.Get("target") {
				continue
			}
			for _, b := range app.bindings {
				row := map[string]any{"target": app.pk}
				for k, v := range b {
					row[k] = v
				}
				all = append(all, row)
			}
		}
		pageSize, _ := strconv.Atoi(q.Get("page_size"))
		page, _ := strconv.Atoi(q.Get("page"))
		if pageSize <= 0 || page <= 0 {
			http.Error(w, "bad paging", http.StatusBadRequest)
			return
		}
		totalPages := max(1, (len(all)+pageSize-1)/pageSize)
		if page > totalPages {
			writeTestJSON(w, http.StatusNotFound, map[string]string{"detail": "Invalid page."})
			return
		}
		end := min(len(all), page*pageSize)
		writeTestJSON(w, http.StatusOK, map[string]any{
			"pagination": map[string]any{"current": page, "total_pages": totalPages, "count": len(all)},
			"results":    all[(page-1)*pageSize : end],
		})

	case r.URL.Path == "/api/v3/core/users/":
		groups, ok := fa.users[q.Get("email")]
		results := []any{}
		if ok {
			var objs []any
			for _, g := range groups {
				objs = append(objs, map[string]any{"name": g})
			}
			results = append(results, map[string]any{"is_active": true, "groups_obj": objs})
		}
		writeTestJSON(w, http.StatusOK, map[string]any{"results": results})

	case r.URL.Path == "/api/v3/core/groups/":
		names := map[string]bool{}
		for _, groups := range fa.users {
			for _, g := range groups {
				names[g] = true
			}
		}
		for g, ps := range fa.parents {
			names[g] = true
			for _, p := range ps {
				names[p] = true
			}
		}
		var rows []authentikGroupRow
		for name := range names {
			row := authentikGroupRow{PK: name + "-pk", Name: name, Parents: []string{}}
			for _, p := range fa.parents[name] {
				row.Parents = append(row.Parents, p+"-pk")
			}
			rows = append(rows, row)
		}
		writeGroupGraphResponse(w, rows...)

	default:
		http.NotFound(w, r)
	}
}

// groupBinding is an enabled, plain group binding as Authentik serializes it.
// Overrides replace fields (a nil value is JSON null).
func groupBinding(group string, overrides ...any) map[string]any {
	b := map[string]any{
		"pk":        "binding-" + group,
		"policy":    nil,
		"group":     group + "-pk",
		"user":      nil,
		"group_obj": map[string]any{"pk": group + "-pk", "name": group},
		"user_obj":  nil,
		"negate":    false,
		"enabled":   true,
		"order":     0,
		"expiring":  false,
		"expires":   nil,
	}
	for i := 0; i+1 < len(overrides); i += 2 {
		b[overrides[i].(string)] = overrides[i+1]
	}
	return b
}

// newTestAppPolicySource returns a source for routes backed by fa that has
// completed one synchronous refresh, without a background loop.
func newTestAppPolicySource(t *testing.T, fa *fakePolicyAuthentik, routes map[string][]string, logger *slog.Logger) *AppPolicySource {
	t.Helper()
	if logger == nil {
		logger = testLogger()
	}
	src := NewAppPolicySource(fa.srv.URL, fakePolicyToken, routes, logger)
	t.Cleanup(src.Stop)
	src.refresh()
	return src
}

// attachAppPolicies gives h a loaded policy source covering every route h
// was built with.
func attachAppPolicies(t *testing.T, h *Handler, fa *fakePolicyAuthentik) *AppPolicySource {
	t.Helper()
	h.authorizer.mu.RLock()
	routes := map[string][]string{}
	for _, app := range h.authorizer.applications {
		routes[app.Name] = app.AllowedGroups
	}
	h.authorizer.mu.RUnlock()
	src := newTestAppPolicySource(t, fa, routes, nil)
	h.SetAppPolicySource(src)
	return src
}

func testConfigRoutes() map[string][]string {
	return appPolicyRoutes(testConfig())
}

func checkAllowed(az *Authorizer, host string, groups ...string) bool {
	allowed, _ := az.CheckHTTP(host, groups)
	return allowed
}

// testConfig's argocd route allows platform and grafana allows engineering and
// team-all. Here Authentik has an argocd application bound to engineering and
// no grafana application.
func TestAppPolicy_AuthentikAppReplacesAllowedGroups(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))

	az := NewAuthorizer(testConfig())
	az.SetAppPolicySource(newTestAppPolicySource(t, fa, testConfigRoutes(), nil))

	assert.True(t, checkAllowed(az, "argocd.internal", "engineering"), "the Authentik binding grants access")
	assert.False(t, checkAllowed(az, "argocd.internal", "platform"), "the route's allowed_groups must be ignored")
	assert.True(t, checkAllowed(az, "argocd.internal", "authentik Admins"), "admin bypass is unchanged")

	assert.True(t, checkAllowed(az, "grafana.internal", "team-all"), "a 404 keeps allowed_groups")
	assert.False(t, checkAllowed(az, "grafana.internal", "platform"))

	apps := az.AllowedApplications([]string{"engineering"})
	names := make([]string, 0, len(apps))
	for _, app := range apps {
		names = append(names, app.Name)
	}
	assert.ElementsMatch(t, []string{"argocd", "grafana"}, names, "the portal follows the same policy")
	assert.Empty(t, az.AllowedApplications([]string{"platform"}))
}

func TestAppPolicy_UnresolvedRoutesDeny(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setDown(true)

	az := NewAuthorizer(testConfig())
	az.SetAppPolicySource(newTestAppPolicySource(t, fa, testConfigRoutes(), nil))

	assert.False(t, checkAllowed(az, "argocd.internal", "platform"),
		"an unresolved route must not fall back to allowed_groups")
	assert.False(t, checkAllowed(az, "grafana.internal", "engineering"))
	assert.True(t, checkAllowed(az, "grafana.internal", "authentik Admins"), "admin bypass is unchanged")
	assert.Empty(t, az.AllowedApplications([]string{"engineering", "platform", "team-all"}))
}

func TestAppPolicy_RouteUnknownToSourceDenies(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	az := NewAuthorizer(testConfig())
	// The source knows only argocd; grafana resolves nowhere.
	az.SetAppPolicySource(newTestAppPolicySource(t, fa, map[string][]string{"argocd": {"platform"}}, nil))

	assert.True(t, checkAllowed(az, "argocd.internal", "platform"))
	assert.False(t, checkAllowed(az, "grafana.internal", "engineering"))
}

func TestAppPolicy_LookupFailureKeepsLastKnownGood(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))

	az := NewAuthorizer(testConfig())
	src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
	az.SetAppPolicySource(src)
	require.True(t, checkAllowed(az, "argocd.internal", "engineering"))

	check := func(when string) {
		t.Helper()
		assert.True(t, checkAllowed(az, "argocd.internal", "engineering"), when)
		assert.False(t, checkAllowed(az, "argocd.internal", "platform"), when)
		assert.True(t, checkAllowed(az, "grafana.internal", "team-all"), when)
	}

	fa.setDown(true)
	src.refresh()
	check("a 503 keeps the last-known-good policy")

	fa.setDown(false)
	fa.mu.Lock()
	fa.plain404 = true
	delete(fa.apps, "argocd")
	fa.mu.Unlock()
	src.refresh()
	check("a 404 that is not from Authentik's API keeps the last-known-good policy")

	fa.srv.Close()
	src.refresh()
	check("a transport error keeps the last-known-good policy")
}

func TestAppPolicy_DefinitiveAnswersReplaceState(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	az := NewAuthorizer(testConfig())
	src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
	az.SetAppPolicySource(src)
	require.True(t, checkAllowed(az, "argocd.internal", "engineering"))

	fa.setApp("argocd", "any", groupBinding("security"))
	src.refresh()
	assert.False(t, checkAllowed(az, "argocd.internal", "engineering"), "a removed binding revokes access")
	assert.True(t, checkAllowed(az, "argocd.internal", "security"), "an added binding grants access")

	fa.deleteApp("argocd")
	src.refresh()
	assert.True(t, checkAllowed(az, "argocd.internal", "platform"), "a deleted application falls back to allowed_groups")
	assert.False(t, checkAllowed(az, "argocd.internal", "security"))

	fa.setApp("argocd", "any")
	src.refresh()
	assert.False(t, checkAllowed(az, "argocd.internal", "platform"), "an application with no bindings denies")
	assert.Equal(t, appPolicySourceInvalid, src.policyFor("argocd").source)

	fa.setApp("grafana", "any", groupBinding("platform"))
	src.refresh()
	assert.True(t, checkAllowed(az, "grafana.internal", "platform"), "a newly created application takes over the route")
	assert.False(t, checkAllowed(az, "grafana.internal", "team-all"))
}

func TestAppPolicy_UnsupportedPoliciesDeny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     string
		bindings []map[string]any
	}{
		{name: "policy engine mode all", mode: "all", bindings: []map[string]any{groupBinding("engineering")}},
		{name: "user binding", mode: "any", bindings: []map[string]any{
			groupBinding("engineering"),
			groupBinding("u", "group", nil, "group_obj", nil, "user", 7, "user_obj", map[string]any{"pk": 7}),
		}},
		{name: "expression policy binding", mode: "any", bindings: []map[string]any{
			groupBinding("engineering"),
			groupBinding("p", "group", nil, "group_obj", nil, "policy", "policy-pk"),
		}},
		{name: "negated group binding", mode: "any", bindings: []map[string]any{
			groupBinding("engineering"),
			groupBinding("contractors", "negate", true),
		}},
		{name: "expiring group binding", mode: "any", bindings: []map[string]any{
			groupBinding("engineering", "expiring", true, "expires", "2099-01-01T00:00:00Z"),
		}},
		{name: "binding with no subject", mode: "any", bindings: []map[string]any{
			groupBinding("engineering"),
			groupBinding("empty", "group", nil, "group_obj", nil),
		}},
		{name: "no bindings", mode: "any"},
		{name: "only disabled bindings", mode: "any", bindings: []map[string]any{
			groupBinding("engineering", "enabled", false),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fa := newFakePolicyAuthentik(t)
			fa.setApp("argocd", tt.mode, tt.bindings...)
			az := NewAuthorizer(testConfig())
			src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
			az.SetAppPolicySource(src)

			assert.Equal(t, appPolicySourceInvalid, src.policyFor("argocd").source)
			assert.NotEmpty(t, src.policyFor("argocd").reason)
			assert.False(t, checkAllowed(az, "argocd.internal", "engineering"))
			assert.False(t, checkAllowed(az, "argocd.internal", "platform"), "an invalid policy must not fall back to allowed_groups")
			assert.True(t, checkAllowed(az, "argocd.internal", "authentik Admins"))
		})
	}
}

func TestAppPolicy_DisabledBindingsIgnored(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any",
		groupBinding("engineering"),
		groupBinding("platform", "enabled", false),
		groupBinding("contractors", "enabled", false, "negate", true),
		groupBinding("u", "enabled", false, "group", nil, "group_obj", nil, "user", 7),
		groupBinding("p", "enabled", false, "group", nil, "group_obj", nil, "policy", "policy-pk"),
	)
	az := NewAuthorizer(testConfig())
	az.SetAppPolicySource(newTestAppPolicySource(t, fa, testConfigRoutes(), nil))

	assert.True(t, checkAllowed(az, "argocd.internal", "engineering"))
	assert.False(t, checkAllowed(az, "argocd.internal", "platform"), "a disabled group binding grants nothing")
}

func TestAppPolicy_ForeignTargetBindingIsLookupFailure(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	fa.setApp("other", "any", groupBinding("team-all"))
	fa.mu.Lock()
	fa.ignoreTarget = true
	fa.mu.Unlock()

	az := NewAuthorizer(testConfig())
	src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
	az.SetAppPolicySource(src)

	assert.Equal(t, appPolicySourceUnresolved, src.policyFor("argocd").source,
		"another application's bindings must never be merged in")
	assert.False(t, checkAllowed(az, "argocd.internal", "team-all"))
	assert.False(t, checkAllowed(az, "argocd.internal", "engineering"))
}

func TestAppPolicy_MalformedBindingIsLookupFailure(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"negate", "enabled", "expiring", "user", "policy", "group"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			b := groupBinding("engineering")
			delete(b, field)
			fa := newFakePolicyAuthentik(t)
			fa.setApp("argocd", "any", b)
			src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
			assert.Equal(t, appPolicySourceUnresolved, src.policyFor("argocd").source,
				"a binding missing %q must not be read as a plain group binding", field)
		})
	}
}

func TestAppPolicy_BindingsPaginate(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	var bindings []map[string]any
	for i := range 250 {
		bindings = append(bindings, groupBinding("group-"+strconv.Itoa(i)))
	}
	fa.setApp("argocd", "any", bindings...)
	az := NewAuthorizer(testConfig())
	src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
	az.SetAppPolicySource(src)

	assert.Len(t, src.policyFor("argocd").groups, 250)
	assert.True(t, checkAllowed(az, "argocd.internal", "group-0"))
	assert.True(t, checkAllowed(az, "argocd.internal", "group-249"))
}

// A slow but healthy Authentik must not starve the tail of the route list:
// the timeout is per route, so every route resolves even when the whole
// refresh takes several lookup timeouts.
func TestAppPolicy_SlowAuthentikResolvesEveryRoute(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.delay.Store(int64(20 * time.Millisecond))
	routes := map[string][]string{}
	for i := range 200 {
		name := "app-" + strconv.Itoa(i)
		fa.setApp(name, "any", groupBinding("engineering"))
		routes[name] = []string{"platform"}
	}

	src := NewAppPolicySource(fa.srv.URL, fakePolicyToken, routes, testLogger())
	t.Cleanup(src.Stop)
	// Each route needs two ~20ms requests, so the refresh as a whole takes
	// about a second at appPolicyConcurrency: twice the lookup timeout.
	src.lookupTimeout = 500 * time.Millisecond
	src.refresh()
	assert.Empty(t, src.unresolvedRoutes())
}

func TestAppPolicy_NonSlugRouteSkipsLookup(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	src := newTestAppPolicySource(t, fa, map[string][]string{"not.a.slug": {"engineering"}}, nil)
	assert.Equal(t, appPolicySourceAllowedGroups, src.policyFor("not.a.slug").source)
	assert.Zero(t, fa.appRequests.Load(), "no Authentik application can have this slug")
}

func TestAppPolicy_Plain404IsLookupFailure(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.mu.Lock()
	fa.plain404 = true
	fa.mu.Unlock()
	src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
	assert.Equal(t, appPolicySourceUnresolved, src.policyFor("grafana").source,
		"only Authentik's own 404 may move a route to allowed_groups")
}

// A JSON 404 with some other detail (a gateway's {"detail":"Not Found"}, or
// Authentik's own 404 for a different object) is not proof that the
// application is missing, so it must not move a route to allowed_groups.
func TestAppPolicy_OtherJSON404IsLookupFailure(t *testing.T) {
	t.Parallel()
	for _, detail := range []string{"Not Found", "Not found.", "No Group matches the given query."} {
		t.Run(detail, func(t *testing.T) {
			t.Parallel()
			fa := newFakePolicyAuthentik(t)
			fa.mu.Lock()
			fa.notFoundDetail = detail
			fa.mu.Unlock()
			src := newTestAppPolicySource(t, fa, testConfigRoutes(), nil)
			assert.Equal(t, appPolicySourceUnresolved, src.policyFor("grafana").source,
				"only Authentik's application-not-found answer may move a route to allowed_groups")
		})
	}
}

func TestValidateAuthentikAPIConfig(t *testing.T) {
	t.Parallel()
	require.NoError(t, validateAuthentikAPIConfig("", ""), "neither set: allowed_groups only")
	require.NoError(t, validateAuthentikAPIConfig("http://authentik", "token"))
	require.Error(t, validateAuthentikAPIConfig("http://authentik", ""),
		"a URL without a token must not silently drop Authentik policy")
	require.Error(t, validateAuthentikAPIConfig("", "token"),
		"a token without a URL must not silently drop Authentik policy")
}

func TestAppPolicy_WrongTokenIsLookupFailure(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	src := NewAppPolicySource(fa.srv.URL, "wrong-token", testConfigRoutes(), testLogger())
	t.Cleanup(src.Stop)
	src.refresh()
	assert.Equal(t, appPolicySourceUnresolved, src.policyFor("grafana").source)
}

// Authentik's group bindings match members of the bound group or of any
// descendant group. Beyond reproduces that by matching against the
// ancestor-expanded groups UserValidator resolves.
func TestAppPolicy_ChildGroupMemberPassesParentBinding(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	fa.mu.Lock()
	fa.users["child@example.com"] = []string{"sre"}
	fa.users["other@example.com"] = []string{"marketing"}
	fa.parents["sre"] = []string{"infrastructure"}
	fa.parents["infrastructure"] = []string{"engineering"}
	fa.mu.Unlock()

	backend := newRecordingBackend(t)
	h, sm := newTestHandler(t, backend.srv)
	h.SetUserValidator(NewUserValidator(fa.srv.URL, fakePolicyToken))
	attachAppPolicies(t, h, fa)

	serve := func(email string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "argocd.internal"
		// The frozen session groups are irrelevant: the validator re-resolves.
		setSession(t, sm, req, email, []string{"platform"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, http.StatusOK, serve("child@example.com"), "a grandchild-group member passes a parent-group binding")
	assert.ElementsMatch(t, []string{"sre", "infrastructure", "engineering"},
		strings.Split(backend.last.Get("X-Beyond-Groups"), "|"))
	assert.Equal(t, http.StatusForbidden, serve("other@example.com"))
}

func TestAppPolicy_StartRetriesUntilResolved(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	fa.setDown(true)

	src := NewAppPolicySource(fa.srv.URL, fakePolicyToken, testConfigRoutes(), testLogger())
	src.refreshInterval = time.Hour
	src.retryInterval = 10 * time.Millisecond
	src.Start(t.Context())
	t.Cleanup(src.Stop)
	assert.Equal(t, appPolicySourceUnresolved, src.policyFor("argocd").source, "Start's synchronous load failed")

	fa.setDown(false)
	require.Eventually(t, func() bool {
		return src.policyFor("argocd").source == appPolicySourceAuthentik &&
			src.policyFor("grafana").source == appPolicySourceAllowedGroups
	}, 5*time.Second, 10*time.Millisecond, "the retry loop must resolve routes once Authentik answers")
	assert.Equal(t, time.Hour, src.nextInterval(), "resolved routes refresh on the normal interval")
}

func TestAppPolicy_StartContextCancellationStops(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	src := NewAppPolicySource(fa.srv.URL, fakePolicyToken, testConfigRoutes(), testLogger())
	ctx, cancel := context.WithCancel(t.Context())
	src.Start(ctx)
	cancel()
	select {
	case <-src.done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling Start's context must stop the refresh loop")
	}
	src.Stop()
}

func TestAppPolicy_ReloadConfigUpdatesRoutes(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	fa.setApp("newapp", "any", groupBinding("security"))

	h, _ := newTestHandler(t, nil)
	src := NewAppPolicySource(fa.srv.URL, fakePolicyToken, testConfigRoutes(), testLogger())
	src.refreshInterval = time.Hour
	src.retryInterval = 10 * time.Millisecond
	src.Start(t.Context())
	t.Cleanup(src.Stop)
	h.SetAppPolicySource(src)
	require.True(t, checkAllowed(h.authorizer, "argocd.internal", "engineering"))

	cfg := testConfig()
	delete(cfg.Applications, "grafana")
	cfg.Applications["newapp"] = &Application{
		Name: "newapp", Upstream: "http://localhost:1", Host: "newapp.internal", AllowedGroups: []string{"team-all"},
	}
	h.ReloadConfig(cfg)

	assert.False(t, checkAllowed(h.authorizer, "newapp.internal", "team-all"), "a new route denies until resolved")
	require.Eventually(t, func() bool {
		return checkAllowed(h.authorizer, "newapp.internal", "security")
	}, 5*time.Second, 10*time.Millisecond, "the reload must schedule a lookup of the new route")
	assert.True(t, checkAllowed(h.authorizer, "argocd.internal", "engineering"), "retained routes keep their state")
	_, known := (*src.policies.Load())["grafana"]
	assert.False(t, known, "removed routes leave the source")
}

func TestAppPolicy_ConcurrentReadsAndUpdates(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	h, _ := newTestHandler(t, nil)
	src := attachAppPolicies(t, h, fa)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					checkAllowed(h.authorizer, "argocd.internal", "engineering")
					h.authorizer.AllowedApplications([]string{"engineering"})
				}
			}
		})
	}
	for i := range 20 {
		if i%2 == 0 {
			fa.setApp("argocd", "any", groupBinding("platform"))
		} else {
			fa.setApp("argocd", "any", groupBinding("engineering"))
		}
		src.refresh()
		h.ReloadConfig(testConfig())
	}
	close(stop)
	wg.Wait()
}

func TestAppPolicy_LogsPolicyChanges(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	var buf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	src := newTestAppPolicySource(t, fa, testConfigRoutes(), logger)

	logs := buf.String()
	assert.Contains(t, logs, `"msg":"route policy changed","route":"argocd","old_source":"unresolved","new_source":"authentik","old_groups":[],"new_groups":["engineering"]`)
	assert.Contains(t, logs, `"msg":"route policy changed","route":"grafana","old_source":"unresolved","new_source":"allowed_groups","old_groups":[],"new_groups":["engineering","team-all"]`)
	assert.Contains(t, logs, `"msg":"route allowed_groups ignored: an Authentik application with the route's name governs it","route":"argocd","ignored_allowed_groups":["platform"]`)

	buf.Reset()
	src.refresh()
	assert.Empty(t, buf.String(), "an unchanged policy logs nothing")

	fa.setApp("argocd", "any", groupBinding("engineering"), groupBinding("security"))
	src.refresh()
	assert.Contains(t, buf.String(), `"route":"argocd","old_source":"authentik","new_source":"authentik","old_groups":["engineering"],"new_groups":["engineering","security"]`)
	assert.NotContains(t, buf.String(), "allowed_groups ignored", "the ignored allowed_groups warning is logged once per load")

	buf.Reset()
	fa.setApp("argocd", "all", groupBinding("engineering"))
	src.refresh()
	assert.Contains(t, buf.String(), `"level":"WARN"`)
	assert.Contains(t, buf.String(), `"new_source":"invalid"`)
	assert.Contains(t, buf.String(), `policy_engine_mode is \"all\"`)
}

// syncBuffer is a bytes.Buffer safe for a logger and a test to share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// Not parallel: the metrics are process-global and other tests' sources
// update the refresh timestamp.
func TestAppPolicy_Metrics(t *testing.T) {
	fa := newFakePolicyAuthentik(t)
	fa.setApp("metrics-authentik", "any", groupBinding("engineering"))
	fa.setApp("metrics-invalid", "all", groupBinding("engineering"))
	routes := map[string][]string{
		"metrics-authentik": {"platform"},
		"metrics-fallback":  {"platform"},
		"metrics-invalid":   {"platform"},
	}
	src := NewAppPolicySource(fa.srv.URL, fakePolicyToken, routes, testLogger())
	t.Cleanup(src.Stop)

	sourceOf := func(route string) map[string]float64 {
		got := map[string]float64{}
		for _, s := range appPolicySources {
			got[s] = testutil.ToFloat64(appPolicySource.WithLabelValues(route, s))
		}
		return got
	}
	assert.Equal(t, map[string]float64{"authentik": 0, "allowed_groups": 0, "unresolved": 1, "invalid": 0}, sourceOf("metrics-fallback"))

	appPolicyLastRefreshSuccess.Set(0)
	src.refresh()
	assert.Equal(t, map[string]float64{"authentik": 1, "allowed_groups": 0, "unresolved": 0, "invalid": 0}, sourceOf("metrics-authentik"))
	assert.Equal(t, map[string]float64{"authentik": 0, "allowed_groups": 1, "unresolved": 0, "invalid": 0}, sourceOf("metrics-fallback"))
	assert.Equal(t, map[string]float64{"authentik": 0, "allowed_groups": 0, "unresolved": 0, "invalid": 1}, sourceOf("metrics-invalid"))
	assert.Greater(t, testutil.ToFloat64(appPolicyLastRefreshSuccess), 0.0)

	appPolicyLastRefreshSuccess.Set(0)
	fa.setDown(true)
	src.refresh()
	assert.Zero(t, testutil.ToFloat64(appPolicyLastRefreshSuccess), "a failed lookup must not advance the success timestamp")
	assert.Equal(t, 1.0, testutil.ToFloat64(appPolicySource.WithLabelValues("metrics-authentik", "authentik")), "last-known-good keeps its source")

	before := testutil.CollectAndCount(appPolicySource)
	src.SetRoutes(map[string][]string{"metrics-authentik": {"platform"}})
	assert.Equal(t, before-2*len(appPolicySources), testutil.CollectAndCount(appPolicySource),
		"removed routes must drop their series")
}

// --- Per auth path: every path authorizes through CheckHTTP, so each must
// honor the Authentik application for an Authentik-backed route and
// allowed_groups for a fallback route.

func TestAppPolicy_CookiePath(t *testing.T) {
	t.Parallel()
	fa := newFakePolicyAuthentik(t)
	fa.setApp("argocd", "any", groupBinding("engineering"))
	backend := newRecordingBackend(t)
	h, sm := newTestHandler(t, backend.srv)
	attachAppPolicies(t, h, fa)

	serve := func(host string, groups ...string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		setSession(t, sm, req, "alice@example.com", groups)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	t.Run("authentik route", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve("argocd.internal", "engineering"))
		assert.Equal(t, http.StatusForbidden, serve("argocd.internal", "platform"))
	})
	t.Run("fallback route", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve("grafana.internal", "team-all"))
		assert.Equal(t, http.StatusForbidden, serve("grafana.internal", "platform"))
	})
}

func TestAppPolicy_BearerPath(t *testing.T) {
	t.Parallel()
	// skipper's route allows platform.
	t.Run("authentik route", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		fa.setApp("skipper", "any", groupBinding("engineering"))
		h, idp, _ := newBearerTestHandler(t)
		attachAppPolicies(t, h, fa)
		serve := func(groups ...string) int {
			tok := idp.mint(t, bearerTestIssuer, bearerTestAudience, time.Now().Add(time.Hour), groups)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))
			return rec.Code
		}
		assert.Equal(t, http.StatusOK, serve("engineering"))
		assert.Equal(t, http.StatusForbidden, serve("platform"))
	})
	t.Run("fallback route", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		h, idp, _ := newBearerTestHandler(t)
		attachAppPolicies(t, h, fa)
		serve := func(groups ...string) int {
			tok := idp.mint(t, bearerTestIssuer, bearerTestAudience, time.Now().Add(time.Hour), groups)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, bearerReq("skipper.example.com", tok))
			return rec.Code
		}
		assert.Equal(t, http.StatusOK, serve("platform"))
		assert.Equal(t, http.StatusForbidden, serve("engineering"))
	})
}

func TestAppPolicy_CredentialPath(t *testing.T) {
	t.Parallel()
	serve := func(t *testing.T, fa *fakePolicyAuthentik, groups ...string) int {
		t.Helper()
		claims := defaultClaims()
		claims["groups"] = groups
		token := newFakeAuthentik(t, happyTokenEndpoint(t, "alice@example.com", "pw", claims))
		// aigw's route allows platform.
		h, _ := newCredentialTestHandler(t, token, []string{"platform"})
		attachAppPolicies(t, h, fa)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, credReqBearer("aigw.example.com", "alice@example.com:pw"))
		return rec.Code
	}
	t.Run("authentik route", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		fa.setApp("aigw", "any", groupBinding("engineering"))
		assert.Equal(t, http.StatusOK, serve(t, fa, "engineering"))
		assert.Equal(t, http.StatusForbidden, serve(t, fa, "platform"))
	})
	t.Run("fallback route", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		assert.Equal(t, http.StatusOK, serve(t, fa, "platform"))
		assert.Equal(t, http.StatusForbidden, serve(t, fa, "engineering"))
	})
}

func TestAppPolicy_MintPath(t *testing.T) {
	t.Parallel()
	// The mint helpers drive the index and /start-mint with a platform
	// session; the callback authorizes on the id_token claims.
	t.Run("authentik route allows", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		fa.setApp("mint", "any", groupBinding("platform"))
		api := newFakeAuthentikAPI(t)
		claims := mintClaims([]string{"platform"})
		h := newMintTestHandler(t, api, []string{"outsiders"}, claims, nil)
		attachAppPolicies(t, h, fa)

		stateCookie, state, _ := driveMintToCallback(t, h, claims)
		rec := mintCallback(t, h, stateCookie, state)
		assert.Equal(t, http.StatusOK, rec.Code, "the Authentik binding, not allowed_groups, admits the user")
		assert.Equal(t, int64(1), api.creates.Load())
	})
	t.Run("authentik route denies at the callback", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		fa.setApp("mint", "any", groupBinding("platform"))
		api := newFakeAuthentikAPI(t)
		claims := mintClaims([]string{"outsiders"})
		h := newMintTestHandler(t, api, []string{"outsiders"}, claims, nil)
		attachAppPolicies(t, h, fa)

		stateCookie, state, _ := driveMintToCallback(t, h, claims)
		rec := mintCallback(t, h, stateCookie, state)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Zero(t, api.creates.Load(), "a denied user must cause zero token-create calls")
	})
	t.Run("authentik route denies at the index", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		fa.setApp("mint", "any", groupBinding("engineering"))
		api := newFakeAuthentikAPI(t)
		h := newMintTestHandler(t, api, []string{"platform"}, mintClaims([]string{"platform"}), nil)
		attachAppPolicies(t, h, fa)

		rec, _, _ := getMintIndex(t, h)
		assert.Equal(t, http.StatusForbidden, rec.Code, "allowed_groups must not admit the session")
	})
	t.Run("fallback route", func(t *testing.T) {
		t.Parallel()
		fa := newFakePolicyAuthentik(t)
		api := newFakeAuthentikAPI(t)
		claims := mintClaims([]string{"platform"})
		h := newMintTestHandler(t, api, []string{"platform"}, claims, nil)
		attachAppPolicies(t, h, fa)

		stateCookie, state, _ := driveMintToCallback(t, h, claims)
		rec := mintCallback(t, h, stateCookie, state)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, int64(1), api.creates.Load())
	})
}

// The wiring in beyond.go attaches a source only when the Authentik API is
// configured; without one every route keeps allowed_groups.
func TestAppPolicy_NoSourceUsesAllowedGroups(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())
	assert.Nil(t, az.AppPolicySource())
	assert.True(t, checkAllowed(az, "argocd.internal", "platform"))
	assert.True(t, checkAllowed(az, "grafana.internal", "engineering"))
}
