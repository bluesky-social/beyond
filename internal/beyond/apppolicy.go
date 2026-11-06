package beyond

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	appPolicyRefreshInterval = 60 * time.Second
	// appPolicyRetryInterval applies while any route is still unresolved, so
	// a Beyond that started while Authentik was unreachable stops denying
	// soon after Authentik returns.
	appPolicyRetryInterval = 10 * time.Second
	// appPolicyLookupTimeout bounds one route's lookup (application plus
	// every bindings page). It is per route, not per refresh: a refresh-wide
	// deadline would cut off the same tail of the sorted route list every
	// time Authentik is slow, leaving those routes stale or unresolved.
	appPolicyLookupTimeout = 15 * time.Second
	appPolicyPageSize      = 100
	// appPolicyConcurrency bounds parallel route lookups so a refresh stays
	// short without bursting requests at Authentik.
	appPolicyConcurrency = 8
)

// Where a route's group policy comes from. These are also the values of the
// beyond_app_policy_source metric's source label.
const (
	// The Authentik application named by the route exists and its group
	// bindings are the route's only access list.
	appPolicySourceAuthentik = "authentik"
	// Authentik has no application with the route's name, so the route's
	// allowed_groups apply.
	appPolicySourceAllowedGroups = "allowed_groups"
	// No definitive lookup has succeeded yet. The route denies: falling back
	// to allowed_groups could grant more than Authentik does.
	appPolicySourceUnresolved = "unresolved"
	// The application exists but its policy is not one Beyond can evaluate
	// faithfully. The route denies.
	appPolicySourceInvalid = "invalid"
)

var appPolicySources = []string{
	appPolicySourceAuthentik,
	appPolicySourceAllowedGroups,
	appPolicySourceUnresolved,
	appPolicySourceInvalid,
}

// authentikApplicationNotFound is the exact error detail Authentik's API
// returns when no application has the requested slug (Django's
// get_object_or_404 message for the Application model). Only this answer
// moves a route to allowed_groups: any other 404, even one with a JSON
// "detail" from a proxy or another endpoint, is a failed lookup.
const authentikApplicationNotFound = "No Application matches the given query."

// authentikSlugPattern is the slug syntax Authentik accepts (Django's
// SlugField). A route whose name cannot be a slug can have no Authentik
// application, so it is resolved to allowed_groups without a lookup.
var authentikSlugPattern = regexp.MustCompile(`^[-a-zA-Z0-9_]+$`)

// appPolicy is one route's resolved policy. It is immutable once published.
type appPolicy struct {
	source string
	// groups and allow hold the Authentik binding group names; set only for
	// appPolicySourceAuthentik. groups is sorted, for logging.
	groups []string
	allow  map[string]bool
	// reason explains an invalid policy.
	reason string
}

func (p *appPolicy) allowsAny(userGroups []string) bool {
	for _, g := range userGroups {
		if p.allow[g] {
			return true
		}
	}
	return false
}

var unresolvedAppPolicy = &appPolicy{source: appPolicySourceUnresolved}

// AppPolicySource makes Authentik application policy bindings the access list
// for Beyond routes. A route's name (its key under `applications`) is the slug
// of the Authentik application that governs it:
//
//   - The application exists: its bindings are the route's only policy, and
//     the route's allowed_groups are ignored.
//   - Authentik answers 404: the route keeps its allowed_groups.
//   - No definitive answer yet: the route denies every non-admin request.
//
// Beyond evaluates the bindings itself because Authentik's check_access only
// honors for_user for superusers, and Beyond's API token deliberately belongs
// to a read-only non-superuser. Evaluation accepts only the policy shape it
// can reproduce exactly: policy_engine_mode "any" and enabled bindings that
// are plain, non-negated, non-expiring group bindings. A user passes when any
// of their group names (direct groups plus every ancestor, as UserValidator
// resolves them) equals a bound group's name, which is Authentik's own
// group-binding semantics. Disabled bindings are ignored, as Authentik ignores
// them. Any other enabled binding (user, expression or other policy, negated,
// expiring), mode "all", or zero enabled bindings makes the route deny every
// non-admin request. Authentik itself treats an application with no bindings
// as open to every user; Beyond deliberately fails closed instead.
//
// Policies refresh in the background. A failed lookup (transport error,
// non-404 error status, malformed response) keeps the route's last-known-good
// policy; a definitive answer replaces it. Readers see an immutable snapshot
// swapped atomically, so authorization never blocks on a refresh.
type AppPolicySource struct {
	apiURL string
	token  string
	client *http.Client
	logger *slog.Logger

	refreshInterval time.Duration
	retryInterval   time.Duration
	lookupTimeout   time.Duration

	// policies is the published route -> policy snapshot. Writers replace the
	// map under mu and never mutate a published one.
	policies atomic.Pointer[map[string]*appPolicy]

	// mu serializes snapshot writers and guards routes.
	mu sync.Mutex
	// routes maps each route name to its configured allowed_groups, used to
	// log the effective access list when a route falls back to them.
	routes map[string][]string

	ctx     context.Context
	cancel  context.CancelFunc
	wake    chan struct{}
	done    chan struct{}
	started atomic.Bool
}

// NewAppPolicySource creates a source for routes (route name ->
// allowed_groups) that queries the Authentik API at apiURL with token. Every
// route denies until Start loads it.
func NewAppPolicySource(apiURL, token string, routes map[string][]string, logger *slog.Logger) *AppPolicySource {
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &AppPolicySource{
		apiURL:          strings.TrimRight(apiURL, "/"),
		token:           token,
		client:          &http.Client{Timeout: 5 * time.Second},
		logger:          logger,
		refreshInterval: appPolicyRefreshInterval,
		retryInterval:   appPolicyRetryInterval,
		lookupTimeout:   appPolicyLookupTimeout,
		ctx:             ctx,
		cancel:          cancel,
		wake:            make(chan struct{}, 1),
		done:            make(chan struct{}),
	}
	empty := map[string]*appPolicy{}
	s.policies.Store(&empty)
	s.SetRoutes(routes)
	return s
}

// appPolicyRoutes returns the route -> allowed_groups map for cfg, keyed by
// Application.Name as the Authorizer looks routes up.
func appPolicyRoutes(cfg *Config) map[string][]string {
	routes := make(map[string][]string, len(cfg.Applications))
	for _, app := range cfg.Applications {
		if app != nil {
			routes[app.Name] = slices.Clone(app.AllowedGroups)
		}
	}
	return routes
}

// validateAuthentikAPIConfig rejects a half-configured Authentik API. With
// both values unset every route uses allowed_groups by design; with only one
// set, the operator meant to enable Authentik policy, and silently falling
// back to allowed_groups (which may be wider than the bindings) would be a
// fail-open.
func validateAuthentikAPIConfig(apiURL, token string) error {
	if (apiURL == "") != (token == "") {
		return fmt.Errorf("--authentik-api-url and --authentik-api-token must be set together (or both left unset)")
	}
	return nil
}

// Start loads every route once, synchronously, then refreshes in the
// background until Stop or until ctx is cancelled. A failed initial load is
// logged; the affected routes deny and are retried every retryInterval until
// they resolve.
func (s *AppPolicySource) Start(ctx context.Context) {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	context.AfterFunc(ctx, s.cancel)
	s.refresh()
	if unresolved := s.unresolvedRoutes(); len(unresolved) > 0 {
		s.logger.Error("authentik application policies unresolved at startup; these routes deny all non-admin requests until Authentik answers",
			"routes", unresolved, "retry_interval", s.retryInterval.String())
	}
	go s.loop()
}

// Stop ends background refreshes and waits for an in-flight one to finish.
// It is safe to call more than once, and without Start.
func (s *AppPolicySource) Stop() {
	s.cancel()
	if s.started.Load() {
		<-s.done
	}
}

// SetRoutes replaces the route set. Retained routes keep their state, new
// routes deny until resolved, and a background refresh is requested.
func (s *AppPolicySource) SetRoutes(routes map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := *s.policies.Load()
	next := make(map[string]*appPolicy, len(routes))
	s.routes = make(map[string][]string, len(routes))
	for name, groups := range routes {
		s.routes[name] = slices.Clone(groups)
		if p, ok := old[name]; ok {
			next[name] = p
		} else {
			next[name] = unresolvedAppPolicy
		}
	}
	for name := range old {
		if _, ok := next[name]; !ok {
			for _, source := range appPolicySources {
				appPolicySource.DeleteLabelValues(name, source)
			}
		}
	}
	s.policies.Store(&next)
	for name, p := range next {
		setAppPolicySourceMetric(name, p.source)
	}

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// policyFor returns route's current policy. A nil source, or a route the
// source does not know, is unresolved.
func (s *AppPolicySource) policyFor(route string) *appPolicy {
	if s == nil {
		return unresolvedAppPolicy
	}
	if p, ok := (*s.policies.Load())[route]; ok {
		return p
	}
	return unresolvedAppPolicy
}

func (s *AppPolicySource) unresolvedRoutes() []string {
	var names []string
	for name, p := range *s.policies.Load() {
		if p.source == appPolicySourceUnresolved {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (s *AppPolicySource) loop() {
	defer close(s.done)
	timer := time.NewTimer(s.nextInterval())
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
		s.refresh()
		timer.Reset(s.nextInterval())
	}
}

func (s *AppPolicySource) nextInterval() time.Duration {
	if len(s.unresolvedRoutes()) > 0 {
		return s.retryInterval
	}
	return s.refreshInterval
}

type appPolicyResult struct {
	policy *appPolicy // set on a definitive answer
	err    error      // set when the lookup failed
}

// refresh looks every route up and publishes the merged result.
func (s *AppPolicySource) refresh() {
	var names []string
	for name := range *s.policies.Load() {
		names = append(names, name)
	}
	sort.Strings(names)

	results := make([]appPolicyResult, len(names))
	sem := make(chan struct{}, appPolicyConcurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(s.ctx, s.lookupTimeout)
			defer cancel()
			p, err := s.fetch(ctx, name)
			results[i] = appPolicyResult{policy: p, err: err}
		})
	}
	wg.Wait()

	byName := make(map[string]appPolicyResult, len(names))
	for i, name := range names {
		byName[name] = results[i]
	}
	s.apply(byName)
}

// apply merges lookup results into a new snapshot: a definitive answer
// replaces a route's policy, a failed lookup keeps it.
func (s *AppPolicySource) apply(results map[string]appPolicyResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := *s.policies.Load()
	next := make(map[string]*appPolicy, len(old))
	complete := true
	for name, cur := range old {
		res, looked := results[name]
		switch {
		case !looked:
			// Added by SetRoutes after this refresh began; the wake it
			// sent schedules the lookup.
			next[name] = cur
			complete = false
		case res.err != nil:
			next[name] = cur
			complete = false
			if cur.source == appPolicySourceUnresolved {
				s.logger.Error("authentik application policy lookup failed; route denies until it resolves",
					"route", name, "error", res.err)
			} else {
				s.logger.Warn("authentik application policy lookup failed; keeping last-known-good policy",
					"route", name, "source", cur.source, "error", res.err)
			}
		default:
			next[name] = res.policy
			s.logChange(name, cur, res.policy)
		}
	}
	s.policies.Store(&next)
	for name, p := range next {
		setAppPolicySourceMetric(name, p.source)
	}
	if complete {
		appPolicyLastRefreshSuccess.SetToCurrentTime()
	}
}

// logChange records an access-list change for audit. Callers hold s.mu.
func (s *AppPolicySource) logChange(route string, old, next *appPolicy) {
	if old.source == next.source && slices.Equal(old.groups, next.groups) && old.reason == next.reason {
		return
	}
	attrs := []any{
		"route", route,
		"old_source", old.source,
		"new_source", next.source,
		"old_groups", s.effectiveGroups(route, old),
		"new_groups", s.effectiveGroups(route, next),
	}
	switch next.source {
	case appPolicySourceInvalid:
		s.logger.Warn("route policy changed: Authentik application policy is not supported; route denies all non-admin requests",
			append(attrs, "reason", next.reason)...)
	default:
		s.logger.Info("route policy changed", attrs...)
	}
	if next.source == appPolicySourceAuthentik && old.source != appPolicySourceAuthentik && len(s.routes[route]) > 0 {
		s.logger.Warn("route allowed_groups ignored: an Authentik application with the route's name governs it",
			"route", route, "ignored_allowed_groups", s.routes[route])
	}
}

// effectiveGroups is the access list p grants on route, for logging. An empty
// list means the route denies every non-admin request.
func (s *AppPolicySource) effectiveGroups(route string, p *appPolicy) []string {
	switch p.source {
	case appPolicySourceAuthentik:
		return p.groups
	case appPolicySourceAllowedGroups:
		return s.routes[route]
	default:
		return []string{}
	}
}

func setAppPolicySourceMetric(route, source string) {
	for _, s := range appPolicySources {
		v := 0.0
		if s == source {
			v = 1
		}
		appPolicySource.WithLabelValues(route, s).Set(v)
	}
}

// authentikApplication is the subset of Authentik's application object
// Beyond needs.
type authentikApplication struct {
	PK               string `json:"pk"`
	Slug             string `json:"slug"`
	PolicyEngineMode string `json:"policy_engine_mode"`
}

type authentikBindingListResponse struct {
	Pagination struct {
		Current    int `json:"current"`
		TotalPages int `json:"total_pages"`
	} `json:"pagination"`
	Results []authentikPolicyBinding `json:"results"`
}

// authentikPolicyBinding is one policy binding. Fields that decide whether a
// binding is acceptable are pointers or raw JSON so that a field missing from
// the response is an error rather than a zero value that reads as "plain".
type authentikPolicyBinding struct {
	PK       string          `json:"pk"`
	Target   string          `json:"target"`
	Policy   json.RawMessage `json:"policy"`
	Group    json.RawMessage `json:"group"`
	User     json.RawMessage `json:"user"`
	GroupObj *struct {
		Name string `json:"name"`
	} `json:"group_obj"`
	Negate   *bool `json:"negate"`
	Enabled  *bool `json:"enabled"`
	Expiring *bool `json:"expiring"`
}

func invalidAppPolicy(format string, args ...any) *appPolicy {
	return &appPolicy{source: appPolicySourceInvalid, reason: fmt.Sprintf(format, args...)}
}

// fetch resolves route's policy. A nil error means the policy is a definitive
// answer; an error means the lookup failed and the caller keeps the previous
// state.
func (s *AppPolicySource) fetch(ctx context.Context, route string) (*appPolicy, error) {
	if !authentikSlugPattern.MatchString(route) {
		return &appPolicy{source: appPolicySourceAllowedGroups}, nil
	}

	// Retrieve by slug, never the application list: for a non-superuser the
	// list is filtered to applications the caller itself may access.
	status, body, err := s.get(ctx, s.apiURL+"/api/v3/core/applications/"+url.PathEscape(route)+"/")
	if err != nil {
		return nil, fmt.Errorf("retrieving application: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		// A 404 moves the route to allowed_groups, which may grant more than
		// Authentik would. Accept it only as Authentik's own "no such
		// application" answer, not any 404 from a proxy, ingress, or other
		// endpoint that happens to carry a JSON detail.
		var notFound struct {
			Detail *string `json:"detail"`
		}
		if json.Unmarshal(body, &notFound) != nil || notFound.Detail == nil || *notFound.Detail != authentikApplicationNotFound {
			return nil, fmt.Errorf("retrieving application: HTTP 404 that is not Authentik's application-not-found error")
		}
		return &appPolicy{source: appPolicySourceAllowedGroups}, nil
	default:
		return nil, fmt.Errorf("retrieving application: HTTP %d", status)
	}
	var app authentikApplication
	if err := json.Unmarshal(body, &app); err != nil {
		return nil, fmt.Errorf("decoding application: %w", err)
	}
	if app.Slug != route {
		return nil, fmt.Errorf("application lookup for %q returned slug %q", route, app.Slug)
	}
	if app.PK == "" {
		return nil, fmt.Errorf("application %q has an empty pk", route)
	}
	if app.PolicyEngineMode != "any" {
		return invalidAppPolicy("policy_engine_mode is %q; only \"any\" is supported", app.PolicyEngineMode), nil
	}

	bindings, err := s.listBindings(ctx, app.PK)
	if err != nil {
		return nil, err
	}
	allow := make(map[string]bool)
	for _, b := range bindings {
		// Authentik silently ignores unknown filter parameters and returns
		// every binding. Never let another target's bindings in.
		if b.Target != app.PK {
			return nil, fmt.Errorf("binding %s targets %q, not application %q", b.PK, b.Target, app.PK)
		}
		if b.Enabled == nil || b.Negate == nil || b.Expiring == nil || b.Policy == nil || b.Group == nil || b.User == nil {
			return nil, fmt.Errorf("binding %s is missing a required field", b.PK)
		}
		if !*b.Enabled {
			continue
		}
		switch {
		case !isJSONNull(b.Policy):
			return invalidAppPolicy("binding %s binds a policy; only group bindings are supported", b.PK), nil
		case !isJSONNull(b.User):
			return invalidAppPolicy("binding %s binds a user; only group bindings are supported", b.PK), nil
		case isJSONNull(b.Group):
			return invalidAppPolicy("binding %s binds no group", b.PK), nil
		case *b.Negate:
			return invalidAppPolicy("binding %s is negated", b.PK), nil
		case *b.Expiring:
			return invalidAppPolicy("binding %s expires; expiring bindings are not supported", b.PK), nil
		}
		if b.GroupObj == nil || b.GroupObj.Name == "" {
			return nil, fmt.Errorf("group binding %s has no group name", b.PK)
		}
		allow[b.GroupObj.Name] = true
	}
	if len(allow) == 0 {
		return invalidAppPolicy("application has no enabled group bindings (Authentik would admit every user; Beyond denies)"), nil
	}
	groups := make([]string, 0, len(allow))
	for g := range allow {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	return &appPolicy{source: appPolicySourceAuthentik, groups: groups, allow: allow}, nil
}

// listBindings returns every policy binding whose target is pk.
func (s *AppPolicySource) listBindings(ctx context.Context, pk string) ([]authentikPolicyBinding, error) {
	var bindings []authentikPolicyBinding
	for page := 1; ; page++ {
		query := url.Values{
			"target":    {pk},
			"page_size": {strconv.Itoa(appPolicyPageSize)},
			"page":      {strconv.Itoa(page)},
		}
		status, body, err := s.get(ctx, s.apiURL+"/api/v3/policies/bindings/?"+query.Encode())
		if err != nil {
			return nil, fmt.Errorf("listing bindings: %w", err)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("listing bindings: HTTP %d", status)
		}
		var result authentikBindingListResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("decoding bindings: %w", err)
		}
		if result.Pagination.Current != page || result.Pagination.TotalPages < page {
			return nil, fmt.Errorf("invalid Authentik binding pagination: page %d of %d", result.Pagination.Current, result.Pagination.TotalPages)
		}
		bindings = append(bindings, result.Results...)
		if page == result.Pagination.TotalPages {
			return bindings, nil
		}
	}
}

// appPolicyMaxBody bounds an Authentik API response body. A full bindings
// page is tens of kilobytes.
const appPolicyMaxBody = 4 << 20

// get GETs reqURL from the Authentik API and returns the status and body.
func (s *AppPolicySource) get(ctx context.Context, reqURL string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, appPolicyMaxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("reading response: %w", err)
	}
	if len(body) > appPolicyMaxBody {
		return 0, nil, fmt.Errorf("response exceeds %d bytes", appPolicyMaxBody)
	}
	return resp.StatusCode, body, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
