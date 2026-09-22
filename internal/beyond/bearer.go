package beyond

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/beyond/tokenverify"
)

// bearerFailureRateLimit caps failed bearer verifications per source IP per
// minute. An unknown `kid` on a token forces a synchronous JWKS re-fetch
// (go-oidc has no negative caching), so without this cap a flood of garbage
// JWTs with random kids becomes a fetch amplifier against Authentik.
// Successful verifications are not counted — a healthy CLI polling an API
// stays under no budget.
const bearerFailureRateLimit = 20

// bearerVerifiers lazily constructs and caches one tokenverify.Verifier per
// application. Config is immutable after boot (no hot-reload since fsnotify
// was removed), so entries are never invalidated; the map is keyed by app
// name. Construction is cheap and non-blocking (the JWKS fetch happens on
// first Verify), but caching preserves go-oidc's in-process JWKS cache,
// which IS the steady-state "zero network calls" property.
type bearerVerifiers struct {
	mu sync.Mutex
	m  map[string]tokenverify.Verifier
}

func newBearerVerifiers() *bearerVerifiers {
	return &bearerVerifiers{m: make(map[string]tokenverify.Verifier)}
}

// Reset drops all cached verifiers so the next forApp rebuilds them from the
// current config. Called on config reload to avoid serving a stale
// issuer/audience/JWKS after a per-app bearer_auth change.
func (bv *bearerVerifiers) Reset() {
	bv.mu.Lock()
	bv.m = make(map[string]tokenverify.Verifier)
	bv.mu.Unlock()
}

func (bv *bearerVerifiers) forApp(app *Application) tokenverify.Verifier {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	if v, ok := bv.m[app.Name]; ok {
		return v
	}
	ba := app.BearerAuth
	v := tokenverify.New(context.Background(), ba.Issuer, ba.JWKSURL, ba.Audience)
	bv.m[app.Name] = v
	return v
}

// handleBearer authenticates a bearer-carrying request against app.BearerAuth
// and, on success, runs the SAME group authorization the cookie path uses
// (allowed_groups + admin_groups bypass) before proxying. Responses on the
// failure paths are plain 401/403/429 — never a 302 to the IdP, never a
// Set-Cookie — because the caller is a CLI, not a browser.
//
// The original Authorization header is left intact on the proxied request so
// the upstream can independently re-verify the token (defense in depth).
func (h *Handler) handleBearer(w http.ResponseWriter, r *http.Request, app *Application, rawToken string, start time.Time) {
	host := stripPort(r.Host)

	logEntry := AccessLogEntry{
		Timestamp: start, // request arrival time, not flush time
		Method:    r.Method,
		Path:      r.URL.Path,
		Host:      host,
		SourceIP:  sourceIP(r),
		UserAgent: r.UserAgent(),
	}
	if app != nil {
		logEntry.Resource = app.Name
	}
	logHTTP := func(decision string, statusCode int) {
		// The host metric label must come from config, never from the
		// attacker-controlled Host header: a flood of random Hosts would
		// otherwise mint unbounded Prometheus time series (cardinality
		// DoS). The access-log entry keeps the raw host — ClickHouse rows
		// are bounded, label sets are not.
		metricHost := "unknown"
		if app != nil {
			metricHost = app.Host
		}
		httpRequestDuration.WithLabelValues(
			metricMethod(r.Method),
			decision,
			fmt.Sprintf("%d", statusCode),
			metricHost,
		).Observe(time.Since(start).Seconds())
		logEntry.Decision = decision
		logEntry.StatusCode = statusCode
		logEntry.DurationMS = int(time.Since(start).Milliseconds())
		h.accessLog.Log("http_bearer", logEntry)
	}

	// Failure rate limit. The slot is consumed atomically upfront (Allow)
	// so a concurrent garbage flood can't slip past a check-then-record
	// gap and amplify JWKS fetches; successful verification refunds it, so
	// only failures spend budget and a healthy CLI never throttles.
	ip := sourceIP(r)
	if !h.bearerFailLimiter.Allow(ip) {
		logEntry.Error = "bearer failure rate limit"
		logHTTP("deny", http.StatusTooManyRequests)
		beyondResponse(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	if app == nil || app.BearerAuth == nil {
		// A bearer aimed at an unknown host or a cookie-only app is an
		// explicit rejection, not a fall-through to the redirect flow: a
		// CLI can't complete an OIDC browser dance, and silently ignoring
		// its credential would turn auth failures into confusing redirect
		// loops. The unknown-host case responds identically to the
		// not-enabled case so unauthenticated callers can't probe which
		// hostnames exist.
		logEntry.Error = "bearer not enabled for application"
		logHTTP("deny", http.StatusUnauthorized)
		beyondResponse(w, "bearer authentication not enabled for this application", http.StatusUnauthorized)
		return
	}

	claims, err := h.bearerVerifiers.forApp(app).Verify(r.Context(), rawToken)
	if err != nil {
		// Record why verification failed. The response stays opaque below —
		// an unauthenticated caller must not learn which check rejected it —
		// so the access log is the only place expiry, audience mismatch and
		// signature failure remain distinguishable for operators.
		logEntry.Error = fmt.Sprintf("invalid bearer token: %s", truncateLogError(err.Error()))
		logHTTP("deny", http.StatusUnauthorized)
		beyondResponse(w, "invalid token", http.StatusUnauthorized)
		return
	}
	h.bearerFailLimiter.Refund(ip)

	logEntry.UserEmail = claims.Email

	// Same deactivated-account gate as the cookie path. The JWT proves the
	// token was valid when minted; IsActive proves the account still is.
	// Without this, a deactivated user keeps bearer access until expiry
	// while their cookie sessions die immediately.
	if h.userValidator != nil && !h.userValidator.IsActive(claims.Email) {
		logEntry.UserGroups = claims.Groups
		logEntry.Error = "account deactivated"
		logHTTP("deny", http.StatusForbidden)
		beyondResponse(w, "account deactivated", http.StatusForbidden)
		return
	}

	// Normalize identity BEFORE authorizing so the allow/deny decision and the
	// injected X-Beyond-* headers use the SAME group set. Normalization
	// applies the OIDC login path's invariant gate (control chars, '|' framing,
	// length caps) and can drop/truncate groups — authorizing on the raw claim
	// groups while injecting the normalized set would let the decision and the
	// forwarded identity diverge. The token signature proves WHO issued the
	// claims, not that they're safe to use as header values.
	identity, err := validateAndNormalizeIdentity(claims.Email, "", claims.PreferredUsername, claims.Groups)
	if err != nil {
		logEntry.UserGroups = claims.Groups
		logEntry.Error = "invalid identity claims"
		logHTTP("deny", http.StatusUnauthorized)
		beyondResponse(w, "invalid token claims", http.StatusUnauthorized)
		return
	}
	logEntry.UserGroups = identity.Groups

	// Same policy gate as the cookie path: allowed_groups + admin bypass,
	// evaluated on the normalized groups that will also be forwarded upstream.
	allowed, _ := h.authorizer.CheckHTTP(host, identity.Groups)
	if !allowed {
		logEntry.Error = "forbidden"
		logHTTP("deny", http.StatusForbidden)
		beyondResponse(w, "forbidden", http.StatusForbidden)
		return
	}

	proxy, err := h.proxies.Get(app.Upstream)
	if err != nil {
		logHTTP("allow", http.StatusBadGateway)
		beyondResponse(w, "bad gateway", http.StatusBadGateway)
		return
	}

	rw := newResponseWriter(w)
	proxy.ServeHTTP(rw, r, identity, app)

	logEntry.Upstream = app.Upstream
	logEntry.BytesSent = rw.bytesWritten.Load()
	logHTTP(proxyDecision(rw), rw.statusCode)
}

// metricMethod maps r.Method onto the standard verb set for use as a metric
// label. Go's HTTP server accepts ANY RFC 7230 token as a method, so the raw
// value is attacker-controlled and unbounded — same cardinality-DoS shape as
// the Host header, same containment: anything nonstandard becomes "OTHER".
func metricMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return m
	default:
		return "OTHER"
	}
}

// bearerToken extracts the token from an `Authorization: Bearer ...` header,
// or "" if the header is absent or differently shaped.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return strings.TrimSpace(auth[len(prefix):])
	}
	return ""
}

// maxLogErrorLen bounds the verification reason recorded in the access log.
// The reason quotes token-derived values — an audience mismatch echoes the
// token's own `aud` claim — so it is attacker-influenced. bearerFailLimiter
// bounds how often these rows are written, not how large each one is, so a
// crafted JWT could otherwise inflate a ClickHouse row arbitrarily.
const maxLogErrorLen = 200

// truncateLogError caps an attacker-influenced error string for the access
// log, dropping any partial rune left by the cut so the stored value is
// always valid UTF-8.
func truncateLogError(s string) string {
	if len(s) <= maxLogErrorLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxLogErrorLen], "") + "(truncated)"
}
