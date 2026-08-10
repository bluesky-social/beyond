package beyond

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// credFailureRateLimit caps failed credential validations per source IP per
// minute. Each failure is a full round-trip to Authentik's token endpoint, so
// without this cap a flood of bad credentials becomes both a brute-force
// channel against app passwords and a load amplifier against Authentik.
// Successful validations refund their slot (see handleCredential), so a
// healthy agent making steady requests never throttles — same shape as
// bearerFailureRateLimit.
const credFailureRateLimit = 20

// maxCredentialLen caps the accepted credential size before any network call.
// A composite "<email>:<app-password>" is well under this; the cap exists so a
// pathological Authorization/x-api-key value can't drive an oversized form POST
// to Authentik. 512 bytes is generous (RFC 5321 caps email at 254; app
// passwords are short random strings).
const maxCredentialLen = 512

// credTokenTimeout bounds each token-endpoint round-trip. The design requires
// failing closed with NO retries on timeout/error (no retry amplification
// against Authentik), so this is the whole budget for one validation.
const credTokenTimeout = 10 * time.Second

// credHTTPClient is the default client for token-endpoint calls. We use a
// dedicated client (never http.DefaultClient) with an explicit transport
// timeout so a hung Authentik can't pin a goroutine indefinitely; the
// per-request context deadline (credTokenTimeout) is the primary bound and
// this is the belt-and-suspenders ceiling.
var credHTTPClient = &http.Client{
	Timeout: credTokenTimeout,
}

// hasCredentialHeader reports whether r carries a credential in either wire
// convention the AI SDK ecosystem uses: `Authorization: Bearer <cred>`
// (OpenAI-style) or `x-api-key: <cred>` (Anthropic-style). Used by the
// dispatch gate so a credential_auth app with no credential at all falls
// through to the normal (browser/redirect) path.
func hasCredentialHeader(r *http.Request) bool {
	return bearerToken(r) != "" || r.Header.Get("x-api-key") != ""
}

// hasCustomCredentialHeader reports whether r carries a non-empty value in
// the app's configured custom credential header (ca.CredentialHeader), if
// any. Used by the dispatch gate so a credential_auth app with a
// credential_header configured also enters handleCredential when that
// header — and only that header — is present, independent of whether
// Authorization/x-api-key are present (they may legitimately carry an
// unrelated credential, e.g. an Anthropic OAuth token).
func hasCustomCredentialHeader(r *http.Request, ca *CredentialAuthConfig) bool {
	if ca.CredentialHeader == "" {
		return false
	}
	// Header.Get returns only the FIRST value for a repeated header field; a
	// client (or an intermediary that concatenates/duplicates headers) could
	// send the custom header twice with a blank first value, which would
	// make Get see "" and skip dispatch even though a real credential rides
	// in a later value. Scan all values via Header.Values, and normalize to
	// the one non-empty value we found via Header.Set so the later Get calls
	// in handleCredential (extraction, then Del to strip it) see exactly the
	// value that triggered this dispatch.
	for _, v := range r.Header.Values(ca.CredentialHeader) {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			r.Header.Set(ca.CredentialHeader, trimmed)
			return true
		}
	}
	return false
}

// extractCredential pulls the composite credential from r, supporting both
// wire conventions. `Authorization: Bearer <cred>` wins over `x-api-key`
// (x-api-key is only consulted when no Bearer matched), matching the OpenAI /
// Anthropic precedence an SDK-shaped client expects.
func extractCredential(r *http.Request) string {
	if tok := bearerToken(r); tok != "" {
		return tok
	}
	return strings.TrimSpace(r.Header.Get("x-api-key"))
}

// splitCredential splits a composite credential on the FIRST colon:
// username is the part before, password is everything after (so a colon inside
// an app password is preserved). Returns ok=false when the credential is
// oversized, has no colon, or has an empty username or password. Callers must
// treat every failure identically (a generic "invalid credential") so the
// response never leaks which part was malformed.
func splitCredential(cred string) (username, password string, ok bool) {
	if cred == "" || len(cred) > maxCredentialLen {
		return "", "", false
	}
	i := strings.IndexByte(cred, ':')
	if i <= 0 || i == len(cred)-1 {
		// No colon, empty username (i==0), or empty password (colon last).
		return "", "", false
	}
	return cred[:i], cred[i+1:], true
}

// credentialClaims is the subset of the Authentik-issued JWT payload beyond
// consumes. Groups uses our provider's custom scope mapping (recursive
// memberships via all_groups()).
type credentialClaims struct {
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// tokenResponse is the relevant subset of Authentik's token-endpoint 200 body.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

// handleCredential authenticates a request carrying a composite
// "<username>:<app-password>" credential by validating it per-request against
// Authentik's token endpoint (client-credentials grant), then runs the SAME
// group authorization the cookie/bearer paths use before proxying. Like
// handleBearer, every failure path is a plain 401/403/429/503 — never a 302 to
// the IdP, never a Set-Cookie — because the caller is an agent harness, not a
// browser.
func (h *Handler) handleCredential(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
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
		// otherwise mint unbounded Prometheus time series (cardinality DoS).
		// The access-log entry keeps the raw host — Postgres rows are bounded,
		// label sets are not.
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
		h.accessLog.Log("http_credential", logEntry)
	}

	// Failure rate limit. The slot is consumed atomically upfront (Allow) so a
	// concurrent bad-credential flood can't slip past a check-then-record gap
	// and amplify token-endpoint calls; successful validation refunds it, so
	// only failures spend budget and a healthy agent never throttles.
	ip := sourceIP(r)
	if !h.credFailLimiter.Allow(ip) {
		logEntry.Error = "credential failure rate limit"
		logHTTP("deny", http.StatusTooManyRequests)
		beyondResponse(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Extract + shape-check the credential BEFORE any network call. A
	// malformed credential spends a rate-limit slot (it is a failure) but
	// never touches Authentik. All shape failures return the same generic
	// "invalid credential" as a rejected credential so the response leaks no
	// format detail.
	//
	// Precedence: when the app configures a custom credential_header AND the
	// request carries it, ITS value wins — even if Authorization/x-api-key
	// are ALSO present. The custom header is the more specific signal (an
	// operator opted a client contract into it deliberately), and the
	// standard headers may legitimately carry a credential that is NOT
	// beyond's to consume (e.g. an official Claude Code client's own
	// Anthropic OAuth token in Authorization: Bearer sk-ant-oat...). Treating
	// Authorization/x-api-key as the beyond credential in that case would be
	// wrong twice over: it would try to validate an oat token as an app
	// password, and — worse — handleCredential would then strip the client's
	// own OAuth token before proxying instead of forwarding it untouched.
	usingCustomHeader := hasCustomCredentialHeader(r, app.CredentialAuth)
	var cred string
	if usingCustomHeader {
		cred = strings.TrimSpace(r.Header.Get(app.CredentialAuth.CredentialHeader))
	} else {
		cred = extractCredential(r)
	}
	username, password, ok := splitCredential(cred)
	if !ok {
		credentialValidations.WithLabelValues("invalid").Inc()
		logEntry.Error = "malformed credential"
		logHTTP("deny", http.StatusUnauthorized)
		beyondResponse(w, "invalid credential", http.StatusUnauthorized)
		return
	}

	claims, status := h.validateCredential(r.Context(), app.CredentialAuth, username, password)
	switch status {
	case credOK:
		// fall through to authorization below
	case credInvalid:
		// Rejected credential (bad user/key, policy-denied, deactivated,
		// wrong client_id). This is precisely the failure the rate limiter
		// exists for, so the slot is NOT refunded.
		credentialValidations.WithLabelValues("invalid").Inc()
		logEntry.Error = "invalid credential"
		logHTTP("deny", http.StatusUnauthorized)
		beyondResponse(w, "invalid credential", http.StatusUnauthorized)
		return
	case credUnavailable:
		// Authentik unreachable / 5xx / timeout. Fail closed with 503 and no
		// retry (no retry amplification — design requirement). The specific
		// error is logged server-side only; the client gets a generic message.
		credentialValidations.WithLabelValues("unavailable").Inc()
		logHTTP("deny", http.StatusServiceUnavailable)
		beyondResponse(w, "authentication service unavailable", http.StatusServiceUnavailable)
		return
	}

	logEntry.UserEmail = claims.Email

	// Normalize identity BEFORE authorizing so the allow/deny decision and the
	// injected X-Beyond-* headers use the SAME group set (same reasoning as the
	// bearer path). Authentik issued these claims directly to us over the
	// in-cluster channel, but normalization still applies the invariant gate
	// (control chars, '|' framing, length caps) so a malformed group can't
	// produce an opaque 502 downstream or a decision/forwarded-set mismatch.
	//
	// No separate IsActive check here: Authentik enforces user is_active and
	// the gateway app's policy bindings INSIDE the client-credentials grant, so
	// a successful validation already proves the account is active — the check
	// the bearer path runs is redundant on this path.
	identity, err := validateAndNormalizeIdentity(claims.Email, "", claims.PreferredUsername, claims.Groups)
	if err != nil {
		// A 200 from Authentik with unusable claims (missing/malformed email)
		// is not a rejected credential, but from the client's perspective it is
		// still an unauthenticated request. Refund the failure slot: the
		// credential itself validated, so this is not the brute-force signal
		// the limiter guards against.
		h.credFailLimiter.Refund(ip)
		credentialValidations.WithLabelValues("invalid").Inc()
		logEntry.UserGroups = claims.Groups
		logEntry.Error = "invalid identity claims"
		logHTTP("deny", http.StatusUnauthorized)
		beyondResponse(w, "invalid credential", http.StatusUnauthorized)
		return
	}
	// Validation succeeded and produced a usable identity: refund the slot so
	// only genuine failures spend budget.
	h.credFailLimiter.Refund(ip)
	credentialValidations.WithLabelValues("ok").Inc()
	logEntry.UserGroups = identity.Groups

	// Same policy gate as the cookie/bearer paths: allowed_groups + admin
	// bypass, evaluated on the normalized groups that will also be forwarded.
	allowed, _ := h.authorizer.CheckHTTP(host, identity.Groups)
	if !allowed {
		logEntry.Error = "forbidden"
		logHTTP("deny", http.StatusForbidden)
		beyondResponse(w, "forbidden", http.StatusForbidden)
		return
	}

	// Strip the credential before proxying. Unlike the bearer path — which
	// deliberately FORWARDS Authorization so the upstream can independently
	// re-verify the JWT (defense in depth) — the credential_auth upstream (the
	// AI gateway) has no auth of its own and the credential is a live secret.
	// It must never leave beyond.
	//
	// When the custom header carried the credential, strip ONLY that header:
	// Authorization/x-api-key were never the beyond credential on this path
	// (see the precedence comment above) and may carry a client credential
	// the upstream needs verbatim (e.g. an Anthropic OAuth token), so they
	// must not be touched. Otherwise (legacy path), delete both
	// wire-convention headers as before.
	if usingCustomHeader {
		r.Header.Del(app.CredentialAuth.CredentialHeader)
	} else {
		r.Header.Del("Authorization")
		r.Header.Del("x-api-key")
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

// credStatus is the outcome of a single token-endpoint validation.
type credStatus int

const (
	credOK          credStatus = iota // 200 with a decodable access_token
	credInvalid                       // 4xx (invalid_grant / invalid_client / etc.)
	credUnavailable                   // 5xx, network error, or timeout
)

// validateCredential POSTs the (username, app-password) pair to Authentik's
// token endpoint using the client-credentials grant and returns the decoded
// JWT claims on success. It classifies the outcome into credOK / credInvalid /
// credUnavailable so the caller can map each to the right status code and
// rate-limit disposition. No retries: a single attempt per request (the design
// forbids retry amplification against Authentik).
func (h *Handler) validateCredential(ctx context.Context, ca *CredentialAuthConfig, username, password string) (credentialClaims, credStatus) {
	ctx, cancel := context.WithTimeout(ctx, credTokenTimeout)
	defer cancel()

	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {ca.ClientID},
		// Authentik matches `username` against the user's username field,
		// which is the full email for our users.
		"username": {username},
		"password": {password},
		"scope":    {"openid email groups"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ca.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		// A malformed token_url survives config validation only if it parses
		// as absolute http(s) but is otherwise unusable; treat as unavailable
		// (fail closed) and log server-side.
		slog.Error("credential_auth: build token request", "error", err)
		return credentialClaims{}, credUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := h.credClient
	if client == nil {
		client = credHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// Network error, connection refused, or context timeout — fail closed.
		slog.Error("credential_auth: token endpoint request failed", "error", err)
		return credentialClaims{}, credUnavailable
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		// proceed
	case resp.StatusCode >= 500:
		slog.Error("credential_auth: token endpoint 5xx", "status", resp.StatusCode)
		return credentialClaims{}, credUnavailable
	default:
		// Any non-200, non-5xx (400 invalid_grant / invalid_client, 401, 403,
		// etc.) is a rejected credential.
		return credentialClaims{}, credInvalid
	}

	// Cap the body read: a 200 from a healthy Authentik is a small JSON blob,
	// so bound it to avoid a compromised/confused endpoint streaming unbounded
	// data into memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		slog.Error("credential_auth: read token response", "error", err)
		return credentialClaims{}, credUnavailable
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		slog.Error("credential_auth: decode token response", "error", err)
		return credentialClaims{}, credUnavailable
	}

	claims, err := decodeJWTClaims(tr.AccessToken)
	if err != nil {
		slog.Error("credential_auth: decode access token claims", "error", err)
		return credentialClaims{}, credUnavailable
	}
	return claims, credOK
}

// decodeJWTClaims decodes (WITHOUT verifying the signature) the payload of a
// compact JWS and returns the claims beyond consumes.
//
// Skipping signature verification is deliberate and safe HERE — and ONLY here:
// beyond receives this JWT as the direct HTTP response body from Authentik's
// token endpoint over the trusted in-cluster channel (the same trust posture
// as bearer_auth's jwks_url fetch). The token did not arrive from an untrusted
// client, so there is no attacker in the position to substitute a forged
// payload; verifying a signature on a body we just received from the signer
// over a trusted channel would add a JWKS fetch and key-management surface for
// no security gain. (The bearer path, by contrast, DOES verify, because there
// the token arrives from the client.)
func decodeJWTClaims(token string) (credentialClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return credentialClaims{}, fmt.Errorf("credential_auth: token is not a compact JWS (%d segments)", len(parts))
	}
	// JWT uses base64url without padding (RFC 7519 / RFC 7515).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return credentialClaims{}, fmt.Errorf("credential_auth: decode token payload: %w", err)
	}
	var claims credentialClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return credentialClaims{}, fmt.Errorf("credential_auth: unmarshal token claims: %w", err)
	}
	return claims, nil
}
