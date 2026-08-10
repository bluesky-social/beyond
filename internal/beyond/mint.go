package beyond

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The app-password mint page.
//
// Unlike the rest of beyond (a reverse proxy), a mint app IS the upstream: a
// bespoke handler that renders HTML and, inside its OIDC callback, calls
// Authentik's token API AS THE USER to create an app password and render the
// composite `<username>:<app-password>` once. The value-add over Authentik's
// own UI is a sane expiry (the user's cap, not the +30-min default) and the
// pre-assembled composite behind one memorable URL.
//
// Keys are per-purpose: the user supplies a short purpose label (e.g. "aigw",
// "gcx") on the confirmation page. The label appears in the Authentik token
// identifier for bookkeeping and revocation ergonomics. It does NOT restrict
// which services the key works with — an Authentik app password is a
// user-level credential valid across all beyond-fronted services that accept
// app passwords. The per-purpose overwrite sweep enforces one key per user per
// purpose, not one key globally.
//
// Security posture (all load-bearing — see the doc):
//   - The API-scoped access token from the code exchange NEVER crosses a
//     request boundary: it lives in one handler stack frame (the A3 custody
//     model), never in a cookie, DB, or log line.
//   - GET / and POST /start-mint require a beyond session and pass the app's
//     allowed_groups, exactly like a proxied app. Session-required is beyond's
//     default for browser surfaces; a mint app being bespoke does not exempt
//     it. Only /mint/callback is sessionless (see handleMint).
//   - Minting is never a side effect of navigation. A bare GET renders a
//     button; only an explicit CSRF-protected POST /start-mint enters the OIDC
//     flow (closes the drive-by-mint hole). The session gate above sits in
//     front of this one; it does not replace it, because a logged-in user is
//     exactly who a drive-by mint would target.
//   - The mint-state cookie is single-use: the callback clears it before any
//     Authentik write, on success and on every error path, so a refresh/replay
//     can't mint twice.
//   - allowed_groups is enforced in the callback from the id_token groups,
//     BEFORE any token-create call (403 + zero Authentik writes if denied).
//   - Partial-success cleanup: if token-create succeeds but view_key/render
//     fails before any response body is written, the created token is deleted.

const (
	// mintStateCookieName holds the encrypted OIDC state for the mint flow. It
	// is deliberately distinct from the login flow's _beyond_oidc_state so the
	// two flows can never consume each other's state.
	mintStateCookieName = "_beyond_mint_state"
	// mintCSRFCookieName holds the encrypted CSRF token bound to the GET /
	// confirmation page; POST /start-mint requires the form value to match.
	mintCSRFCookieName = "_beyond_mint_csrf"

	// mintStateCookieTTL bounds how long a user has to complete the OIDC hop
	// after clicking the button. Same window as the login flow.
	mintStateCookieTTL = 10 * time.Minute
	// mintCSRFCookieTTL bounds how long the confirmation page stays actionable
	// before a fresh GET / is required. Generous — the page may sit open a while.
	mintCSRFCookieTTL = 30 * time.Minute
)

// mintAPITimeout bounds each Authentik API round-trip (token-create, view_key,
// delete). The API is in-cluster plain HTTP; a hung Authentik must not pin the
// handler. No retries (same fail-closed discipline as credential_auth).
const mintAPITimeout = 15 * time.Second

// mintHTTPClient is the default client for the Authentik API calls. Dedicated
// (never http.DefaultClient) with an explicit ceiling; the per-request context
// deadline (mintAPITimeout) is the primary bound.
var mintHTTPClient = &http.Client{
	Timeout: mintAPITimeout,
}

// mintPurposeRe validates a purpose label supplied by the user. It must start
// with an alphanumeric character and contain only lowercase letters, digits,
// and hyphens, up to 32 characters total. Short labels like "aigw" and "gcx"
// are the expected common case.
var mintPurposeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// mintLegacyIDRe matches identifiers created before per-purpose labeling was
// introduced. Legacy identifiers look like "beyond-mint-<32 hex chars>" with
// no purpose segment. These are treated as de-facto "aigw" keys during the
// per-purpose overwrite sweep so that existing deployed keys are reaped
// correctly when the user re-mints with purpose "aigw".
//
// This pattern must NOT misfire on purpose-format identifiers. A
// purpose-format id looks like "beyond-mint-<purpose>-<32 hex>", and since a
// purpose is 1-32 chars of [a-z0-9-] it can never satisfy the exactly-32-hex
// constraint that anchors this pattern.
var mintLegacyIDRe = regexp.MustCompile(`^beyond-mint-[0-9a-f]{32}$`)

// mintHexSuffixRe matches the random suffix of a purpose-format identifier.
// The sweep requires the full "<purpose>-<32 hex>" shape rather than a bare
// "beyond-mint-<purpose>-" prefix so that a purpose which is itself a prefix
// of another (hyphens are legal: "gcx" vs "gcx-prod") can never sweep the
// longer purpose's keys.
var mintHexSuffixRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// SetMintAuth attaches the mint flow's OIDCAuth for the application served at
// host. Nil-safe: a mint host with no configured OIDCAuth returns a clean 500
// from the callback rather than dereferencing nil.
func (h *Handler) SetMintAuth(host string, auth *OIDCAuth) {
	h.mu.Lock()
	if h.mintAuths == nil {
		h.mintAuths = make(map[string]*OIDCAuth)
	}
	h.mintAuths[strings.ToLower(host)] = auth
	h.mu.Unlock()
}

func (h *Handler) mintAuthFor(host string) *OIDCAuth {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.mintAuths[strings.ToLower(host)]
}

// mintRedirectURL derives the mint OIDC callback URL from the request host,
// mirroring oidcRedirectURL but on the mint-specific path. The caller only
// reaches this for a host beyond serves (handleProxy dispatches by LookupApp),
// so r.Host is a configured mint host, not attacker-chosen.
func mintRedirectURL(r *http.Request) string {
	return "https://" + r.Host + "/mint/callback"
}

// handleMint is the dispatch entry for a mint application. handleProxy routes
// here (before session load) whenever the request's host is a mint app, so the
// whole request lifecycle for a mint host is bespoke — it never proxies.
func (h *Handler) handleMint(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		h.handleMintIndex(w, r, app, start)
	case r.Method == http.MethodPost && r.URL.Path == "/start-mint":
		h.handleMintStart(w, r, app, start)
	case r.Method == http.MethodGet && r.URL.Path == "/mint/callback":
		// Deliberately NOT session-gated, unlike the two routes above. The
		// authority here is the single-use encrypted mint-state cookie plus
		// the verified id_token, and a login redirect at this point would
		// discard an in-flight authorization code. In practice the user always
		// holds a session by now — they needed one to reach the button.
		h.handleMintCallback(w, r, app, start)
	default:
		// A mint app serves only these three routes; anything else is a 404.
		h.mintLog(r, app, start, "deny", http.StatusNotFound, "unknown mint route")
		beyondResponse(w, "not found", http.StatusNotFound)
	}
}

// mintLog records an access-log entry + duration metric for a mint request,
// using the config host for the metric label (never the raw Host header) to
// keep Prometheus cardinality bounded — same containment as the proxy paths.
func (h *Handler) mintLog(r *http.Request, app *Application, start time.Time, decision string, statusCode int, errMsg string) {
	host := stripPort(r.Host)
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

	h.accessLog.Log("http_mint", AccessLogEntry{
		Timestamp:  start,
		Method:     r.Method,
		Path:       r.URL.Path,
		Host:       host,
		SourceIP:   sourceIP(r),
		UserAgent:  r.UserAgent(),
		Resource:   app.Name,
		Decision:   decision,
		StatusCode: statusCode,
		DurationMS: int(time.Since(start).Milliseconds()),
		Error:      errMsg,
	})
}

// mintNoSessionBehavior selects what a mint handler does when the request
// carries no beyond session.
type mintNoSessionBehavior int

const (
	// mintNoSessionLogin redirects into the ordinary OIDC login flow. Correct
	// for GET /: the browser comes back to the same URL once authenticated.
	mintNoSessionLogin mintNoSessionBehavior = iota
	// mintNoSessionNotice renders a start-again notice instead of redirecting.
	// Correct for POST /start-mint: a login redirect would discard the form
	// body and return the browser to GET /start-mint, which is a 404.
	mintNoSessionNotice
)

// mintSessionOK enforces the two gates every beyond-fronted app applies before
// serving a browser: a valid session, and the app's allowed_groups. It writes
// the response and returns false when the request must not proceed.
//
// The session's groups are the login-time set. That is deliberate and
// sufficient here because this gate only decides whether to render a page —
// the authoritative pre-write check remains the callback's, which re-derives
// groups from a freshly verified id_token before any token-create. A user
// whose access was revoked mid-session can reach the form and still cannot
// mint.
func (h *Handler) mintSessionOK(w http.ResponseWriter, r *http.Request, app *Application, start time.Time, onMissing mintNoSessionBehavior) bool {
	sess, err := h.sessions.Load(r)
	if err != nil {
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "session load")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if sess == nil {
		if onMissing == mintNoSessionNotice {
			h.mintLog(r, app, start, "deny", http.StatusForbidden, "no session")
			h.renderMintNotice(w, "Session expired",
				"Your session expired before the key was created. Start again to create one.",
				http.StatusForbidden)
			return false
		}
		h.mintLog(r, app, start, "redirect", http.StatusFound, "no session")
		h.startLogin(w, r)
		return false
	}
	if allowed, _ := h.authorizer.CheckHTTP(stripPort(r.Host), sess.Groups); !allowed {
		h.mintLog(r, app, start, "deny", http.StatusForbidden, "forbidden")
		h.renderMintNotice(w, "Not permitted",
			"You are not permitted to create an access key.", http.StatusForbidden)
		return false
	}
	return true
}

// handleMintIndex renders the confirmation page: a CSRF-protected form that
// POSTs to /start-mint with a purpose label. It mints a CSRF token, binds it
// into an encrypted cookie, and embeds the same value in the form
// (double-submit). A bare GET NEVER starts OIDC and NEVER mints — it only
// shows the form.
func (h *Handler) handleMintIndex(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	// A mint host is a beyond-fronted app like any other: no session, no page.
	// An anonymous GET goes through the ordinary login flow and comes back
	// here (originalURL is "/"), rather than rendering the form to the open
	// internet — the load balancer in front of beyond is typically
	// internet-facing, so "renders a button" meant "renders a button to
	// anyone".
	//
	// This does NOT reopen the drive-by-mint hole. startLogin establishes a
	// plain beyond session; it has no API scope and creates no token. Minting
	// still requires the explicit CSRF-protected POST /start-mint and its own
	// separate API-scoped OIDC hop.
	if !h.mintSessionOK(w, r, app, start, mintNoSessionLogin) {
		return
	}

	// ?purpose=<label> pre-fills the form field so per-consumer mint links
	// (docs, golinks like go/gcx-key) can select a purpose without any
	// client-side tooling. Prefill only — the POST re-validates, and an
	// invalid query value silently falls back to the default rather than
	// erroring (the link is advisory, the form is authoritative).
	purpose := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("purpose")))
	if !mintPurposeRe.MatchString(purpose) {
		purpose = "aigw"
	}
	h.renderMintIndexPage(w, r, app, start, "", purpose, http.StatusOK)
}

// renderMintIndexPage renders the index confirmation page with an optional
// inline error message, a purpose value to pre-fill the form field, and an
// HTTP status code. It is called by handleMintIndex (no error, 200, purpose
// from the query string) and by handleMintStart when purpose validation fails
// (error message, 400, the user's rejected input so they can correct it).
// Issuing a fresh CSRF token on each render is correct: the old token was
// consumed or was never issued, so a fresh one is needed.
func (h *Handler) renderMintIndexPage(w http.ResponseWriter, r *http.Request, app *Application, start time.Time, errMsg, purpose string, code int) {
	csrf, err := randHex(32)
	if err != nil {
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "csrf gen")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	cookieVal, err := h.encryptMintCSRF(csrf)
	if err != nil {
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "csrf encrypt")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mintCSRFCookieName,
		Value:    cookieVal,
		Path:     "/",
		MaxAge:   int(mintCSRFCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	nonce, err := randHex(16)
	if err != nil {
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "nonce gen")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := mintIndexTmpl.Execute(&buf, mintIndexData{CSRFToken: csrf, Nonce: nonce, Error: errMsg, Purpose: purpose}); err != nil {
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "render index")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The form POSTs to same-origin /start-mint, which 302s to the Authentik
	// authorize endpoint. form-action must allow that origin or the browser
	// blocks the redirect. This is the only mint page with a form.
	writeMintHTML(w, nonce, originOf(app.MintAuth.Issuer), code, buf.Bytes())
	if code == http.StatusOK {
		h.mintLog(r, app, start, "allow", http.StatusOK, "")
	}
}

// handleMintStart is the only entry to the mint flow. It verifies the CSRF
// token, generates OIDC state/verifier/nonce, binds them into the encrypted
// mint-state cookie, and redirects to Authentik via the mint OIDCAuth. Because
// this is the sole gate, every mint traces to an explicit click in this
// browser (closes the drive-by-mint hole).
func (h *Handler) handleMintStart(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	// Same session + allowed_groups gates as the index page. Reaching here
	// without a session means it expired while the confirmation page sat open
	// (the CSRF cookie outlives it), so this renders a start-again notice
	// rather than redirecting a POST.
	//
	// This runs BEFORE the rate limiter deliberately. oidcLimiter is shared
	// with the login flow, so charging it here would (a) let anonymous POSTs
	// that can never reach the OIDC hop spend capacity belonging to real
	// logins on the same source IP, and (b) turn the notice above into a bare
	// 429 for an expired user whose IP is over the limit.
	if !h.mintSessionOK(w, r, app, start, mintNoSessionNotice) {
		return
	}

	// Rate-limit the crypto-heavy redirect path per source IP, same as login.
	ip := sourceIP(r)
	if !h.oidcLimiter.Allow(ip) {
		h.mintLog(r, app, start, "deny", http.StatusTooManyRequests, "rate limit")
		beyondResponse(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Verify CSRF: the encrypted cookie's token must match the form value. An
	// attacker cross-site POSTing here can't forge the encrypted cookie value
	// nor read it (HttpOnly) to place a matching form field. Constant-time
	// compare so a mismatch leaks no timing signal.
	if err := r.ParseForm(); err != nil {
		mintOperations.WithLabelValues("csrf_rejected").Inc()
		h.mintLog(r, app, start, "deny", http.StatusBadRequest, "bad form")
		beyondResponse(w, "bad request", http.StatusBadRequest)
		return
	}
	formToken := r.PostFormValue("csrf_token")
	cookie, err := r.Cookie(mintCSRFCookieName)
	if err != nil || !h.verifyMintCSRF(cookie.Value, formToken) {
		mintOperations.WithLabelValues("csrf_rejected").Inc()
		h.mintLog(r, app, start, "deny", http.StatusForbidden, "csrf mismatch")
		beyondResponse(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	// Read and validate the purpose label. Empty => default "aigw". Lowercase
	// normalization is the only silent mutation we apply; anything else that
	// fails the pattern is rejected with an inline error so the user sees
	// exactly what went wrong.
	purpose := strings.ToLower(strings.TrimSpace(r.PostFormValue("purpose")))
	if purpose == "" {
		purpose = "aigw"
	}
	if !mintPurposeRe.MatchString(purpose) {
		mintOperations.WithLabelValues("invalid_purpose").Inc()
		h.mintLog(r, app, start, "deny", http.StatusBadRequest, "invalid purpose")
		// Re-render the index page with an inline error rather than a bare
		// error page; the rejected input is preserved in the field so the
		// user can correct it and resubmit. Template escaping makes echoing
		// the raw value safe.
		h.renderMintIndexPage(w, r, app, start,
			"Invalid purpose: use only lowercase letters, digits, and hyphens (e.g. aigw, gcx).",
			purpose, http.StatusBadRequest)
		return
	}

	auth := h.mintAuthFor(stripPort(r.Host))
	if auth == nil {
		mintOperations.WithLabelValues("error").Inc()
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "mint oidc not configured")
		beyondResponse(w, "mint not configured", http.StatusInternalServerError)
		return
	}

	state, verifier, nonce := auth.GenerateAuthParams()
	stateCookie, err := h.encryptMintState(state, verifier, nonce, purpose)
	if err != nil {
		mintOperations.WithLabelValues("error").Inc()
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "state encrypt")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mintStateCookieName,
		Value:    stateCookie,
		Path:     "/",
		MaxAge:   int(mintStateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	// Clear the CSRF cookie now that it has been consumed (single-use).
	clearMintCookie(w, mintCSRFCookieName)

	h.mintLog(r, app, start, "allow", http.StatusFound, "")
	auth.HandleLogin(w, r, state, verifier, nonce, mintRedirectURL(r))
}

// handleMintCallback is the crux: it exchanges the code, enforces groups, and
// (only if permitted) creates the app password and renders the composite once,
// all in one handler. The access token never leaves this stack frame.
func (h *Handler) handleMintCallback(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	auth := h.mintAuthFor(stripPort(r.Host))
	if auth == nil {
		mintOperations.WithLabelValues("error").Inc()
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "mint oidc not configured")
		beyondResponse(w, "mint not configured", http.StatusInternalServerError)
		return
	}

	cookie, err := r.Cookie(mintStateCookieName)
	if err != nil {
		// No state cookie: a refresh/replay of the callback URL, or a direct
		// hit. Render the non-minting "already used" page — never a raw OIDC
		// error, never a mint.
		mintOperations.WithLabelValues("replay").Inc()
		h.renderMintReplay(w, r, app, start)
		return
	}
	state, verifier, nonce, purpose, err := h.decryptMintState(cookie.Value)
	if err != nil {
		mintOperations.WithLabelValues("replay").Inc()
		h.renderMintReplay(w, r, app, start)
		return
	}

	// Single-use: consume the state cookie NOW, before the code exchange or any
	// Authentik write. Cleared on success and on every subsequent error path,
	// so a replayed callback finds no valid state and mints nothing.
	clearMintCookie(w, mintStateCookieName)

	// Bound the code exchange + id_token verification (which lazily fetches
	// JWKS). Without this the exchange runs on bare r.Context(), and since the
	// proxy server disables WriteTimeout for streaming, a hung/blackholed token
	// endpoint could pin this handler goroutine until the client disconnects.
	// Same discipline doMint applies to its Authentik API calls.
	exchangeCtx, cancel := context.WithTimeout(r.Context(), mintAPITimeout)
	defer cancel()
	identity, accessToken, err := auth.HandleMintCallback(
		exchangeCtx, r, state, verifier, nonce, mintRedirectURL(r),
	)
	if err != nil {
		// Bad state, exchange failure, id_token/nonce failure, or unusable
		// claims. No Authentik write has happened. Log server-side only.
		mintOperations.WithLabelValues("error").Inc()
		slog.Error("mint callback failed", "error", err)
		h.mintLog(r, app, start, "deny", http.StatusForbidden, "callback auth failed")
		h.renderMintError(w, r, app, "Authentication failed. Start again to mint a key.", http.StatusForbidden)
		return
	}

	// Enforce allowed_groups from the verified id_token groups BEFORE any
	// token-create call — the same gate the cookie/bearer/credential paths use.
	// The access token is discarded unused on denial: zero Authentik writes.
	host := stripPort(r.Host)
	allowed, _ := h.authorizer.CheckHTTP(host, identity.Groups)
	if !allowed {
		mintOperations.WithLabelValues("group_denied").Inc()
		h.mintLog(r, app, start, "deny", http.StatusForbidden, "forbidden")
		h.renderMintError(w, r, app, "You are not permitted to create an access key.", http.StatusForbidden)
		return
	}

	// Mint: create the app password, then read its key back. On any failure
	// after a successful create but before we write the result body, delete the
	// orphaned token (partial-success cleanup).
	h.doMint(w, r, app, identity, accessToken, purpose, start)
}

// doMint performs the create + view_key against Authentik as the user, then
// renders the composite once. accessToken is a live secret held only for the
// duration of this call; it is never persisted or logged. purpose is the
// validated key-purpose label carried through the OIDC round-trip.
func (h *Handler) doMint(w http.ResponseWriter, r *http.Request, app *Application, identity *Identity, accessToken, purpose string, start time.Time) {
	ma := app.MintAuth
	ctx, cancel := context.WithTimeout(r.Context(), mintAPITimeout)
	defer cancel()

	randSuffix, err := randHex(16)
	if err != nil {
		mintOperations.WithLabelValues("error").Inc()
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "identifier gen")
		h.renderMintError(w, r, app, "Internal error. Please try again.", http.StatusInternalServerError)
		return
	}
	// Identifier format: "beyond-mint-<purpose>-<32 hex chars>". The purpose
	// segment makes each key self-describing in Authentik's token list and
	// enables per-purpose overwrite sweep without touching keys for other
	// purposes or hand-created tokens.
	identifier := "beyond-mint-" + purpose + "-" + randSuffix

	// Create the app password. Authentik force-pins the token to the caller
	// (a non-superuser cannot mint for another user), so we never send a user
	// field. Expiry is an absolute datetime = now + the configured lifetime.
	createStatus := h.createAppPassword(ctx, ma, accessToken, identifier)
	switch createStatus {
	case mintAPIOK:
		// proceed to view_key
	case mintAPICapExceeded:
		mintOperations.WithLabelValues("cap_exceeded").Inc()
		h.mintLog(r, app, start, "deny", http.StatusBadRequest, "expiry exceeds cap")
		h.renderMintError(w, r, app,
			"The requested key lifetime exceeds your account's maximum. Contact platform if you need a longer-lived key.",
			http.StatusBadRequest)
		return
	case mintAPIRejected:
		mintOperations.WithLabelValues("error").Inc()
		h.mintLog(r, app, start, "deny", http.StatusForbidden, "token create rejected")
		h.renderMintError(w, r, app, "Authentik rejected the request. Start again to retry.", http.StatusForbidden)
		return
	case mintAPIUnavailable:
		mintOperations.WithLabelValues("unavailable").Inc()
		h.mintLog(r, app, start, "deny", http.StatusServiceUnavailable, "authentik unavailable")
		h.renderMintError(w, r, app, "The authentication service is unavailable. Please try again shortly.", http.StatusServiceUnavailable)
		return
	}

	// A token now exists in Authentik. From here, any failure before we write
	// the result body must delete the orphan (partial-success cleanup).
	key, ok := h.viewKey(ctx, ma, accessToken, identifier)
	if !ok {
		h.cleanupOrphan(w, r, app, ma, accessToken, identifier, start)
		return
	}

	// Overwrite semantics: re-minting should REPLACE the user's existing key for
	// this purpose, not pile up. Authentik has no upsert (token identifiers are
	// globally unique, so a re-POST with a fixed id 400s, and we can't share an
	// id across users), so we mint fresh then sweep the caller's OTHER
	// beyond-mint-<purpose>-* tokens. Sweep AFTER the successful create (not
	// before) so a failed create never revokes a working deployed key — the user
	// always ends with exactly one usable key per purpose, and each successful
	// mint self-heals any prior pile-up. Best-effort: a sweep failure must not
	// fail the mint (the new key is already valid). The purpose-scoped prefix
	// filter means keys for other purposes and hand-made app passwords are never
	// touched.
	h.revokeOldMintTokens(ctx, ma, accessToken, identifier, purpose, identity)

	// Build the whole result page into a buffer first, so a render error can
	// still trigger orphan cleanup before any bytes are written. Once we start
	// writing, a client disconnect is the one irreducible orphan window — we log
	// the token id so the user can revoke it (see the result page copy).
	nonce, err := randHex(16)
	if err != nil {
		h.cleanupOrphan(w, r, app, ma, accessToken, identifier, start)
		return
	}
	composite := identity.Email + ":" + key
	var buf bytes.Buffer
	data := mintResultData{
		Composite: composite,
		Username:  identity.Email,
		Nonce:     nonce,
		ExpiresIn: humanizeDuration(ma.TokenLifetime),
		Purpose:   purpose,
	}
	if err := mintResultTmpl.Execute(&buf, data); err != nil {
		h.cleanupOrphan(w, r, app, ma, accessToken, identifier, start)
		return
	}

	// Cache-Control: no-store keeps the secret out of any cache; the result
	// template swaps the URL to "/" via history.replaceState so a refresh
	// reloads the confirmation page instead of reissuing the callback. No form
	// on this page, so form-action stays 'none'.
	writeMintHTML(w, nonce, "", http.StatusOK, buf.Bytes())
	mintOperations.WithLabelValues("minted").Inc()
	// Log the token identifier (NOT the key) so the residual client-disconnect
	// orphan window is recoverable: if the page didn't finish displaying, the
	// user can revoke exactly this token.
	slog.Info("app password minted", "identifier", identifier, "user", identity.Email)
	h.mintLog(r, app, start, "allow", http.StatusOK, "")
}

// cleanupOrphan deletes a just-created token whose key could not be retrieved
// or rendered, then renders an error page. If the delete cannot be confirmed,
// the page tells the user a key may exist and links to Authentik to revoke it.
func (h *Handler) cleanupOrphan(w http.ResponseWriter, r *http.Request, app *Application, ma *MintAuthConfig, accessToken, identifier string, start time.Time) {
	mintOperations.WithLabelValues("orphan").Inc()
	// Best-effort delete on a fresh short context: r.Context() may already be
	// near its deadline after the failed view_key.
	delCtx, cancel := context.WithTimeout(context.Background(), mintAPITimeout)
	defer cancel()
	if h.deleteToken(delCtx, ma, accessToken, identifier) {
		slog.Warn("mint: retrieving key failed; created token deleted", "identifier", identifier)
		h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "view_key failed; token deleted")
		h.renderMintError(w, r, app, "Failed to retrieve the key; no key was created. Start again to retry.", http.StatusInternalServerError)
		return
	}
	// Delete failed — a token may be orphaned. Log the id and tell the user.
	slog.Error("mint: retrieving key failed AND cleanup delete failed; token may be orphaned", "identifier", identifier)
	h.mintLog(r, app, start, "deny", http.StatusInternalServerError, "view_key failed; cleanup failed")
	h.renderMintOrphanError(w, r, app, ma)
}

// mintAPIStatus classifies an Authentik token-create outcome.
type mintAPIStatus int

const (
	mintAPIOK          mintAPIStatus = iota // 201 Created
	mintAPICapExceeded                      // 400 with an "exceeds maximum lifetime" body
	mintAPIRejected                         // other 4xx (policy/auth)
	mintAPIUnavailable                      // 5xx, network error, or timeout
)

// tokenCreateBody is the JSON payload beyond POSTs to /core/tokens/. No `user`
// field: Authentik force-pins the token to the authenticated caller.
type tokenCreateBody struct {
	Identifier string `json:"identifier"`
	Intent     string `json:"intent"`
	Expiring   bool   `json:"expiring"`
	Expires    string `json:"expires"`
}

// createAppPassword POSTs to {api_url}/core/tokens/ with the user's access
// token as bearer, requesting an app_password token with the configured expiry.
func (h *Handler) createAppPassword(ctx context.Context, ma *MintAuthConfig, accessToken, identifier string) mintAPIStatus {
	body := tokenCreateBody{
		Identifier: identifier,
		Intent:     "app_password",
		Expiring:   true,
		Expires:    time.Now().Add(ma.TokenLifetime).UTC().Format(time.RFC3339),
	}
	payload, err := json.Marshal(body)
	if err != nil {
		slog.Error("mint: marshal token-create body", "error", err)
		return mintAPIUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mintAPIURL(ma, "/core/tokens/"), bytes.NewReader(payload))
	if err != nil {
		slog.Error("mint: build token-create request", "error", err)
		return mintAPIUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.mintClientDo(req)
	if err != nil {
		slog.Error("mint: token-create request failed", "error", err)
		return mintAPIUnavailable
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		return mintAPIOK
	case resp.StatusCode >= 500:
		slog.Error("mint: token-create 5xx", "status", resp.StatusCode)
		return mintAPIUnavailable
	case resp.StatusCode == http.StatusBadRequest:
		// Distinguish the expiry-cap rejection so the user gets a clear message.
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if strings.Contains(strings.ToLower(string(b)), "maximum lifetime") {
			return mintAPICapExceeded
		}
		slog.Error("mint: token-create 400", "body_len", len(b))
		return mintAPIRejected
	default:
		slog.Error("mint: token-create rejected", "status", resp.StatusCode)
		return mintAPIRejected
	}
}

// viewKeyResponse is the relevant subset of the view_key 200 body.
type viewKeyResponse struct {
	Key string `json:"key"`
}

// viewKey reads the token's key back via {api_url}/core/tokens/{id}/view_key/.
// Returns (key, true) on success; (\"\", false) on any failure (caller cleans up).
func (h *Handler) viewKey(ctx context.Context, ma *MintAuthConfig, accessToken, identifier string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		mintAPIURL(ma, "/core/tokens/"+url.PathEscape(identifier)+"/view_key/"), nil)
	if err != nil {
		slog.Error("mint: build view_key request", "error", err)
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.mintClientDo(req)
	if err != nil {
		slog.Error("mint: view_key request failed", "error", err)
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		slog.Error("mint: view_key non-200", "status", resp.StatusCode)
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		slog.Error("mint: read view_key body", "error", err)
		return "", false
	}
	var vr viewKeyResponse
	if err := json.Unmarshal(b, &vr); err != nil || vr.Key == "" {
		slog.Error("mint: decode view_key body", "error", err)
		return "", false
	}
	return vr.Key, true
}

// deleteToken DELETEs {api_url}/core/tokens/{id}/. Returns true if the delete
// was confirmed (2xx). Best-effort orphan cleanup.
func (h *Handler) deleteToken(ctx context.Context, ma *MintAuthConfig, accessToken, identifier string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		mintAPIURL(ma, "/core/tokens/"+url.PathEscape(identifier)+"/"), nil)
	if err != nil {
		slog.Error("mint: build delete request", "error", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.mintClientDo(req)
	if err != nil {
		slog.Error("mint: delete request failed", "error", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// mintTokenListItem is the subset of a /core/tokens/ list entry we consume.
// UserObj carries the token owner for the client-side ownership check in
// revokeOldMintTokens.
type mintTokenListItem struct {
	Identifier string `json:"identifier"`
	UserObj    struct {
		Username string `json:"username"`
	} `json:"user_obj"`
}

// mintTokenList is the paginated /core/tokens/ list response.
type mintTokenList struct {
	Results    []mintTokenListItem `json:"results"`
	Pagination struct {
		Next int `json:"next"`
	} `json:"pagination"`
}

// revokeOldMintTokens deletes the caller's OTHER app-password tokens for the
// given purpose (all except keepIdentifier, the one just minted), enforcing
// one key per user per purpose. It runs as the user (their access token).
// Ownership scoping is enforced twice, and BOTH layers are load-bearing:
//
//   - user__username filter on the list query. RBAC owner-scoping alone is
//     NOT sufficient: authentik superusers (authentik Admins members) list
//     EVERY user's tokens, and an unfiltered sweep run by an admin deleted
//     another user's same-purpose key in prod (2026-07-10, gcx cutover).
//   - a client-side user_obj.username check on each candidate, so a
//     filter-parsing regression upstream can't reopen the hole.
//
// Best-effort: every failure is logged and swallowed so a sweep problem never
// fails an otherwise-successful mint.
//
// Per-purpose matching: only tokens whose identifier is exactly
// "beyond-mint-<purpose>-<32 hex>" are eligible for revocation, leaving keys
// for other purposes and hand-made app passwords entirely untouched. The
// suffix must be checked, not just the prefix: purposes may contain hyphens,
// so "beyond-mint-gcx-" is a prefix of purpose gcx-prod's identifiers — a
// bare prefix match would let a "gcx" mint sweep the user's "gcx-prod" key.
//
// Legacy compatibility: identifiers minted before per-purpose labeling look
// like "beyond-mint-<32 hex chars>" (no purpose segment). When purpose ==
// "aigw" these legacy identifiers are also eligible, since all pre-labeling
// keys were de-facto aigw keys. The legacy pattern is anchored to exactly 32
// hex chars so it cannot misfire on purpose-format identifiers
// ("beyond-mint-<purpose>-<32 hex>"): the "-" separator is not a hex character,
// so a purpose-format identifier can never be exactly 32 hex chars after the
// prefix.
func (h *Handler) revokeOldMintTokens(ctx context.Context, ma *MintAuthConfig, accessToken, keepIdentifier, purpose string, owner *Identity) {
	purposePrefix := "beyond-mint-" + purpose + "-"

	// One page is plenty in practice (a user should have ~1 of these), but page
	// defensively so a pathological pile-up from before this fix still drains.
	// user__username: see the ownership comment above — do not remove.
	listURL := mintAPIURL(ma, "/core/tokens/?intent=app_password&page_size=100&user__username="+url.QueryEscape(owner.Email))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		slog.Error("mint: build token-list request", "error", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := h.mintClientDo(req)
	if err != nil {
		slog.Error("mint: token-list request failed", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		slog.Error("mint: token-list non-200", "status", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		slog.Error("mint: read token-list body", "error", err)
		return
	}
	var list mintTokenList
	if err := json.Unmarshal(body, &list); err != nil {
		slog.Error("mint: decode token-list body", "error", err)
		return
	}
	revoked := 0
	for _, tok := range list.Results {
		if tok.Identifier == keepIdentifier {
			continue
		}
		// Second ownership layer (see function comment): never delete a token
		// the API attributes to someone else, regardless of what the list
		// query returned. Usernames are full emails for our users.
		if tok.UserObj.Username != owner.Email {
			slog.Warn("mint: sweep skipped foreign-owned token",
				"identifier", tok.Identifier, "owner", tok.UserObj.Username, "caller", owner.Email)
			continue
		}
		suffix, samePurpose := strings.CutPrefix(tok.Identifier, purposePrefix)
		eligible := (samePurpose && mintHexSuffixRe.MatchString(suffix)) ||
			(purpose == "aigw" && mintLegacyIDRe.MatchString(tok.Identifier))
		if !eligible {
			continue
		}
		if h.deleteToken(ctx, ma, accessToken, tok.Identifier) {
			revoked++
		}
	}
	if revoked > 0 {
		slog.Info("mint: revoked superseded access keys", "count", revoked, "purpose", purpose)
	}
}

// mintClientDo issues req via the overridable mint client (tests shrink the
// timeout), falling back to the package client.
func (h *Handler) mintClientDo(req *http.Request) (*http.Response, error) {
	client := h.mintClient
	if client == nil {
		client = mintHTTPClient
	}
	return client.Do(req)
}

// mintAPIURL joins the configured api_url base with path, tolerating a trailing
// slash on the base.
func mintAPIURL(ma *MintAuthConfig, path string) string {
	return strings.TrimRight(ma.APIURL, "/") + path
}

// --- state / CSRF cookie helpers (mirror encryptOIDCState) ---

func (h *Handler) encryptMintState(state, verifier, nonce, purpose string) (string, error) {
	return h.sessions.EncryptToken(&SessionData{
		Type:         tokenTypeMintState,
		OIDCState:    state,
		OIDCVerifier: verifier,
		OIDCNonce:    nonce,
		MintPurpose:  purpose,
		ExpiresAt:    time.Now().Add(mintStateCookieTTL),
	})
}

// decryptMintState decrypts the mint-state cookie and returns the OIDC
// parameters plus the purpose label. Purpose defaults to "aigw" if the
// decrypted value is empty (stale cookie from before per-purpose labeling) or
// fails the validation pattern (belt-and-suspenders; the cookie is
// encrypted/authenticated, but we validate cheaply rather than trusting the
// content blindly). This gives mid-deploy users the old behavior rather than
// an error.
func (h *Handler) decryptMintState(cookieValue string) (state, verifier, nonce, purpose string, err error) {
	data, decErr := h.sessions.DecryptTokenWithType(cookieValue, tokenTypeMintState)
	if decErr != nil || data == nil {
		return "", "", "", "", fmt.Errorf("invalid or expired mint state")
	}
	purpose = data.MintPurpose
	if purpose == "" || !mintPurposeRe.MatchString(purpose) {
		// Defensive default: stale or tampered purpose => treat as aigw.
		purpose = "aigw"
	}
	return data.OIDCState, data.OIDCVerifier, data.OIDCNonce, purpose, nil
}

func (h *Handler) encryptMintCSRF(token string) (string, error) {
	return h.sessions.EncryptToken(&SessionData{
		Type:      tokenTypeMintCSRF,
		OIDCState: token, // reuse the generic random-string carrier
		ExpiresAt: time.Now().Add(mintCSRFCookieTTL),
	})
}

// verifyMintCSRF returns true iff cookieValue decrypts to a mint-CSRF token
// whose value matches formToken (constant-time). A non-empty formToken is
// required so an empty cookie value can never satisfy an empty form value.
func (h *Handler) verifyMintCSRF(cookieValue, formToken string) bool {
	if formToken == "" {
		return false
	}
	data, err := h.sessions.DecryptTokenWithType(cookieValue, tokenTypeMintCSRF)
	if err != nil || data == nil || data.OIDCState == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(data.OIDCState), []byte(formToken)) == 1
}

func clearMintCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// randHex returns 2n hex characters of cryptographically-random data.
func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// humanizeDuration renders a whole-day duration as "N days", else falls back to
// the stdlib string. Only used for display copy on the result page.
func humanizeDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return d.String()
}

// --- HTML rendering ---

// mintHTMLCSP is the Content-Security-Policy for mint HTML pages. It permits
// only the single nonced inline <style> and <script> the pages carry (the
// history.replaceState + copy-button logic), and locks everything else down.
//
// formActionOrigin, when non-empty, is added to form-action alongside 'self'.
// The confirmation page's form POSTs to same-origin /start-mint, but that
// returns a 302 to the Authentik authorize endpoint — and form-action governs
// the REDIRECT target of a form submission too, so without the Authentik origin
// here the browser silently blocks the cross-origin hop (the form "does
// nothing"). Pages with no form pass "" and get the strict form-action 'none'.
func mintHTMLCSP(nonce, formActionOrigin string) string {
	formAction := "form-action 'none'"
	if formActionOrigin != "" {
		formAction = "form-action 'self' " + formActionOrigin
	}
	return "default-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce +
		"'; base-uri 'none'; " + formAction
}

// writeMintHTML writes an HTML response with the mint CSP + the same security
// headers beyondResponse uses, plus Cache-Control: no-store so a rendered key
// is never cached. body is pre-rendered so a template error can't leave a
// half-written response. formActionOrigin is the extra origin allowed in
// form-action (the Authentik origin for the confirmation page; "" for the
// form-less result/notice pages).
func writeMintHTML(w http.ResponseWriter, nonce, formActionOrigin string, code int, body []byte) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", mintHTMLCSP(nonce, formActionOrigin))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// originOf returns the scheme://host origin of a URL (e.g. the Authentik
// issuer), or "" if it can't be parsed — used for the confirmation page's
// form-action allowance.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// renderMintReplay renders the non-minting "already used" page reached when a
// callback has no valid (unconsumed) state cookie. It mints nothing.
func (h *Handler) renderMintReplay(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	h.mintLog(r, app, start, "deny", http.StatusOK, "consumed or missing mint state")
	h.renderMintNotice(w,
		"Key already displayed",
		"This link has already been used, or your session expired. Your key (if one was created) was shown only once. Start again to mint a new key.",
		http.StatusOK)
}

// renderMintError renders a minimal error page with the given message + status.
func (h *Handler) renderMintError(w http.ResponseWriter, _ *http.Request, _ *Application, msg string, code int) {
	h.renderMintNotice(w, "Could not create key", msg, code)
}

// renderMintOrphanError renders the recovery page for the rare case where a
// token was created but neither its key could be read nor the token deleted.
func (h *Handler) renderMintOrphanError(w http.ResponseWriter, _ *http.Request, _ *Application, ma *MintAuthConfig) {
	revoke := authentikUserSettingsURL(ma.Issuer)
	msg := "A key may have been created but could not be retrieved, and automatic cleanup failed. " +
		"Please revoke your most recent app password in Authentik to be safe."
	nonce, err := randHex(16)
	if err != nil {
		beyondResponse(w, msg, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := mintNoticeTmpl.Execute(&buf, mintNoticeData{
		Title:     "Could not create key",
		Message:   msg,
		Nonce:     nonce,
		RevokeURL: revoke,
	}); err != nil {
		beyondResponse(w, msg, http.StatusInternalServerError)
		return
	}
	writeMintHTML(w, nonce, "", http.StatusInternalServerError, buf.Bytes())
}

// renderMintNotice renders the shared notice template (title + message + a link
// back to the confirmation page).
func (h *Handler) renderMintNotice(w http.ResponseWriter, title, msg string, code int) {
	nonce, err := randHex(16)
	if err != nil {
		beyondResponse(w, msg, code)
		return
	}
	var buf bytes.Buffer
	if err := mintNoticeTmpl.Execute(&buf, mintNoticeData{Title: title, Message: msg, Nonce: nonce}); err != nil {
		beyondResponse(w, msg, code)
		return
	}
	writeMintHTML(w, nonce, "", code, buf.Bytes())
}

// authentikUserSettingsURL derives the Authentik user-settings URL (where app
// passwords are managed) from the public issuer URL. On a parse failure it
// returns the issuer unchanged rather than an empty link.
func authentikUserSettingsURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return issuer
	}
	return u.Scheme + "://" + u.Host + "/if/user/#/settings;page-tokens"
}

type mintIndexData struct {
	CSRFToken string
	Nonce     string
	// Error is an optional inline validation error shown above the form, e.g.
	// when the supplied purpose fails validation. Empty means no error.
	Error string
	// Purpose pre-fills the form field. "aigw" unless the page was linked
	// with ?purpose=<label> (how per-consumer mint links like go/gcx-key
	// select a purpose without any client-side tooling — the CLI being
	// minted for never talks to this page).
	Purpose string
}

type mintResultData struct {
	Composite string
	Username  string
	Nonce     string
	ExpiresIn string
	// Purpose is the user-supplied purpose label, shown on the result page for
	// bookkeeping reference.
	Purpose string
}

type mintNoticeData struct {
	Title     string
	Message   string
	Nonce     string
	RevokeURL string
}

// Templates are parsed once at init. html/template applies context-aware
// escaping, so the composite (rendered into a text node) and the username are
// safe against injection. The copy script reads the secret from the DOM rather
// than from an embedded JS string, so the secret is never JS-string-escaped.
var (
	mintIndexTmpl  = template.Must(template.New("mintIndex").Parse(mintIndexHTML))
	mintResultTmpl = template.Must(template.New("mintResult").Parse(mintResultHTML))
	mintNoticeTmpl = template.Must(template.New("mintNotice").Parse(mintNoticeHTML))
)

const mintPageStyle = `body{font-family:system-ui,-apple-system,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a}
h1{font-size:1.4rem}button{font-size:1rem;padding:.6rem 1rem;border-radius:.4rem;border:1px solid #888;background:#f5f5f5;cursor:pointer}
code{background:#f0f0f0;padding:.1rem .3rem;border-radius:.25rem;font-size:.95rem}
code.cred{display:block;padding:.8rem;border-radius:.4rem;word-break:break-all;margin:1rem 0}
.muted{color:#666;font-size:.9rem}a{color:#0645ad}
input[type=text]{font-size:1rem;padding:.4rem .6rem;border-radius:.3rem;border:1px solid #888;width:12rem}
label{display:block;margin-bottom:.25rem}
.field{margin:.75rem 0}
.error{color:#b00;font-size:.9rem;margin:.5rem 0}`

const mintIndexHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Create an access key</title>
<style nonce="{{.Nonce}}">` + mintPageStyle + `</style></head>
<body>
<h1>Create an access key</h1>
<p>This creates an Authentik app password you can use as your
<code>&lt;email&gt;:&lt;key&gt;</code> credential for beyond-fronted services
that accept app passwords — for example, an AI gateway at
<code>aigw.example.com</code> or a Grafana CLI endpoint at
<code>grafana.example.com</code>. You will be asked to sign in, then the key is
shown once with a sensible expiry.</p>
<p>The purpose label names the key in Authentik for your own bookkeeping and
revocation — it does not limit which services the key works with.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="POST" action="/start-mint">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<div class="field">
<label for="purpose">What is this key for?</label>
<input type="text" id="purpose" name="purpose" value="{{.Purpose}}" placeholder="e.g. aigw, gcx">
</div>
<button type="submit">Create access key</button>
</form>
<p class="muted">Minting only happens when you click the button above.</p>
</body></html>`

const mintResultHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your access key</title>
<style nonce="{{.Nonce}}">` + mintPageStyle + `</style></head>
<body>
<h1>Your access key</h1>
<p>Copy this now — it is shown only once. Expires in {{.ExpiresIn}}.</p>
<p class="muted">Key purpose: <code>{{.Purpose}}</code></p>
<code id="composite" class="cred">{{.Composite}}</code>
<p><button type="button" id="copyBtn">Copy to clipboard</button></p>
<p class="muted">Paste the whole string as the token or API key wherever this
key is used.</p>
<script nonce="{{.Nonce}}">
history.replaceState(null, "", "/");
document.getElementById("copyBtn").addEventListener("click", function () {
  var text = document.getElementById("composite").textContent;
  navigator.clipboard.writeText(text).then(function () {
    document.getElementById("copyBtn").textContent = "Copied";
  });
});
</script>
</body></html>`

const mintNoticeHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">` + mintPageStyle + `</style></head>
<body>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
{{if .RevokeURL}}<p><a href="{{.RevokeURL}}">Manage your app passwords in Authentik</a></p>{{end}}
<p><a href="/">Start again</a></p>
</body></html>`
