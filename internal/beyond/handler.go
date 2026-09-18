package beyond

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// oidcStateCookieTTL is the lifetime of the encrypted OIDC state cookie.
// This bounds how long a user has to complete the OIDC flow after the redirect.
const oidcStateCookieTTL = 10 * time.Minute

// oidcRateLimit is the maximum number of OIDC login redirects per source IP
// per minute. This prevents abuse of the crypto-heavy redirect path.
const oidcRateLimit = 20

// encryptOIDCState encrypts the OIDC state data into an opaque cookie value.
func (h *Handler) encryptOIDCState(state, verifier, nonce, originalURL string) (string, error) {
	data := &SessionData{
		Type:            tokenTypeOIDCState,
		OIDCState:       state,
		OIDCVerifier:    verifier,
		OIDCNonce:       nonce,
		OIDCOriginalURL: originalURL,
		ExpiresAt:       time.Now().Add(oidcStateCookieTTL),
	}
	return h.sessions.EncryptToken(data)
}

// decryptOIDCState decrypts the OIDC state cookie and returns the state,
// verifier, nonce, and original URL. Returns an error if the cookie is
// tampered, expired, or malformed.
func (h *Handler) decryptOIDCState(cookieValue string) (state, verifier, nonce, originalURL string, err error) {
	data, decErr := h.sessions.DecryptTokenWithType(cookieValue, tokenTypeOIDCState)
	if decErr != nil || data == nil {
		return "", "", "", "", fmt.Errorf("invalid or expired OIDC state")
	}
	return data.OIDCState, data.OIDCVerifier, data.OIDCNonce, data.OIDCOriginalURL, nil
}

// Handler is the main HTTP request handler chain for beyond. It loads sessions,
// checks authorisation, and proxies allowed requests to the upstream application.
type Handler struct {
	mux          *http.ServeMux
	sessions     *SessionManager
	authorizer   *Authorizer
	proxies      *ProxyPool
	accessLog    *AccessLogger
	accessLogs   AccessLogQueryStore
	logger       *slog.Logger
	oidcAuth     *OIDCAuth // nil if OIDC not configured
	mu           sync.RWMutex
	httpLifetime time.Duration
	portal       *PortalConfig

	// clientIP resolves the true client IP per request. Empty by default
	// (RemoteAddr only); operators behind a load balancer configure trusted
	// proxy CIDRs via SetTrustedProxies so X-Forwarded-For can be trusted.
	clientIP clientIPResolver

	// User validation against identity provider.
	userValidator *UserValidator // nil if not configured

	// Rate limiter for OIDC login redirects.
	oidcLimiter *ipRateLimiter

	// Bearer-token auth for apps with bearer_auth configured: per-app
	// verifiers plus a failure rate limiter (JWKS-fetch DoS guard).
	bearerVerifiers   *bearerVerifiers
	bearerFailLimiter *ipRateLimiter

	// Credential-auth (composite user:app-password) failure rate limiter.
	// Bounds brute-force on app passwords and load amplification against
	// Authentik's token endpoint — see credFailureRateLimit.
	credFailLimiter *ipRateLimiter
	// credClient is the HTTP client used for credential_auth token-endpoint
	// calls. Overridable so tests can shrink its timeout; nil falls back to
	// the package-level credHTTPClient at call time.
	credClient *http.Client

	// mintAuths holds the app-password mint flow's OIDCAuth per mint host. It
	// is separate from oidcAuth because the mint client requests the
	// goauthentik.io/api scope (see NewMintOIDCAuth) which must never touch the
	// login client. Guarded by mu (read via mintAuthFor).
	mintAuths map[string]*OIDCAuth
	// mintClient is the HTTP client used for the Authentik token API calls on
	// the mint path. Overridable so tests can shrink its timeout; nil falls
	// back to the package-level mintHTTPClient at call time.
	mintClient *http.Client
}

// NewHandler creates a Handler wired to the provided session manager and access
// logger. It builds its own Authorizer and ProxyPool from cfg.
func NewHandler(cfg *Config, sessions *SessionManager, accessLog *AccessLogger) *Handler {
	logger := slog.Default()
	if accessLog != nil && accessLog.Logger != nil {
		logger = accessLog.Logger
	}
	var accessLogs AccessLogQueryStore
	if accessLog != nil {
		accessLogs, _ = accessLog.Sink.(AccessLogQueryStore)
	}
	h := &Handler{
		sessions:          sessions,
		authorizer:        NewAuthorizer(cfg),
		proxies:           NewProxyPool(),
		accessLog:         accessLog,
		accessLogs:        accessLogs,
		logger:            logger,
		httpLifetime:      cfg.Sessions.HTTPLifetime,
		portal:            clonePortalConfig(cfg.Portal),
		oidcLimiter:       newIPRateLimiter(oidcRateLimit, time.Minute),
		bearerVerifiers:   newBearerVerifiers(),
		bearerFailLimiter: newIPRateLimiter(bearerFailureRateLimit, time.Minute),
		credFailLimiter:   newIPRateLimiter(credFailureRateLimit, time.Minute),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /oidc/callback", h.handleOIDCCallback)
	mux.HandleFunc("/", h.handleProxy)
	h.mux = mux

	return h
}

// SetAccessLogQueryStore overrides the read store. It is primarily useful for
// tests; production discovers the query capability from AccessLogger.Sink.
func (h *Handler) SetAccessLogQueryStore(store AccessLogQueryStore) {
	h.accessLogs = store
}

// SetOIDCAuth attaches an OIDCAuth for login redirects. If nil, unauthenticated
// requests receive a plain 401.
func (h *Handler) SetOIDCAuth(auth *OIDCAuth) {
	h.oidcAuth = auth
}

// Authorizer returns the handler's authorizer for use by other components.
func (h *Handler) Authorizer() *Authorizer { return h.authorizer }

// SetUserValidator attaches a UserValidator for checking user status against
// the identity provider on every request.
func (h *Handler) SetUserValidator(uv *UserValidator) {
	h.userValidator = uv
}

// SetTrustedProxies configures the CIDRs whose appended X-Forwarded-For entries
// beyond will trust when resolving the client IP. With none set (the default),
// the immediate TCP peer (RemoteAddr) is always used and X-Forwarded-For is
// ignored. Set this to your load balancer / VPC CIDRs when beyond runs behind a
// proxy that terminates the client connection (e.g. an AWS ALB).
func (h *Handler) SetTrustedProxies(prefixes []netip.Prefix) {
	h.clientIP.trusted = prefixes
}

// ReloadConfig atomically replaces the authorizer's internal maps and
// config-derived handler fields.
//
// Config is immutable after boot today (ReloadConfig is called only from
// tests), but it also resets the proxy pool and the bearer-verifier cache so
// that if in-process reload ever returns, stale upstreams or stale
// issuer/audience/JWKS verifiers can't survive a reload.
func (h *Handler) ReloadConfig(cfg *Config) {
	h.authorizer.Reload(cfg)
	h.mu.Lock()
	h.httpLifetime = cfg.Sessions.HTTPLifetime
	h.portal = clonePortalConfig(cfg.Portal)
	h.mu.Unlock()
	h.proxies.Reset()
	h.bearerVerifiers.Reset()
}

func clonePortalConfig(portal *PortalConfig) *PortalConfig {
	if portal == nil {
		return nil
	}
	cloned := *portal
	return &cloned
}

// portalForHost returns a detached portal config when host is the configured
// portal host. Keeping this under the same lock as reload avoids a race if
// runtime config reload is added later.
func (h *Handler) portalForHost(host string) (PortalConfig, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.portal == nil || !strings.EqualFold(host, h.portal.Host) {
		return PortalConfig{}, false
	}
	return *h.portal, true
}

// getHTTPLifetime returns the current HTTP session lifetime, safe for
// concurrent reads.
func (h *Handler) getHTTPLifetime() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.httpLifetime
}

// ServeHTTP dispatches requests through the built-in mux after setting
// transport-level headers that apply to every response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// HSTS on all responses (transport-level, safe for proxied responses).
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	// Resolve the true client IP once, at the edge, and carry it on the request
	// context. Every downstream consumer (access logging via sourceIP, the
	// outbound X-Forwarded-For header via setForwardedHeaders) reads this single
	// value, so the IP beyond logs always matches the IP it forwards upstream.
	r = r.WithContext(withClientIP(r.Context(), h.clientIP.clientIP(r)))

	h.mux.ServeHTTP(w, r)
}

// handleHealthz responds with a plain 200 "ok" — no auth required.
func (h *Handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	beyondResponse(w, "ok", http.StatusOK)
}

// startLogin sends an unauthenticated browser through beyond's ordinary OIDC
// login flow, or answers 401 when no login flow is configured. Shared by the
// proxy path and the mint index page so every browser-facing surface gets
// identical host gating, rate limiting, and state-cookie handling — requiring
// a session before serving anything is beyond's default, not a per-app choice.
//
// This establishes a plain beyond session and nothing more. It is safe to call
// from the mint index for exactly that reason: logging in is not minting.
func (h *Handler) startLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidcAuth == nil {
		beyondResponse(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Gate the login flow on a known host BEFORE doing any OIDC work. The
	// redirect_uri is built from r.Host (oidcRedirectURL), so without this
	// check beyond would emit an authorization request whose redirect_uri
	// points at an arbitrary attacker-chosen host — relying entirely on
	// Authentik's exact-match allowlist to prevent code interception. Refusing
	// unconfigured hosts here keeps the unauthenticated, crypto-heavy login
	// path from being driven for hosts beyond doesn't serve.
	requestHost := stripPort(r.Host)
	_, isPortal := h.portalForHost(requestHost)
	if h.authorizer.LookupApp(requestHost) == nil && !isPortal {
		beyondResponse(w, "not found", http.StatusNotFound)
		return
	}

	// Rate-limit OIDC login redirects per source IP.
	ip := sourceIP(r)
	if !h.oidcLimiter.Allow(ip) {
		beyondResponse(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Generate OIDC auth params and store in an encrypted cookie.
	state, verifier, nonce := h.oidcAuth.GenerateAuthParams()
	originalURL := r.URL.RequestURI()
	cookieVal, err := h.encryptOIDCState(state, verifier, nonce, originalURL)
	if err != nil {
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "_beyond_oidc_state",
		Value:    cookieVal,
		Path:     "/",
		MaxAge:   int(oidcStateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	h.oidcAuth.HandleLogin(w, r, state, verifier, nonce, oidcRedirectURL(r))
}

// handleProxy is the catch-all handler that loads sessions, checks
// authorisation, and proxies allowed requests to the upstream application.
func (h *Handler) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := stripPort(r.Host)

	if portal, ok := h.portalForHost(host); ok {
		h.handlePortal(w, r, portal, start)
		return
	}

	// Mint apps are fully bespoke: they render HTML and run their own scoped
	// OIDC flow rather than proxying, so they are dispatched before the session
	// load / proxy machinery below. Matched by host like every other app.
	if app := h.authorizer.LookupApp(stripPort(r.Host)); app != nil && app.MintAuth != nil {
		h.handleMint(w, r, app, start)
		return
	}

	// A configured custom credential_header is dispatched BEFORE session load,
	// unlike the legacy Authorization/x-api-key signal below. That header
	// carries a live beyond composite credential (an app password) which must
	// never leave beyond and authenticates as the header's own identity — a
	// browser session on the same host authenticates a DIFFERENT user/scope
	// and, critically, the normal session-authenticated proxy path never
	// strips this custom header. Letting a session take precedence here (the
	// way it legitimately does for a stray Authorization header below) would
	// leak the live credential to the upstream unstripped and authenticate
	// the request as the wrong identity. So this check cannot wait for
	// sess == nil the way the legacy dispatch below does.
	if app := h.authorizer.LookupApp(stripPort(r.Host)); app != nil && app.CredentialAuth != nil && hasCustomCredentialHeader(r, app.CredentialAuth) {
		h.handleCredential(w, r, app, start)
		return
	}

	// Some machine protocols must reach the upstream once without credentials
	// in order to discover how to authenticate. Match only explicitly listed,
	// canonical paths and only when Authorization is absent. This happens
	// before session loading so a stray Beyond browser cookie cannot replace
	// the upstream protocol response with injected browser identity.
	if app := h.authorizer.LookupApp(host); unauthenticatedPassthroughPath(r, app) {
		h.handleUnauthenticatedPassthrough(w, r, app, start)
		return
	}

	// A browser's CORS preflight intentionally carries no credentials. Apps
	// with split UI/API origins can opt in to delegating that probe while the
	// subsequent bearer-carrying request still goes through JWT verification.
	if app := h.authorizer.LookupApp(host); corsPreflightPassthrough(r, app) {
		h.handleCORSPreflightPassthrough(w, r, app, start)
		return
	}

	// Load session first so a valid browser session takes precedence over a
	// stray Authorization header. A browser that sends BOTH a session cookie
	// and a Bearer token (e.g. a misconfigured extension) should be served as
	// the authenticated browser it is, not forced down the bearer path and
	// locked out if the app isn't bearer-enabled (L-12).
	sess, err := h.sessions.Load(r)
	if err != nil {
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Sessionless machine-client dispatch: bearer tokens and passthrough
	// schemes are both handled without a browser redirect because machine
	// clients can't complete an OIDC flow.
	if sess == nil {
		app := h.authorizer.LookupApp(stripPort(r.Host))
		// Credential auth: composite "<user>:<app-password>" validated
		// per-request against Authentik. Dispatched BEFORE passthrough/bearer
		// because a credential_auth app can never also carry bearer_auth or
		// passthrough_auth_schemes (config validation forbids the overlap), so
		// this precedence is unambiguous. A credential_auth app with NO
		// credential header falls through to the normal path below (browser
		// hits get the OIDC redirect, health probes behave unchanged). The
		// custom credential_header case is handled above, before session
		// load — this covers only the legacy Authorization/x-api-key signal.
		if app != nil && app.CredentialAuth != nil && hasCredentialHeader(r) {
			h.handleCredential(w, r, app, start)
			return
		}
		// Passthrough: Authorization scheme matches app config — proxy
		// directly and let the upstream authenticate the request.
		if scheme, _ := passthroughScheme(r, app); scheme != "" {
			h.handlePassthrough(w, r, app, scheme, start)
			return
		}
		// Bearer: JWT verified at the edge via bearer_auth config.
		if rawToken := bearerToken(r); rawToken != "" {
			h.handleBearer(w, r, app, rawToken, start)
			return
		}
	}

	// No session — unauthenticated. Send the browser through the login flow.
	if sess == nil {
		h.startLogin(w, r)
		return
	}

	// Verify user is still active in the identity provider, and re-resolve
	// their current group membership. Re-resolving groups here (rather than
	// trusting the set frozen into the session cookie at login) means a
	// group/role change is reflected within userCacheTTL — the cookie-path
	// equivalent of the bearer path's fresh per-request JWT groups.
	//
	// groups carries the freshly-resolved set. The active gate fails closed on
	// an Authentik error. A successful resolve with an EMPTY set means the user
	// was removed from every group; we must honor that (deny), NOT fall back to
	// stale login groups, or revoking a user's only group would not take effect
	// until the session expires.
	identity, ok := h.resolveBrowserIdentity(w, sess)
	if !ok {
		return
	}
	groups := identity.Groups

	// Base log entry — common fields for every outcome of this request.
	logEntry := AccessLogEntry{
		Timestamp:  start, // request arrival time, not flush time
		UserEmail:  sess.Email,
		UserGroups: groups,
		Method:     r.Method,
		Path:       r.URL.Path,
		Host:       host,
		SourceIP:   sourceIP(r),
		UserAgent:  r.UserAgent(),
	}

	// logHTTP logs the entry with the given decision and status, records the
	// duration metric, and fills in DurationMS from start.
	logHTTP := func(decision string, statusCode int) {
		// Host label bounded to config (or "unknown"), same containment as
		// the bearer path: the raw Host header is client-controlled and
		// would mint unbounded time series. The access-log entry keeps it.
		metricHost := "unknown"
		if a := h.authorizer.LookupApp(host); a != nil {
			metricHost = a.Host
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
		h.accessLog.Log("http", logEntry)
	}

	// Check authorisation against the freshly-resolved groups.
	allowed, app := h.authorizer.CheckHTTP(host, groups)
	if app == nil {
		// Unknown host.
		logEntry.Resource = host
		logEntry.Error = "unknown host"
		logHTTP("deny", http.StatusNotFound)
		beyondResponse(w, "not found", http.StatusNotFound)
		return
	}

	logEntry.Resource = app.Name
	logEntry.Upstream = app.Upstream

	// Not allowed.
	if !allowed {
		logEntry.Error = "forbidden"
		logHTTP("deny", http.StatusForbidden)
		beyondResponse(w, "forbidden", http.StatusForbidden)
		return
	}

	// Proxy the request.
	proxy, err := h.proxies.Get(app.Upstream)
	if err != nil {
		logHTTP("allow", http.StatusBadGateway)
		beyondResponse(w, "bad gateway", http.StatusBadGateway)
		return
	}

	rw := newResponseWriter(w)
	proxy.ServeHTTP(rw, r, identity, app)

	logEntry.BytesSent = rw.bytesWritten.Load()
	logHTTP(proxyDecision(rw), rw.statusCode)
}

// resolveBrowserIdentity applies the post-session identity-provider check used
// by every authenticated browser surface. A successful empty group set is
// authoritative; an inactive result or IdP transport failure is denied by the
// active gate. false means a response was already written.
func (h *Handler) resolveBrowserIdentity(w http.ResponseWriter, sess *SessionData) (*Identity, bool) {
	groups := sess.Groups
	if h.userValidator != nil {
		active, fresh, ok := h.userValidator.Resolve(sess.Email)
		if !active {
			h.sessions.Clear(w)
			beyondResponse(w, "account deactivated", http.StatusForbidden)
			return nil, false
		}
		if ok {
			// Fresh groups come straight from the Authentik API and never
			// passed through login-time validation, so sanitize them to the
			// same caps before authorization or header framing. May be empty.
			groups = sanitizeGroups(fresh)
		}
	}
	return &Identity{Email: sess.Email, Name: sess.Name, Groups: groups}, true
}

// proxyDecision returns the access-log decision for a completed proxy request:
// "upgrade" for a hijacked protocol switch (WebSocket/h2c), otherwise "allow".
// This keeps successful tunnels distinguishable in the audit trail from
// ordinary request/response exchanges.
func proxyDecision(rw *responseWriter) string {
	if rw.hijacked {
		return "upgrade"
	}
	return "allow"
}

// handleOIDCCallback handles the OIDC provider's redirect back to beyond after
// the user authenticates.
func (h *Handler) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Defensive nil guard: the /oidc/callback route is registered
	// unconditionally, but reaching the HandleCallback deref below requires a
	// validly-encrypted oidc-state cookie, which is only ever minted on the
	// login path (guarded by oidcAuth != nil). Without OIDC configured no
	// attacker can forge one, so this is not remotely reachable — but a one-line
	// guard beats a deref panic if the invariant ever changes.
	if h.oidcAuth == nil {
		oidcCallbackDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		beyondResponse(w, "oidc not configured", http.StatusNotFound)
		return
	}

	cookie, err := r.Cookie("_beyond_oidc_state")
	if err != nil {
		oidcCallbackDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		beyondResponse(w, "missing state cookie", http.StatusBadRequest)
		return
	}

	state, verifier, nonce, originalURL, err := h.decryptOIDCState(cookie.Value)
	if err != nil {
		oidcCallbackDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		beyondResponse(w, "invalid state cookie", http.StatusBadRequest)
		return
	}

	redirectURL := oidcRedirectURL(r)
	identity, err := h.oidcAuth.HandleCallback(r.Context(), w, r, state, verifier, nonce, redirectURL)
	if err != nil {
		oidcCallbackDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		h.logger.Error("OIDC callback failed", "error", err)
		beyondResponse(w, "authentication failed", http.StatusForbidden)
		return
	}

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "_beyond_oidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Validate originalURL is a same-origin relative path to prevent open
	// redirects. A bare HasPrefix("/") check is not enough: "//evil.com" and
	// "/\evil.com" both start with "/" yet are protocol-relative redirects to
	// another host. Parse and require an empty host with a "/"-rooted,
	// non-backslash path.
	originalURL = sanitizeRedirectPath(originalURL)

	// Create a session.
	sessData := &SessionData{
		Email:     identity.Email,
		Name:      identity.Name,
		Groups:    identity.Groups,
		ExpiresAt: time.Now().Add(h.getHTTPLifetime()),
	}
	if err := h.sessions.Save(w, sessData); err != nil {
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}

	oidcCallbackDuration.WithLabelValues("success").Observe(time.Since(start).Seconds())
	http.Redirect(w, r, originalURL, http.StatusFound)
}

// beyondResponse writes an HTTP response with security headers for responses
// generated by beyond itself (error pages, health checks). Proxied upstream
// responses are NOT wrapped by this — upstream apps control their own headers.
func beyondResponse(w http.ResponseWriter, body string, code int) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// proxyWriteIdleTimeout is the per-response idle write deadline armed on the
// proxy path. It replaces the server-wide WriteTimeout (which severs streams
// at an absolute deadline). Each successful Write/Flush re-arms it, so an
// actively streaming response (SSE, chunked, long-poll) survives indefinitely
// while a stalled write — a client that stopped reading, leaving us blocked on
// TCP backpressure — is reclaimed after this idle window. It is generous
// because legitimate SSE keep-alives can be sparse.
const proxyWriteIdleTimeout = 5 * time.Minute

// responseWriter wraps http.ResponseWriter to capture the status code and bytes
// written for access logging, and to enforce an idle (not absolute) write
// deadline so streaming responses survive while stalled ones are reclaimed.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	// bytesWritten is atomic because a hijacked upgrade's client-bound copy
	// goroutine (via countingConn) may still be writing when the handler reads
	// the total: httputil's handleUpgradeResponse returns as soon as the FIRST
	// copy direction finishes (it only awaits the second if the first returned
	// nil), so the surviving copier can race the post-ServeHTTP read.
	bytesWritten atomic.Int64
	wroteHeader  bool

	// idleTimeout is the per-write idle window. Zero means "use the package
	// default" so the zero-value struct (constructed directly in tests)
	// behaves sanely; newResponseWriter sets it explicitly.
	idleTimeout time.Duration
	// rc drives the idle write deadline; nil when the underlying writer does
	// not support deadlines (e.g. httptest.ResponseRecorder in unit tests).
	rc *http.ResponseController
	// lastDeadline is the currently-armed write deadline. We only re-arm when
	// it has advanced past a throttle threshold, so a high-frequency stream
	// doesn't make a syscall per byte.
	lastDeadline time.Time
	// hijacked is set once the connection is taken over (WebSocket/h2c). After
	// that beyond no longer owns the deadline or the response writes, so byte
	// accounting and the idle deadline both stop applying.
	hijacked bool
}

// newResponseWriter wraps w for the proxy path and arms the initial idle write
// deadline. If w's underlying connection doesn't support write deadlines the
// deadline machinery is a no-op (SetWriteDeadline returns
// http.ErrNotSupported), which is the case under httptest.ResponseRecorder.
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return newResponseWriterWithIdle(w, proxyWriteIdleTimeout)
}

// newResponseWriterWithIdle is newResponseWriter with an explicit idle window,
// so tests can use a short timeout without waiting minutes.
func newResponseWriterWithIdle(w http.ResponseWriter, idle time.Duration) *responseWriter {
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK, idleTimeout: idle}
	rw.rc = http.NewResponseController(w)
	rw.armWriteDeadline()
	return rw
}

// armWriteDeadline extends the idle write deadline to now+idleTimeout,
// throttled so we only issue a syscall when the deadline would advance by more
// than ~10% of the window. A no-op once hijacked or when deadlines are
// unsupported.
func (rw *responseWriter) armWriteDeadline() {
	if rw.rc == nil || rw.hijacked {
		return
	}
	idle := rw.idleTimeout
	if idle <= 0 {
		idle = proxyWriteIdleTimeout
	}
	now := time.Now()
	if !rw.lastDeadline.IsZero() && now.Add(idle).Sub(rw.lastDeadline) < idle/10 {
		return // close enough; avoid a syscall on every write
	}
	deadline := now.Add(idle)
	// ErrNotSupported (e.g. httptest) is expected and ignored: the test
	// transport has no real connection to bound.
	if err := rw.rc.SetWriteDeadline(deadline); err == nil {
		rw.lastDeadline = deadline
	}
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
	}
	rw.armWriteDeadline()
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten.Add(int64(n))
	return n, err
}

// Flush implements http.Flusher so that Server-Sent Events and other
// streaming responses work correctly through the proxy. Each flush re-arms the
// idle write deadline so a steadily-flushing stream is never cut.
func (rw *responseWriter) Flush() {
	rw.armWriteDeadline()
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so that WebSocket upgrades (and other
// connection takeovers) work correctly through the proxy. Hijacking clears the
// idle write deadline: after takeover the connection is bidirectional and
// long-lived (the stdlib also drops its own deadlines on hijack), so beyond
// must not impose a write deadline that would sever the tunnel.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return conn, brw, err
	}
	rw.hijacked = true
	// Record the real outcome of a successful upgrade. The stdlib writes the
	// 101 and all subsequent bytes directly to the raw net.Conn, bypassing
	// WriteHeader/Write, so without this the access log would record the
	// init value (200) and 0 bytes for every WebSocket/h2c tunnel — an
	// exfiltration channel indistinguishable from an idle health check.
	rw.statusCode = http.StatusSwitchingProtocols
	if rw.rc != nil {
		// After takeover the connection is bidirectional and long-lived (the
		// stdlib drops its own deadlines on hijack), so clear the idle write
		// deadline that would otherwise sever the tunnel. Best-effort; ignore
		// ErrNotSupported.
		_ = rw.rc.SetWriteDeadline(time.Time{})
	}
	// Wrap the connection so bytes streamed to the client over the tunnel are
	// counted into bytesWritten for the access log. handleBearer/handleProxy
	// read the total after ServeHTTP returns, but httputil's
	// handleUpgradeResponse can return while the surviving client-bound copy
	// goroutine is still writing, so the counter is atomic to make that
	// read/write race-free (the byte total may be slightly low if read mid-
	// flush, but it's never corrupt and never races).
	cc := &countingConn{Conn: conn, written: &rw.bytesWritten}
	return cc, brw, nil
}

// countingConn wraps a hijacked net.Conn to accumulate bytes written to the
// client into a shared atomic counter for access logging. Reads are not
// counted (bytesWritten is response bytes only).
type countingConn struct {
	net.Conn
	written *atomic.Int64
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written.Add(int64(n))
	return n, err
}

// Unwrap returns the underlying ResponseWriter, enabling
// http.ResponseController to access optional interfaces.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// stripPort removes the :port suffix from host, if present.
func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port present or other parse error — return as-is.
		return host
	}
	return h
}

// sanitizeRedirectPath returns rawURL if it is a safe same-origin relative
// path, or "/" otherwise. It defends the post-login redirect against open
// redirects: a bare strings.HasPrefix(rawURL, "/") check accepts the
// protocol-relative forms "//evil.com" and "/\evil.com", which browsers treat
// as absolute redirects to another host. We require a parseable URL with no
// scheme and no host, whose path is "/"-rooted and does not start with a
// backslash (some browsers normalize "\" to "/").
func sanitizeRedirectPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "/\\") {
		return "/"
	}
	// Reject the "//" and "/\" protocol-relative forms that url.Parse may keep
	// in the raw path before host resolution.
	if strings.HasPrefix(rawURL, "//") || strings.HasPrefix(rawURL, "/\\") {
		return "/"
	}
	return rawURL
}

// oidcRedirectURL derives the OIDC redirect URL from the request's Host
// header. Each application subdomain gets its own callback endpoint, which
// keeps the OIDC state cookie and session cookie on the same host and avoids
// cross-host cookie scoping problems.
//
// The scheme is always "https" because beyond either terminates TLS itself or
// sits behind a TLS-terminating load balancer with HSTS enforced.
//
// Because r.Host is client-controlled, callers MUST only reach this for a host
// beyond actually serves: handleProxy gates the unauthenticated login path on
// authorizer.LookupApp(host) != nil (M-8) so the redirect_uri can't be pointed
// at an arbitrary host. Even so, the IdP's exact-match redirect_uri allowlist
// remains the load-bearing control against authorization-code interception —
// it must be configured exact-match (Authentik's default), never wildcard.
func oidcRedirectURL(r *http.Request) string {
	return "https://" + r.Host + "/oidc/callback"
}

// sourceIP returns the client IP for the request. It reads the value resolved
// once at the edge by Handler.ServeHTTP (see clientIPResolver), which honours
// the configured trusted-proxy CIDRs. When that value is absent — e.g. a unit
// test calling this directly, or any path that did not pass through ServeHTTP —
// it falls back to RemoteAddr, which is also the resolved value when no trusted
// proxies are configured (X-Forwarded-For untrusted by default).
func sourceIP(r *http.Request) string {
	if ip, ok := clientIPFromContext(r.Context()); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
