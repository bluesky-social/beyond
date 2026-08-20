package beyond

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
)

// proxyContextKey is the context key under which the per-request identity and
// application are carried into the ReverseProxy Rewrite hook. A private type
// prevents collisions with any other package's context values.
type proxyContextKey struct{}

// proxyContext bundles the per-request values the Rewrite hook needs to
// inject the correct identity and app-specific headers onto the OUTBOUND
// request.
type proxyContext struct {
	identity *Identity
	app      *Application
}

// BeyondProxy wraps httputil.ReverseProxy and injects identity headers.
type BeyondProxy struct {
	rp       *httputil.ReverseProxy
	upstream *url.URL
}

// newBeyondProxy creates a BeyondProxy that forwards requests to upstream.
func newBeyondProxy(upstream string) (*BeyondProxy, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("beyond: parse upstream URL %q: %w", upstream, err)
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = u.Host
			pc, _ := pr.In.Context().Value(proxyContextKey{}).(*proxyContext)
			if pc != nil && pc.app != nil && pc.app.PreserveHost {
				// Use the canonical configured host, not the client-supplied
				// authority (which may carry an arbitrary port). URL.Host still
				// points at the in-cluster upstream and remains the dial target.
				pr.Out.Host = pc.app.Host
			}

			// Inject identity headers onto the OUTBOUND request, not the
			// inbound one. The stdlib runs removeHopByHopHeaders on the
			// outbound request BEFORE invoking this Rewrite hook, so any
			// header a client named in its inbound `Connection:` token list
			// has already been stripped from pr.Out. Injecting here means a
			// client cannot erase the identity we vouch for via a crafted
			// `Connection: X-Beyond-User` header (see proxy_test.go).
			if pc != nil && pc.identity != nil {
				injectBeyondHeaders(pr.Out, pc.identity)
				injectApplicationHeaders(pr.Out, pc.app, pc.identity)
			}

			// Forward authoritative X-Forwarded-* context to the upstream.
			// The stdlib already deleted the client-supplied values from
			// pr.Out before this hook (anti-spoofing), and we do NOT copy
			// them from pr.In — beyond is the trust boundary, so it
			// substitutes the values it authoritatively knows.
			setForwardedHeaders(pr)

			// Don't leak beyond's own session cookie to upstreams. The
			// encrypted _beyond_session blob is not host-bound, so a
			// malicious/compromised upstream that received it could replay it
			// against other beyond-protected apps. Strip it (and the transient
			// oidc-state cookie) from the outbound request; the upstream has
			// no use for either.
			scrubBeyondCookies(pr.Out)
		},
	}

	return &BeyondProxy{rp: rp, upstream: u}, nil
}

// ServeHTTP forwards the request to the upstream via the embedded reverse
// proxy, carrying the verified identity and app through the request context
// so the Rewrite hook can inject identity headers onto the outbound request.
//
// Header injection deliberately happens in the Rewrite hook (see
// newBeyondProxy) rather than here on the inbound request: the stdlib strips
// hop-by-hop headers from the outbound request before Rewrite runs, so
// injecting there is the only placement that a client-supplied `Connection:`
// header cannot subvert. The strip+inject logic itself lives in identity.go
// (injectBeyondHeaders) so the set of identity headers beyond owns is defined
// in exactly one place. App-specific projected headers are injected after the
// strip+identity pass so they cannot be pre-seeded by a client.
func (bp *BeyondProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, identity *Identity, app *Application) {
	ctx := context.WithValue(r.Context(), proxyContextKey{}, &proxyContext{identity: identity, app: app})
	bp.rp.ServeHTTP(w, r.WithContext(ctx))
}

// ServeHTTPPassthrough forwards the request to the upstream without injecting
// any X-Beyond-* identity headers. The Rewrite hook still runs (URL rewrite,
// optional Host preservation, X-Forwarded-* substitution, cookie scrubbing),
// but the identity-injection block is skipped because the context has no
// identity.
// Callers are responsible for stripping inbound X-Beyond-* spoofs BEFORE
// calling this — see handlePassthrough.
func (bp *BeyondProxy) ServeHTTPPassthrough(w http.ResponseWriter, r *http.Request, app *Application) {
	ctx := context.WithValue(r.Context(), proxyContextKey{}, &proxyContext{app: app})
	bp.rp.ServeHTTP(w, r.WithContext(ctx))
}

// beyondCookieNames are the cookies beyond owns and must never forward to an
// upstream. They are not host-bound, so an upstream that received them could
// replay them against other beyond-protected apps.
var beyondCookieNames = map[string]bool{
	sessionCookieName:    true, // _beyond_session
	"_beyond_oidc_state": true,
}

// scrubBeyondCookies rewrites the outbound request's Cookie header to remove
// beyond's own cookies while preserving every other cookie the upstream may
// legitimately need. If no beyond cookies are present the header is left
// untouched; if removing them empties the cookie set the header is deleted.
func scrubBeyondCookies(out *http.Request) {
	cookies := out.Cookies()
	kept := cookies[:0]
	removedAny := false
	for _, c := range cookies {
		if beyondCookieNames[c.Name] {
			removedAny = true
			continue
		}
		kept = append(kept, c)
	}
	if !removedAny {
		return
	}
	out.Header.Del("Cookie")
	for _, c := range kept {
		out.AddCookie(c)
	}
}

// setForwardedHeaders overwrites the outbound request's X-Forwarded-* headers
// with the values beyond authoritatively knows, so upstreams behind beyond can
// build correct absolute URLs and set Secure cookies.
//
//   - X-Forwarded-Proto is always "https": beyond's external edge is HTTPS
//     (it either terminates TLS or sits behind a TLS-terminating LB with HSTS),
//     even though the hop to the upstream is plain http. Grafana and similar
//     apps infer cookie Secure flags and redirect schemes from this.
//   - X-Forwarded-Host is the host the client requested (pr.In.Host), not the
//     rewritten upstream host, so upstream-built URLs point at the public name.
//   - X-Forwarded-For is the client IP from RemoteAddr. We OVERWRITE rather
//     than append because the client-supplied value was already stripped and
//     beyond does not trust inbound forwarding chains (sourceIP uses
//     RemoteAddr for the same reason).
//
// These are Set (overwrite), never Add, so a client cannot smuggle a spoofed
// forwarding chain through beyond.
func setForwardedHeaders(pr *httputil.ProxyRequest) {
	pr.Out.Header.Set("X-Forwarded-Proto", "https")
	pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)

	clientIP := pr.In.RemoteAddr
	if host, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
		clientIP = host
	}
	if clientIP != "" {
		pr.Out.Header.Set("X-Forwarded-For", clientIP)
	}
}

// ProxyPool caches reverse proxy instances by upstream URL.
type ProxyPool struct {
	mu      sync.RWMutex
	proxies map[string]*BeyondProxy
}

// NewProxyPool returns an empty ProxyPool.
func NewProxyPool() *ProxyPool {
	return &ProxyPool{
		proxies: make(map[string]*BeyondProxy),
	}
}

// Reset clears the proxy cache. Call after config reload so that stale
// upstream entries are eventually evicted.
func (pp *ProxyPool) Reset() {
	pp.mu.Lock()
	pp.proxies = make(map[string]*BeyondProxy)
	pp.mu.Unlock()
}

// Get returns a cached BeyondProxy for upstream, creating one on first call.
// It uses double-checked locking: a read lock is tried first; a write lock is
// acquired only on a cache miss.
func (pp *ProxyPool) Get(upstream string) (*BeyondProxy, error) {
	pp.mu.RLock()
	bp, ok := pp.proxies[upstream]
	pp.mu.RUnlock()
	if ok {
		return bp, nil
	}

	pp.mu.Lock()
	defer pp.mu.Unlock()

	// Re-check after acquiring the write lock (double-checked locking).
	if bp, ok = pp.proxies[upstream]; ok {
		return bp, nil
	}

	bp, err := newBeyondProxy(upstream)
	if err != nil {
		return nil, err
	}
	pp.proxies[upstream] = bp
	return bp, nil
}
