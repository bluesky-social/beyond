package beyond

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// passthroughScheme extracts the Authorization scheme from r (the word before
// the first space) and returns it along with the full raw header value if the
// scheme matches one of app.PassthroughAuthSchemes (case-insensitive). Returns
// "", "" when the header is absent, the scheme doesn't match, or the app has
// no passthrough schemes configured.
func passthroughScheme(r *http.Request, app *Application) (scheme, rawAuth string) {
	if app == nil || len(app.PassthroughAuthSchemes) == 0 {
		return "", ""
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ""
	}
	// Scheme is the first token before any whitespace.
	idx := strings.IndexByte(auth, ' ')
	var s string
	if idx < 0 {
		s = auth
	} else {
		s = auth[:idx]
	}
	for _, allowed := range app.PassthroughAuthSchemes {
		if strings.EqualFold(s, allowed) {
			return s, auth
		}
	}
	return "", ""
}

// handlePassthrough proxies a request that carries an Authorization header
// matching one of the app's configured passthrough_auth_schemes. The edge
// does NOT authenticate; the upstream must authenticate every request itself.
//
// X-Beyond-* identity headers are stripped from the inbound request so a
// client cannot smuggle a forged identity through to the upstream. The
// Authorization header is forwarded unchanged.
func (h *Handler) handlePassthrough(w http.ResponseWriter, r *http.Request, app *Application, scheme string, start time.Time) {
	h.handleUntrustedPassthrough(w, r, app, "http_passthrough", start)
}

// handleUntrustedPassthrough forwards a request without Beyond identity. It is
// shared by credential-scheme passthrough and exact unauthenticated protocol
// bootstrap paths; both rely on the upstream to authenticate or intentionally
// serve the request.
func (h *Handler) handleUntrustedPassthrough(w http.ResponseWriter, r *http.Request, app *Application, logType string, start time.Time) {
	host := stripPort(r.Host)

	logEntry := AccessLogEntry{
		Timestamp: start,
		Method:    r.Method,
		Path:      r.URL.Path,
		Host:      host,
		SourceIP:  sourceIP(r),
		UserAgent: r.UserAgent(),
	}
	if app != nil {
		logEntry.Resource = app.Name
		logEntry.Upstream = app.Upstream
	}
	logHTTP := func(decision string, statusCode int) {
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
		// The type distinguishes delegated passthrough from bearer/session on
		// log consumers without overloading an error or identity field.
		h.accessLog.Log(logType, logEntry)
	}

	if app == nil {
		logEntry.Error = "unknown host"
		logHTTP("deny", http.StatusNotFound)
		beyondResponse(w, "not found", http.StatusNotFound)
		return
	}

	// Strip any spoofed X-Beyond-* headers the client may have supplied.
	// The upstream has no session context, so there is nothing to inject —
	// but we must not let a client forge identity claims through.
	for key := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), beyondHeaderPrefix) {
			r.Header.Del(key)
		}
	}

	proxy, err := h.proxies.Get(app.Upstream)
	if err != nil {
		logHTTP("allow", http.StatusBadGateway)
		beyondResponse(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Proxy without an Identity. The app remains in context so opt-in transport
	// behavior such as preserve_host still applies, while the Rewrite hook skips
	// X-Beyond-* injection. X-Forwarded-* and cookie scrubbing remain unconditional.
	rw := newResponseWriter(w)
	proxy.ServeHTTPPassthrough(rw, r, app)

	logHTTP(proxyDecision(rw), rw.statusCode)
}
