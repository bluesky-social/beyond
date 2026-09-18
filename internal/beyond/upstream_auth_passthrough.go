package beyond

import (
	"net/http"
	"strings"
	"time"
)

// upstreamAuthPassthroughPath reports whether the request targets an exact
// path whose authentication boundary is delegated to the upstream. Requests
// may be credential-free (protocol bootstrap) or carry a non-empty Bearer
// credential. Other schemes and malformed Bearer headers are never eligible.
func upstreamAuthPassthroughPath(r *http.Request, app *Application) bool {
	if app == nil || len(app.UpstreamAuthPassthroughPaths) == 0 || r.URL.RawPath != "" {
		return false
	}

	auth := r.Header.Get("Authorization")
	if auth != "" {
		scheme, credential, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credential) == "" {
			return false
		}
	}

	for _, allowed := range app.UpstreamAuthPassthroughPaths {
		if r.URL.Path == allowed {
			return true
		}
	}
	return false
}

func (h *Handler) handleUpstreamAuthPassthrough(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	h.handleUntrustedPassthrough(w, r, app, "http_upstream_auth_passthrough", start)
}
