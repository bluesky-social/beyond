package beyond

import (
	"net/http"
	"time"
)

// unauthenticatedPassthroughPath reports whether r targets an exact path that
// the application delegates to the upstream before Beyond authentication.
// Authorization must be absent: bearer-carrying requests always stay on the
// verified bearer_auth path, including malformed or otherwise invalid tokens.
func unauthenticatedPassthroughPath(r *http.Request, app *Application) bool {
	if app == nil || len(app.UnauthenticatedPassthroughPaths) == 0 {
		return false
	}
	if r.Header.Get("Authorization") != "" || r.URL.RawPath != "" {
		return false
	}
	for _, allowed := range app.UnauthenticatedPassthroughPaths {
		if r.URL.Path == allowed {
			return true
		}
	}
	return false
}

// handleUnauthenticatedPassthrough delegates an exact protocol bootstrap path
// to an upstream that is responsible for producing its own unauthenticated
// response (for example MCP's 401 + WWW-Authenticate or OAuth metadata).
func (h *Handler) handleUnauthenticatedPassthrough(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	h.handleUntrustedPassthrough(w, r, app, "http_unauthenticated_passthrough", start)
}
