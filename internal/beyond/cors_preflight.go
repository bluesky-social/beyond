package beyond

import (
	"net/http"
	"time"
)

// corsPreflightPassthrough reports whether r is a credential-free CORS
// preflight for an application that explicitly delegates those probes. The
// upstream remains authoritative for the allowed origin, method, and headers.
func corsPreflightPassthrough(r *http.Request, app *Application) bool {
	if app == nil || !app.CORSPreflightPassthrough {
		return false
	}
	if r.Method != http.MethodOptions || r.Header.Get("Authorization") != "" {
		return false
	}
	return r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != ""
}

func (h *Handler) handleCORSPreflightPassthrough(w http.ResponseWriter, r *http.Request, app *Application, start time.Time) {
	h.handleUntrustedPassthrough(w, r, app, "http_cors_preflight_passthrough", start)
}
