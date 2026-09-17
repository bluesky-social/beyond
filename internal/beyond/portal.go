package beyond

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

type portalPageData struct {
	Title          string
	User           string
	Nonce          string
	ShowAccessLogs bool
	Applications   []PortalApplication
}

func (h *Handler) handlePortal(w http.ResponseWriter, r *http.Request, portal PortalConfig, start time.Time) {
	if r.URL.Path == accessLogsPath {
		h.handleAccessLogs(w, r, portal, start)
		return
	}
	if r.URL.Path != "/" {
		beyondResponse(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		beyondResponse(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, err := h.sessions.Load(r)
	if err != nil {
		h.logPortal(r, portal, nil, start, "error", http.StatusInternalServerError, 0, "session load")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	if sess == nil {
		h.startLogin(w, r)
		return
	}

	identity, ok := h.resolveBrowserIdentity(w, sess)
	if !ok {
		h.logPortal(r, portal, &Identity{Email: sess.Email, Name: sess.Name, Groups: sess.Groups}, start,
			"deny", http.StatusForbidden, 0, "account deactivated")
		return
	}

	nonce, err := randHex(16)
	if err != nil {
		h.logPortal(r, portal, identity, start, "error", http.StatusInternalServerError, 0, "nonce generation")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	user := identity.Name
	if user == "" {
		user = identity.Email
	}
	data := portalPageData{
		Title:          portal.Title,
		User:           user,
		Nonce:          nonce,
		ShowAccessLogs: h.authorizer.IsAdmin(identity.Groups),
		Applications:   h.authorizer.AllowedApplications(identity.Groups),
	}
	var body bytes.Buffer
	if err := portalTmpl.Execute(&body, data); err != nil {
		h.logPortal(r, portal, identity, start, "error", http.StatusInternalServerError, 0, "template render")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}

	written := writePortalHTML(w, nonce, http.StatusOK, body.Bytes())
	h.logPortal(r, portal, identity, start, "allow", http.StatusOK, int64(written), "")
}

func (h *Handler) logPortal(r *http.Request, portal PortalConfig, identity *Identity, start time.Time, decision string, status int, bytesSent int64, errMsg string) {
	entry := AccessLogEntry{
		Timestamp:  start,
		Resource:   "portal",
		Method:     r.Method,
		Path:       r.URL.Path,
		Host:       portal.Host,
		SourceIP:   sourceIP(r),
		UserAgent:  r.UserAgent(),
		Decision:   decision,
		StatusCode: status,
		DurationMS: int(time.Since(start).Milliseconds()),
		BytesSent:  bytesSent,
		Error:      errMsg,
	}
	if identity != nil {
		entry.UserEmail = identity.Email
		entry.UserGroups = identity.Groups
	}
	h.accessLog.Log("http", entry)
	httpRequestDuration.WithLabelValues(metricMethod(r.Method), decision, fmt.Sprintf("%d", status), portal.Host).Observe(time.Since(start).Seconds())
}

func writePortalHTML(w http.ResponseWriter, nonce string, status int, body []byte) int {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	written, _ := w.Write(body)
	return written
}

var portalTmpl = template.Must(template.New("portal").Parse(portalHTML))

const portalHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
:root{color-scheme:light;--bg:#f6f6f4;--surface:#fff;--text:#181817;--muted:#686864;--line:#deded9;--accent:#175cd3}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
.topbar{border-bottom:1px solid var(--line);background:var(--surface)}
.topbar-inner,.main{width:min(100% - 40px,1040px);margin:0 auto}
.topbar-inner{height:64px;display:flex;align-items:center;justify-content:space-between;gap:24px}
.wordmark{font-size:13px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}
.account-wrap{display:flex;align-items:center;gap:14px}.account{color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.admin-link{height:34px;display:inline-flex;align-items:center;padding:0 13px;border-radius:6px;background:var(--accent);color:#fff;font-size:13px;font-weight:650;text-decoration:none}.admin-link:hover{background:#134cae}.admin-link:focus-visible{outline:3px solid rgba(23,92,211,.25);outline-offset:2px}
.main{padding:56px 0 72px}
h1{margin:0;font-size:30px;line-height:1.2;letter-spacing:-.025em;font-weight:650}
.intro{margin:10px 0 32px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.app{min-height:154px;display:flex;flex-direction:column;padding:22px;color:inherit;text-decoration:none;background:var(--surface);border:1px solid var(--line);border-radius:8px}
.app:hover{border-color:#b9b9b2}
.app:focus-visible{outline:3px solid rgba(23,92,211,.25);outline-offset:2px;border-color:var(--accent)}
.app h2{margin:0;font-size:17px;line-height:1.3;font-weight:650;letter-spacing:-.01em}
.description{margin:8px 0 18px;color:var(--muted);font-size:14px}
.open{margin-top:auto;color:var(--accent);font-size:13px;font-weight:600}
.empty{padding:30px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--muted)}
@media(max-width:760px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.main{padding-top:40px}}
@media(max-width:520px){.topbar-inner,.main{width:min(100% - 28px,1040px)}.grid{grid-template-columns:1fr}.account{max-width:55%}h1{font-size:26px}}
</style>
</head>
<body>
<header class="topbar"><div class="topbar-inner"><div class="wordmark">Beyond</div><div class="account-wrap">{{if .ShowAccessLogs}}<a class="admin-link" href="/admin/access-logs">Access logs</a>{{end}}<div class="account">{{.User}}</div></div></div></header>
<main class="main">
<h1>{{.Title}}</h1>
<p class="intro">Applications available to your account.</p>
{{if .Applications}}
<div class="grid">
{{range .Applications}}<a class="app" href="{{.LaunchURL}}"><h2>{{.DisplayName}}</h2>{{if .Description}}<p class="description">{{.Description}}</p>{{end}}<span class="open">Open <span aria-hidden="true">→</span></span></a>{{end}}
</div>
{{else}}
<div class="empty">No applications are available for your account.</div>
{{end}}
</main>
</body>
</html>`
