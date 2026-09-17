package beyond

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	accessLogsPath          = "/admin/access-logs"
	accessLogQueryTimeout   = 5 * time.Second
	accessLogMaxQueryWindow = 31 * 24 * time.Hour
	accessLogDefaultLimit   = 100
	accessLogMaxLimit       = 500
)

// AccessLogQuery is the bounded, parameterized read contract for audit data.
// From and To are always present, To is exclusive, and Limit is at most 500.
type AccessLogQuery struct {
	From       time.Time
	To         time.Time
	UserEmail  string
	Resource   string
	Group      string
	SourceIP   string
	Decision   string
	Method     string
	Host       string
	Path       string
	Type       string
	StatusCode *int
	Limit      int
}

type AccessLogQueryStore interface {
	QueryAccessLogs(context.Context, AccessLogQuery) ([]AccessLogRecord, error)
}

type accessLogsPageData struct {
	Title          string
	User           string
	Nonce          string
	From           string
	To             string
	Query          AccessLogQuery
	StatusCode     string
	Applications   []string
	Records        []AccessLogRecord
	Error          string
	ResultLimitHit bool
}

func (h *Handler) handleAccessLogs(w http.ResponseWriter, r *http.Request, portal PortalConfig, start time.Time) {
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
	if !h.authorizer.IsAdmin(identity.Groups) {
		h.logPortal(r, portal, identity, start, "deny", http.StatusForbidden, 0, "admin required")
		beyondResponse(w, "forbidden", http.StatusForbidden)
		return
	}

	nonce, err := randHex(16)
	if err != nil {
		h.logPortal(r, portal, identity, start, "error", http.StatusInternalServerError, 0, "nonce generation")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	query, queryErr := parseAccessLogQuery(r.URL.Query(), time.Now().UTC())
	data := newAccessLogsPageData(portal, identity, nonce, query, h.authorizer.ApplicationNames())
	status := http.StatusOK
	decision := "allow"
	errMessage := ""

	switch {
	case queryErr != nil:
		status = http.StatusBadRequest
		decision = "deny"
		errMessage = "invalid query"
		data.Error = strings.ToUpper(queryErr.Error()[:1]) + queryErr.Error()[1:]
	case h.accessLogs == nil:
		status = http.StatusServiceUnavailable
		decision = "error"
		errMessage = "query store unavailable"
		data.Error = "Access logs are temporarily unavailable."
	default:
		ctx, cancel := context.WithTimeout(r.Context(), accessLogQueryTimeout)
		records, err := h.accessLogs.QueryAccessLogs(ctx, query)
		cancel()
		if err != nil {
			h.logger.Error("access-log query failed", "error", err)
			status = http.StatusServiceUnavailable
			decision = "error"
			errMessage = "query failed"
			data.Error = "Access logs are temporarily unavailable."
		} else {
			data.Records = records
			data.ResultLimitHit = len(records) == query.Limit
		}
	}

	var body bytes.Buffer
	if err := accessLogsTmpl.Execute(&body, data); err != nil {
		h.logPortal(r, portal, identity, start, "error", http.StatusInternalServerError, 0, "template render")
		beyondResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	written := writeAccessLogsHTML(w, nonce, status, body.Bytes())
	h.logPortal(r, portal, identity, start, decision, status, int64(written), errMessage)
}

func writeAccessLogsHTML(w http.ResponseWriter, nonce string, status int, body []byte) int {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	written, _ := w.Write(body)
	return written
}

func newAccessLogsPageData(portal PortalConfig, identity *Identity, nonce string, query AccessLogQuery, apps []string) accessLogsPageData {
	user := identity.Name
	if user == "" {
		user = identity.Email
	}
	status := ""
	if query.StatusCode != nil {
		status = strconv.Itoa(*query.StatusCode)
	}
	return accessLogsPageData{
		Title: portal.Title, User: user, Nonce: nonce,
		From:  query.From.UTC().Format("2006-01-02T15:04:05"),
		To:    query.To.UTC().Format("2006-01-02T15:04:05"),
		Query: query, StatusCode: status, Applications: apps,
	}
}

func parseAccessLogQuery(values url.Values, now time.Time) (AccessLogQuery, error) {
	now = now.UTC()
	query := AccessLogQuery{
		From:  now.Add(-time.Hour),
		To:    now,
		Limit: accessLogDefaultLimit,
	}
	var err error
	if raw := strings.TrimSpace(values.Get("from")); raw != "" {
		var parsed time.Time
		parsed, err = parseAccessLogTime(raw)
		if err != nil {
			return query, fmt.Errorf("from must be a valid UTC date and time")
		}
		query.From = parsed
	}
	if raw := strings.TrimSpace(values.Get("to")); raw != "" {
		var parsed time.Time
		parsed, err = parseAccessLogTime(raw)
		if err != nil {
			return query, fmt.Errorf("to must be a valid UTC date and time")
		}
		query.To = parsed
	}
	if !query.From.Before(query.To) {
		return query, fmt.Errorf("from must be earlier than to")
	}
	if query.To.Sub(query.From) > accessLogMaxQueryWindow {
		return query, fmt.Errorf("time range cannot exceed 31 days")
	}
	if query.From.Before(now.AddDate(0, 0, -accessLogRetentionDays)) {
		return query, fmt.Errorf("from is outside the 90-day retention window")
	}
	if query.To.After(now.Add(5 * time.Minute)) {
		return query, fmt.Errorf("to cannot be in the future")
	}

	fields := []struct {
		name string
		dest *string
		max  int
	}{
		{"user", &query.UserEmail, 254},
		{"application", &query.Resource, 128},
		{"group", &query.Group, 256},
		{"source_ip", &query.SourceIP, 64},
		{"decision", &query.Decision, 16},
		{"method", &query.Method, 16},
		{"host", &query.Host, 253},
		{"path", &query.Path, 1024},
		{"type", &query.Type, 64},
	}
	for _, field := range fields {
		value := strings.TrimSpace(values.Get(field.name))
		if len(value) > field.max || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return query, fmt.Errorf("%s filter is invalid", field.name)
		}
		*field.dest = value
	}
	query.Method = strings.ToUpper(query.Method)
	if query.SourceIP != "" && net.ParseIP(query.SourceIP) == nil {
		return query, fmt.Errorf("source IP must be a valid IP address")
	}
	if query.Decision != "" && query.Decision != "allow" && query.Decision != "deny" && query.Decision != "error" {
		return query, fmt.Errorf("decision filter is invalid")
	}
	if raw := strings.TrimSpace(values.Get("status")); raw != "" {
		status, err := strconv.Atoi(raw)
		if err != nil || status < 0 || status > 999 {
			return query, fmt.Errorf("status must be between 0 and 999")
		}
		query.StatusCode = &status
	}
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || (limit != 50 && limit != 100 && limit != 250 && limit != accessLogMaxLimit) {
			return query, fmt.Errorf("result limit is invalid")
		}
		query.Limit = limit
	}
	return query, nil
}

func parseAccessLogTime(value string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", time.RFC3339} {
		if parsed, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time")
}

var accessLogsTmpl = template.Must(template.New("accessLogs").Funcs(template.FuncMap{
	"formatTimestamp": func(value time.Time) string { return value.UTC().Format("2006-01-02 15:04:05.000") },
	"joinGroups":      func(groups []string) string { return strings.Join(groups, ", ") },
	"formatDuration": func(ms int) string {
		if ms >= 1000 {
			return fmt.Sprintf("%.2f s", float64(ms)/1000)
		}
		return fmt.Sprintf("%d ms", ms)
	},
	"formatBytes": func(value int64) string {
		switch {
		case value >= 1<<20:
			return fmt.Sprintf("%.1f MiB", float64(value)/(1<<20))
		case value >= 1<<10:
			return fmt.Sprintf("%.1f KiB", float64(value)/(1<<10))
		default:
			return fmt.Sprintf("%d B", value)
		}
	},
}).Parse(accessLogsHTML))

const accessLogsHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access logs · {{.Title}}</title>
<style nonce="{{.Nonce}}">
:root{color-scheme:light;--bg:#f6f6f4;--surface:#fff;--text:#181817;--muted:#686864;--line:#deded9;--accent:#175cd3;--good:#067647;--bad:#b42318;--warn:#b54708}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
.topbar{border-bottom:1px solid var(--line);background:var(--surface)}.topbar-inner,.main{width:min(100% - 40px,1440px);margin:0 auto}.topbar-inner{height:64px;display:flex;align-items:center;justify-content:space-between;gap:24px}.wordmark{font-size:13px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}.account{color:var(--muted);font-size:13px}.back{color:var(--accent);font-weight:650;text-decoration:none}.back:hover{text-decoration:underline}.main{padding:38px 0 72px}
.heading{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin-bottom:24px}h1{margin:0;font-size:28px;line-height:1.2;letter-spacing:-.025em}.intro{margin:7px 0 0;color:var(--muted)}
.filters{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px;padding:20px;background:var(--surface);border:1px solid var(--line);border-radius:8px;margin-bottom:20px}.field{display:flex;flex-direction:column;gap:5px}.span2{grid-column:span 2}label{font-size:12px;font-weight:650;color:#484844}input,select{width:100%;height:38px;border:1px solid #c9c9c2;border-radius:6px;background:#fff;color:var(--text);font:inherit;padding:7px 9px}input:focus,select:focus{outline:3px solid rgba(23,92,211,.18);border-color:var(--accent)}.hint{color:var(--muted);font-size:11px}.actions{display:flex;align-items:flex-end;gap:8px}.button{height:38px;border:0;border-radius:6px;padding:0 16px;background:var(--accent);color:#fff;font-weight:650;cursor:pointer}.clear{height:38px;display:inline-flex;align-items:center;padding:0 8px;color:var(--muted);text-decoration:none}.clear:hover{color:var(--text)}
.notice{padding:12px 15px;border-radius:6px;margin-bottom:16px}.error{background:#fef3f2;color:var(--bad);border:1px solid #fecdca}.limit{background:#fffaeb;color:#93370d;border:1px solid #fedf89}.summary{display:flex;justify-content:space-between;align-items:center;margin:0 0 10px;color:var(--muted);font-size:12px}
.table-wrap{overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:8px}table{width:100%;border-collapse:collapse;white-space:nowrap}th{text-align:left;padding:10px 12px;background:#fafaf9;border-bottom:1px solid var(--line);color:#52524e;font-size:11px;letter-spacing:.04em;text-transform:uppercase;position:sticky;top:0}td{padding:11px 12px;border-bottom:1px solid #ecece8;vertical-align:top}tr:last-child td{border-bottom:0}.timestamp{font-variant-numeric:tabular-nums;color:#484844}.decision{font-weight:700}.decision.allow{color:var(--good)}.decision.deny{color:var(--bad)}.decision.error{color:var(--warn)}.request{white-space:normal;min-width:280px;max-width:520px;overflow-wrap:anywhere}.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.secondary{display:block;color:var(--muted);font-size:12px;margin-top:2px}.groups{white-space:normal;max-width:260px}.empty{padding:42px;text-align:center;color:var(--muted)}
@media(max-width:1100px){.filters{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:650px){.topbar-inner,.main{width:min(100% - 24px,1440px)}.main{padding-top:28px}.heading{align-items:flex-start;flex-direction:column}.filters{grid-template-columns:1fr}.span2{grid-column:span 1}}
</style>
</head>
<body>
<header class="topbar"><div class="topbar-inner"><div class="wordmark">Beyond</div><div><a class="back" href="/">Applications</a> <span class="account">· {{.User}}</span></div></div></header>
<main class="main">
<div class="heading"><div><h1>Access logs</h1><p class="intro">Audit proxy activity across applications. Times are UTC.</p></div></div>
<form class="filters" method="get" action="/admin/access-logs">
<div class="field span2"><label for="from">From (UTC)</label><input id="from" name="from" type="datetime-local" step="1" required value="{{.From}}"></div>
<div class="field span2"><label for="to">To (UTC)</label><input id="to" name="to" type="datetime-local" step="1" required value="{{.To}}"></div>
<div class="field"><label for="limit">Results</label><select id="limit" name="limit"><option value="50" {{if eq .Query.Limit 50}}selected{{end}}>50</option><option value="100" {{if eq .Query.Limit 100}}selected{{end}}>100</option><option value="250" {{if eq .Query.Limit 250}}selected{{end}}>250</option><option value="500" {{if eq .Query.Limit 500}}selected{{end}}>500</option></select></div>
<div class="field"><label for="decision">Decision</label><select id="decision" name="decision"><option value="">Any</option><option value="allow" {{if eq .Query.Decision "allow"}}selected{{end}}>Allow</option><option value="deny" {{if eq .Query.Decision "deny"}}selected{{end}}>Deny</option><option value="error" {{if eq .Query.Decision "error"}}selected{{end}}>Error</option></select></div>
<div class="field span2"><label for="user">User email (exact)</label><input id="user" name="user" type="search" maxlength="254" value="{{.Query.UserEmail}}" placeholder="alice@example.com"></div>
<div class="field"><label for="application">Application</label><input id="application" name="application" list="applications" maxlength="128" value="{{.Query.Resource}}" placeholder="Any"><datalist id="applications"><option value="portal"></option>{{range .Applications}}<option value="{{.}}"></option>{{end}}</datalist></div>
<div class="field"><label for="group">Group (exact)</label><input id="group" name="group" maxlength="256" value="{{.Query.Group}}" placeholder="engineering"></div>
<div class="field"><label for="source_ip">Source IP</label><input id="source_ip" name="source_ip" maxlength="64" value="{{.Query.SourceIP}}" placeholder="192.0.2.10"></div>
<div class="field"><label for="method">Method</label><input id="method" name="method" maxlength="16" value="{{.Query.Method}}" placeholder="GET"></div>
<div class="field span2"><label for="path">Path contains</label><input id="path" name="path" type="search" maxlength="1024" value="{{.Query.Path}}" placeholder="/api/"></div>
<div class="field"><label for="status">Status code</label><input id="status" name="status" inputmode="numeric" pattern="[0-9]{1,3}" value="{{.StatusCode}}" placeholder="Any"></div>
<div class="field"><label for="host">Host</label><input id="host" name="host" maxlength="253" value="{{.Query.Host}}" placeholder="app.example.com"></div>
<div class="field"><label for="type">Event type</label><input id="type" name="type" maxlength="64" value="{{.Query.Type}}" placeholder="http"></div>
<div class="actions"><button class="button" type="submit">Run query</button><a class="clear" href="/admin/access-logs">Clear</a></div>
</form>
{{if .Error}}<div class="notice error" role="alert">{{.Error}}</div>{{end}}
{{if .ResultLimitHit}}<div class="notice limit">Showing the newest {{.Query.Limit}} matching events. Narrow the filters or time range to see more.</div>{{end}}
<div class="summary"><span>{{len .Records}} events</span><span>Maximum window: 31 days · Retention: 90 days</span></div>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>Decision</th><th>User</th><th>Application</th><th>Request</th><th>Source</th><th>Performance</th><th>Type</th></tr></thead><tbody>
{{range .Records}}<tr><td class="timestamp">{{formatTimestamp .Entry.Timestamp}}</td><td><span class="decision {{.Entry.Decision}}">{{.Entry.Decision}}</span><span class="secondary">HTTP {{.Entry.StatusCode}}</span></td><td>{{if .Entry.UserEmail}}{{.Entry.UserEmail}}{{else}}—{{end}}{{if .Entry.UserGroups}}<span class="secondary groups">{{joinGroups .Entry.UserGroups}}</span>{{end}}</td><td>{{.Entry.Resource}}<span class="secondary">{{.Entry.Host}}</span></td><td class="request"><strong>{{.Entry.Method}}</strong> <span class="path">{{.Entry.Path}}</span>{{if .Entry.Error}}<span class="secondary">{{.Entry.Error}}</span>{{end}}</td><td>{{.Entry.SourceIP}}<span class="secondary">{{.Entry.UserAgent}}</span></td><td>{{formatDuration .Entry.DurationMS}}<span class="secondary">{{formatBytes .Entry.BytesSent}}</span></td><td>{{.Type}}</td></tr>{{else}}<tr><td class="empty" colspan="8">No events match this query.</td></tr>{{end}}
</tbody></table></div>
</main></body></html>`
