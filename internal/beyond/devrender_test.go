package beyond

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDevRenderPages is a throwaway helper (gated on BEYOND_RENDER_DIR): it
// renders the HTML page states with sample data so they can be viewed in a
// browser. Not a real test — skipped unless the env var is set.
func TestDevRenderPages(t *testing.T) {
	dir := os.Getenv("BEYOND_RENDER_DIR")
	if dir == "" {
		t.Skip("set BEYOND_RENDER_DIR to render development pages")
	}
	write := func(name string, tmplExec func(*bytes.Buffer) error) {
		var buf bytes.Buffer
		if err := tmplExec(&buf); err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("1-confirm.html", func(b *bytes.Buffer) error {
		return mintIndexTmpl.Execute(b, mintIndexData{CSRFToken: "sample-csrf-token", Nonce: "n1"})
	})
	write("2-result.html", func(b *bytes.Buffer) error {
		return mintResultTmpl.Execute(b, mintResultData{
			Composite: "test@beyond.local:aXmpleKeYvALue1234567890abcdefGHIJKLMNOPqrst",
			Username:  "test@beyond.local",
			Nonce:     "n2",
			ExpiresIn: "365 days",
		})
	})
	write("3-replay.html", func(b *bytes.Buffer) error {
		return mintNoticeTmpl.Execute(b, mintNoticeData{
			Title:   "Key already displayed",
			Message: "This link has already been used, or your session expired. Your key (if one was created) was shown only once. Start again to mint a new key.",
			Nonce:   "n3",
		})
	})
	write("4-orphan.html", func(b *bytes.Buffer) error {
		return mintNoticeTmpl.Execute(b, mintNoticeData{
			Title:     "Could not create key",
			Message:   "A key may have been created but could not be retrieved, and automatic cleanup failed. Please revoke your most recent app password in Authentik to be safe.",
			Nonce:     "n4",
			RevokeURL: "http://localhost:9000/if/user/#/settings;page-tokens",
		})
	})
	write("5-portal.html", func(b *bytes.Buffer) error {
		return portalTmpl.Execute(b, portalPageData{
			Title:          "Applications",
			User:           "test@beyond.local",
			Nonce:          "n5",
			ShowAccessLogs: true,
			Applications: []PortalApplication{
				{Name: "grafana", DisplayName: "Grafana", Description: "Metrics and dashboards", LaunchURL: "https://grafana.example.com/"},
				{Name: "argocd", DisplayName: "Argo CD", Description: "Deployments and application health", LaunchURL: "https://argocd.example.com/"},
				{Name: "netbox", DisplayName: "NetBox", Description: "Network and datacenter inventory", LaunchURL: "https://netbox.example.com/"},
			},
		})
	})
	write("6-access-logs.html", func(b *bytes.Buffer) error {
		status := 403
		return accessLogsTmpl.Execute(b, accessLogsPageData{
			Title: "Applications", User: "admin@beyond.local", Nonce: "n6",
			From: "2026-09-17T14:00:00", To: "2026-09-17T15:00:00",
			Query:      AccessLogQuery{Decision: "deny", Limit: 100, StatusCode: &status},
			StatusCode: "403", Applications: []string{"argocd", "grafana", "netbox"},
			Records: []AccessLogRecord{
				{Type: "http", Entry: AccessLogEntry{Timestamp: time.Date(2026, 9, 17, 14, 58, 3, 120000000, time.UTC), Decision: "deny", UserEmail: "alice@example.com", UserGroups: []string{"engineering"}, Resource: "grafana", Method: "GET", Path: "/api/dashboards/42", Host: "grafana.example.com", SourceIP: "192.0.2.10", UserAgent: "Mozilla/5.0", StatusCode: 403, DurationMS: 17, BytesSent: 512, Error: "forbidden"}},
				{Type: "http_bearer", Entry: AccessLogEntry{Timestamp: time.Date(2026, 9, 17, 14, 54, 48, 901000000, time.UTC), Decision: "allow", UserEmail: "service@example.com", UserGroups: []string{"platform", "automation"}, Resource: "argocd", Method: "POST", Path: "/api/v1/applications/sync", Host: "argocd.example.com", SourceIP: "2001:db8::20", UserAgent: "argocd-cli/2.14", StatusCode: 200, DurationMS: 1240, BytesSent: 18432}},
				{Type: "http_credential", Entry: AccessLogEntry{Timestamp: time.Date(2026, 9, 17, 14, 50, 12, 440000000, time.UTC), Decision: "error", UserEmail: "operator@example.com", UserGroups: []string{"network"}, Resource: "netbox", Method: "GET", Path: "/api/ipam/prefixes/", Host: "netbox.example.com", SourceIP: "198.51.100.8", UserAgent: "curl/8.7", StatusCode: 503, DurationMS: 10004, BytesSent: 94, Error: "upstream unavailable"}},
			},
		})
	})
	t.Logf("rendered development pages to %s", dir)
}
