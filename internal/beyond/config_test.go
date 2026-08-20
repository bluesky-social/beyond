package beyond

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "beyond-config-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	yaml := `
sessions:
  http_lifetime: 24h

portal:
  host: access.internal.example.com
  title: Internal services

admin_groups:
  - platform-admins
  - security-team

applications:
  dashboard:
    upstream: http://localhost:3000
    host: dashboard.internal.example.com
    display_name: Grafana
    description: Metrics and dashboards
    launch_url: https://dashboard.internal.example.com/dashboards/
    allowed_groups:
      - engineering
      - ops
    grafana_role_projection:
      header: X-Beyond-Role
      default_role: Viewer
      rules:
        - groups: [platform]
          role: Admin
        - groups: [engineering, ops]
          role: Editor
  api:
    upstream: http://localhost:8080
    host: api.internal.example.com
    preserve_host: true
    allowed_groups:
      - engineering
`
	path := writeTempFile(t, yaml)
	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	// Sessions
	assert.Equal(t, 24*time.Hour, cfg.Sessions.HTTPLifetime)
	require.NotNil(t, cfg.Portal)
	assert.Equal(t, "access.internal.example.com", cfg.Portal.Host)
	assert.Equal(t, "Internal services", cfg.Portal.Title)

	// Admin groups
	assert.Equal(t, []string{"platform-admins", "security-team"}, cfg.AdminGroups)

	// Applications
	require.Len(t, cfg.Applications, 2)

	dash := cfg.Applications["dashboard"]
	require.NotNil(t, dash)
	assert.Equal(t, "dashboard", dash.Name)
	assert.Equal(t, "http://localhost:3000", dash.Upstream)
	assert.Equal(t, "dashboard.internal.example.com", dash.Host)
	assert.Equal(t, "Grafana", dash.DisplayName)
	assert.Equal(t, "Metrics and dashboards", dash.Description)
	assert.Equal(t, "https://dashboard.internal.example.com/dashboards/", dash.LaunchURL)
	assert.Equal(t, []string{"engineering", "ops"}, dash.AllowedGroups)
	require.NotNil(t, dash.GrafanaRoleProjection)
	assert.Equal(t, "X-Beyond-Role", dash.GrafanaRoleProjection.Header)
	assert.Equal(t, "Viewer", dash.GrafanaRoleProjection.DefaultRole)
	require.Len(t, dash.GrafanaRoleProjection.Rules, 2)
	assert.Equal(t, []string{"platform"}, dash.GrafanaRoleProjection.Rules[0].Groups)
	assert.Equal(t, "Admin", dash.GrafanaRoleProjection.Rules[0].Role)
	assert.Equal(t, []string{"engineering", "ops"}, dash.GrafanaRoleProjection.Rules[1].Groups)
	assert.Equal(t, "Editor", dash.GrafanaRoleProjection.Rules[1].Role)

	api := cfg.Applications["api"]
	require.NotNil(t, api)
	assert.Equal(t, "api", api.Name)
	assert.Equal(t, "http://localhost:8080", api.Upstream)
	assert.Equal(t, "api.internal.example.com", api.Host)
	assert.True(t, api.PreserveHost)
	assert.Equal(t, "api", api.DisplayName)
	assert.Equal(t, "https://api.internal.example.com/", api.LaunchURL)
	assert.Equal(t, []string{"engineering"}, api.AllowedGroups)
}

func TestLoadConfig_Defaults(t *testing.T) {
	t.Parallel()
	yaml := `
applications:
  myapp:
    upstream: http://localhost:9000
    host: myapp.internal.example.com
    allowed_groups:
      - everyone
`
	path := writeTempFile(t, yaml)
	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	assert.Equal(t, 12*time.Hour, cfg.Sessions.HTTPLifetime, "default HTTP lifetime should be 12h")
}

func TestLoadConfig_PortalDefaults(t *testing.T) {
	t.Parallel()
	yaml := `
portal:
  host: Portal.Example.com
applications:
  myapp:
    upstream: http://localhost:9000
    host: App.Example.com
    allowed_groups: [everyone]
`
	path := writeTempFile(t, yaml)
	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	require.NotNil(t, cfg.Portal)
	assert.Equal(t, "portal.example.com", cfg.Portal.Host)
	assert.Equal(t, "Beyond", cfg.Portal.Title)
	assert.Equal(t, "app.example.com", cfg.Applications["myapp"].Host)
	assert.Equal(t, "myapp", cfg.Applications["myapp"].DisplayName)
	assert.Equal(t, "https://app.example.com/", cfg.Applications["myapp"].LaunchURL)
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name: "missing upstream",
			yaml: `
applications:
  myapp:
    host: myapp.example.com
    allowed_groups:
      - eng
`,
			errContains: "myapp",
		},
		{
			name: "missing host",
			yaml: `
applications:
  myapp:
    upstream: http://localhost:3000
    allowed_groups:
      - eng
`,
			errContains: "myapp",
		},
		{
			name: "missing allowed_groups on app",
			yaml: `
applications:
  myapp:
    upstream: http://localhost:3000
    host: myapp.example.com
`,
			errContains: "myapp",
		},
		{
			name: "duplicate host across apps",
			yaml: `
applications:
  app1:
    upstream: http://localhost:3000
    host: shared.example.com
    allowed_groups:
      - eng
  app2:
    upstream: http://localhost:3001
    host: shared.example.com
    allowed_groups:
      - eng
`,
			errContains: "shared.example.com",
		},
		{
			name: "portal host duplicates application host",
			yaml: `
portal:
  host: app.example.com
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    allowed_groups: [eng]
`,
			errContains: "portal host",
		},
		{
			name: "portal requires host",
			yaml: `
portal:
  title: Services
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    allowed_groups: [eng]
`,
			errContains: "portal.host",
		},
		{
			name: "portal host with port",
			yaml: `
portal:
  host: portal.example.com:443
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    allowed_groups: [eng]
`,
			errContains: "bare hostname",
		},
		{
			name: "portal host with scheme",
			yaml: `
portal:
  host: https://portal.example.com
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    allowed_groups: [eng]
`,
			errContains: "bare hostname",
		},
		{
			name: "portal host with trailing empty-port colon",
			yaml: `
portal:
  host: "portal.example.com:"
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    allowed_groups: [eng]
`,
			errContains: "bare hostname",
		},
		{
			name: "portal host with path",
			yaml: `
portal:
  host: portal.example.com/apps
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    allowed_groups: [eng]
`,
			errContains: "bare hostname",
		},
		{
			name: "launch URL host must match application host",
			yaml: `
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    launch_url: https://elsewhere.example.com/
    allowed_groups: [eng]
`,
			errContains: "launch_url host",
		},
		{
			name: "launch URL must use HTTPS",
			yaml: `
applications:
  app:
    upstream: http://localhost:3000
    host: app.example.com
    launch_url: http://app.example.com/
    allowed_groups: [eng]
`,
			errContains: "launch_url must be an absolute https URL",
		},
		{
			name: "duplicate host differing only in case",
			yaml: `
applications:
  app1:
    upstream: http://localhost:3000
    host: App.Example.Com
    allowed_groups:
      - eng
  app2:
    upstream: http://localhost:3001
    host: app.example.com
    allowed_groups:
      - eng
`,
			errContains: "duplicate host",
		},
		{
			name: "invalid upstream URL missing scheme",
			yaml: `
applications:
  myapp:
    upstream: "not-a-url"
    host: myapp.example.com
    allowed_groups:
      - eng
`,
			errContains: "scheme and host",
		},
		{
			name: "grafana role projection header must be owned by beyond",
			yaml: `
applications:
  grafana:
    upstream: http://localhost:3000
    host: grafana.example.com
    allowed_groups:
      - engineering
    grafana_role_projection:
      header: X-Grafana-Role
      default_role: Viewer
      rules:
        - groups: [engineering]
          role: Editor
`,
			errContains: "grafana_role_projection.header",
		},
		{
			name: "grafana role projection rejects invalid default role",
			yaml: `
applications:
  grafana:
    upstream: http://localhost:3000
    host: grafana.example.com
    allowed_groups:
      - engineering
    grafana_role_projection:
      header: X-Beyond-Role
      default_role: Owner
      rules:
        - groups: [engineering]
          role: Editor
`,
			errContains: "default_role",
		},
		{
			name: "grafana role projection rejects invalid HTTP header name",
			yaml: `
applications:
  grafana:
    upstream: http://localhost:3000
    host: grafana.example.com
    allowed_groups:
      - engineering
    grafana_role_projection:
      header: X-Beyond-Role@
      default_role: Viewer
      rules:
        - groups: [engineering]
          role: Editor
`,
			errContains: "valid HTTP header name",
		},
		{
			name: "grafana role projection rejects invalid mapped role",
			yaml: `
applications:
  grafana:
    upstream: http://localhost:3000
    host: grafana.example.com
    allowed_groups:
      - engineering
    grafana_role_projection:
      header: X-Beyond-Role
      default_role: Viewer
      rules:
        - groups: [engineering]
          role: Edtior
`,
			errContains: "rules[0].role",
		},
		{
			name: "negative http_lifetime is rejected",
			yaml: `
sessions:
  http_lifetime: -1h
applications:
  myapp:
    upstream: http://localhost:3000
    host: myapp.example.com
    allowed_groups:
      - eng
`,
			errContains: "http_lifetime must be positive",
		},
		{
			name: "over-bound http_lifetime is rejected",
			yaml: `
sessions:
  http_lifetime: 100h
applications:
  myapp:
    upstream: http://localhost:3000
    host: myapp.example.com
    allowed_groups:
      - eng
`,
			errContains: "exceeds the maximum",
		},
		{
			name: "grafana role projection requires groups",
			yaml: `
applications:
  grafana:
    upstream: http://localhost:3000
    host: grafana.example.com
    allowed_groups:
      - engineering
    grafana_role_projection:
      header: X-Beyond-Role
      default_role: Viewer
      rules:
        - groups: []
          role: Editor
`,
			errContains: "rules[0].groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeTempFile(t, tt.yaml)
			_, err := LoadConfig(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	require.Error(t, err)
}
