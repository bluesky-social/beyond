package beyond

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() *Config {
	return &Config{
		AdminGroups: []string{"authentik Admins"},
		Sessions:    SessionConfig{HTTPLifetime: 12 * time.Hour},
		Applications: map[string]*Application{
			"grafana": {
				Name:          "grafana",
				Upstream:      "http://localhost:3000",
				Host:          "grafana.internal",
				AllowedGroups: []string{"engineering", "team-all"},
				GrafanaRoleProjection: &GrafanaRoleProjection{
					Header:      "X-Beyond-Role",
					DefaultRole: "Viewer",
					Rules: []GrafanaRoleRule{
						{Groups: []string{"platform"}, Role: "Admin"},
						{Groups: []string{"engineering"}, Role: "Editor"},
					},
				},
			},
			"argocd": {
				Name:          "argocd",
				Upstream:      "http://localhost:8080",
				Host:          "argocd.internal",
				AllowedGroups: []string{"platform"},
			},
		},
	}
}

func TestAuthorizer_CheckHTTP_Allowed(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())
	allowed, app := az.CheckHTTP("grafana.internal", []string{"engineering"})
	assert.True(t, allowed)
	require.NotNil(t, app)
	assert.Equal(t, "grafana", app.Name)
}

func TestAuthorizer_CheckHTTP_Denied(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())
	allowed, app := az.CheckHTTP("argocd.internal", []string{"engineering"})
	assert.False(t, allowed)
	require.NotNil(t, app)
	assert.Equal(t, "argocd", app.Name)
}

// TestAuthorizer_CheckHTTP_CaseInsensitiveHost is the L-6 regression test:
// host matching must be case-insensitive (DNS names are), so a mixed-case Host
// header still routes to the configured app.
func TestAuthorizer_CheckHTTP_CaseInsensitiveHost(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())
	allowed, app := az.CheckHTTP("Grafana.Internal", []string{"engineering"})
	assert.True(t, allowed, "mixed-case host must match the configured lowercase host")
	require.NotNil(t, app)
	assert.Equal(t, "grafana", app.Name)

	assert.NotNil(t, az.LookupApp("GRAFANA.INTERNAL"), "LookupApp must be case-insensitive")
}

func TestAuthorizer_CheckHTTP_UnknownHost(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())
	allowed, app := az.CheckHTTP("unknown.internal", []string{"engineering"})
	assert.False(t, allowed)
	assert.Nil(t, app)
}

func TestAuthorizer_CheckHTTP_AdminBypass(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())
	allowed, app := az.CheckHTTP("argocd.internal", []string{"authentik Admins"})
	assert.True(t, allowed)
	require.NotNil(t, app)
	assert.Equal(t, "argocd", app.Name)
}

func TestAuthorizer_Reload(t *testing.T) {
	t.Parallel()
	az := NewAuthorizer(testConfig())

	// Confirm grafana is accessible before reload.
	allowed, app := az.CheckHTTP("grafana.internal", []string{"engineering"})
	assert.True(t, allowed)
	require.NotNil(t, app)

	// Build a new config without grafana.
	newCfg := &Config{
		AdminGroups: []string{"authentik Admins"},
		Applications: map[string]*Application{
			"argocd": {
				Name:          "argocd",
				Upstream:      "http://localhost:8080",
				Host:          "argocd.internal",
				AllowedGroups: []string{"platform"},
			},
		},
	}
	az.Reload(newCfg)

	// grafana should now be unknown.
	allowed, app = az.CheckHTTP("grafana.internal", []string{"engineering"})
	assert.False(t, allowed)
	assert.Nil(t, app)
}

func TestAuthorizer_AllowedApplications(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.Applications["grafana"].DisplayName = "Grafana"
	cfg.Applications["grafana"].Description = "Dashboards"
	cfg.Applications["grafana"].LaunchURL = "https://grafana.internal/"
	cfg.Applications["argocd"].DisplayName = "Argo CD"
	cfg.Applications["argocd"].LaunchURL = "https://argocd.internal/"

	az := NewAuthorizer(cfg)

	apps := az.AllowedApplications([]string{"engineering"})
	require.Len(t, apps, 1)
	assert.Equal(t, PortalApplication{
		Name:        "grafana",
		DisplayName: "Grafana",
		Description: "Dashboards",
		LaunchURL:   "https://grafana.internal/",
	}, apps[0])
}

func TestAuthorizer_AllowedApplications_AdminSeesAllSorted(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.Applications["grafana"].DisplayName = "Grafana"
	cfg.Applications["grafana"].LaunchURL = "https://grafana.internal/"
	cfg.Applications["argocd"].DisplayName = "Argo CD"
	cfg.Applications["argocd"].LaunchURL = "https://argocd.internal/"

	apps := NewAuthorizer(cfg).AllowedApplications([]string{"authentik Admins"})
	require.Len(t, apps, 2)
	assert.Equal(t, "argocd", apps[0].Name)
	assert.Equal(t, "grafana", apps[1].Name)
}

func TestAuthorizer_AllowedApplications_Empty(t *testing.T) {
	t.Parallel()
	apps := NewAuthorizer(testConfig()).AllowedApplications([]string{"unrelated"})
	assert.Empty(t, apps)
}

func TestAuthorizer_AllowedApplications_HidesInternalEntries(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.Applications["grafana"].HideFromPortal = true

	apps := NewAuthorizer(cfg).AllowedApplications([]string{"engineering"})

	for _, app := range apps {
		assert.NotEqual(t, "grafana", app.Name)
	}
}
