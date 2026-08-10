package beyond

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrafanaRoleProjection_RoleForGroups(t *testing.T) {
	t.Parallel()
	projection := &GrafanaRoleProjection{
		Header:      "X-Beyond-Role",
		DefaultRole: "Viewer",
		Rules: []GrafanaRoleRule{
			{Groups: []string{"platform"}, Role: "Admin"},
			{Groups: []string{"engineering"}, Role: "Editor"},
		},
	}

	assert.Equal(t, "Admin", projection.RoleForGroups([]string{"engineering", "platform"}))
	assert.Equal(t, "Editor", projection.RoleForGroups([]string{"engineering"}))
	assert.Equal(t, "Viewer", projection.RoleForGroups([]string{"support"}))
}

func TestInjectApplicationHeaders_GrafanaRoleProjection(t *testing.T) {
	t.Parallel()
	app := &Application{
		Name: "grafana",
		GrafanaRoleProjection: &GrafanaRoleProjection{
			Header:      "X-Beyond-Role",
			DefaultRole: "Viewer",
			Rules: []GrafanaRoleRule{
				{Groups: []string{"platform"}, Role: "Admin"},
				{Groups: []string{"engineering"}, Role: "Editor"},
			},
		},
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	injectApplicationHeaders(r, app, &Identity{Groups: []string{"engineering"}})

	assert.Equal(t, "Editor", r.Header.Get("X-Beyond-Role"))
}
