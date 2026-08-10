package beyond

import "net/http"

// RoleForGroups returns the first matching Grafana role for userGroups, or the
// configured default role when no rule matches.
func (p *GrafanaRoleProjection) RoleForGroups(userGroups []string) string {
	if p == nil {
		return ""
	}

	seen := make(map[string]bool, len(userGroups))
	for _, group := range userGroups {
		seen[group] = true
	}

	for _, rule := range p.Rules {
		for _, group := range rule.Groups {
			if seen[group] {
				return rule.Role
			}
		}
	}

	return p.DefaultRole
}

func injectApplicationHeaders(r *http.Request, app *Application, identity *Identity) {
	if app == nil || identity == nil || app.GrafanaRoleProjection == nil {
		return
	}
	setHeaderIfNonEmpty(
		r.Header,
		app.GrafanaRoleProjection.Header,
		app.GrafanaRoleProjection.RoleForGroups(identity.Groups),
	)
}
