package beyond

import (
	"sort"
	"strings"
	"sync"
)

// PortalApplication is the non-sensitive presentation subset exposed to the
// portal template. In particular it carries no upstream or policy groups.
type PortalApplication struct {
	Name        string
	DisplayName string
	Description string
	LaunchURL   string
}

// Authorizer enforces group-based access policy for HTTP applications.
// All methods are safe for concurrent use.
type Authorizer struct {
	mu           sync.RWMutex
	hostToApp    map[string]*Application // HTTP host -> app
	applications []*Application
	adminGroups  map[string]bool
}

// NewAuthorizer builds an Authorizer from cfg.
func NewAuthorizer(cfg *Config) *Authorizer {
	az := &Authorizer{}
	az.hostToApp, az.applications, az.adminGroups = buildMaps(cfg)
	return az
}

// Reload atomically replaces the internal maps with those derived from cfg.
func (az *Authorizer) Reload(cfg *Config) {
	hostToApp, applications, adminGroups := buildMaps(cfg)
	az.mu.Lock()
	az.hostToApp = hostToApp
	az.applications = applications
	az.adminGroups = adminGroups
	az.mu.Unlock()
}

// AllowedApplications returns only applications permitted by userGroups. The
// result is detached from the live config, contains no policy or upstream
// details, and is sorted for stable rendering.
func (az *Authorizer) AllowedApplications(userGroups []string) []PortalApplication {
	az.mu.RLock()

	isAdmin := az.isAdmin(userGroups)

	apps := make([]PortalApplication, 0, len(az.applications))
	for _, app := range az.applications {
		if app.HideFromPortal {
			continue
		}
		if !isAdmin && !applicationAllowsAnyGroup(app, userGroups) {
			continue
		}
		apps = append(apps, PortalApplication{
			Name:        app.Name,
			DisplayName: app.DisplayName,
			Description: app.Description,
			LaunchURL:   app.LaunchURL,
		})
	}
	az.mu.RUnlock()

	sort.Slice(apps, func(i, j int) bool {
		left, right := strings.ToLower(apps[i].DisplayName), strings.ToLower(apps[j].DisplayName)
		if left == right {
			return apps[i].Name < apps[j].Name
		}
		return left < right
	})
	return apps
}

func applicationAllowsAnyGroup(app *Application, userGroups []string) bool {
	for _, userGroup := range userGroups {
		for _, allowedGroup := range app.AllowedGroups {
			if userGroup == allowedGroup {
				return true
			}
		}
	}
	return false
}

// CheckHTTP returns whether userGroups are permitted to access the application
// served at host. Return values:
//
//   - (false, nil)  – host is unknown
//   - (false, app)  – host is known but none of userGroups are allowed
//   - (true,  app)  – access granted (group match or admin bypass)
func (az *Authorizer) CheckHTTP(host string, userGroups []string) (bool, *Application) {
	host = strings.ToLower(host)
	az.mu.RLock()
	app, ok := az.hostToApp[host]
	isAdmin := az.isAdmin(userGroups)
	az.mu.RUnlock()

	if !ok {
		return false, nil
	}
	if isAdmin {
		return true, app
	}
	if applicationAllowsAnyGroup(app, userGroups) {
		return true, app
	}
	return false, app
}

// LookupApp returns the Application whose host matches, or nil if unknown.
// host is matched case-insensitively (DNS names are case-insensitive).
func (az *Authorizer) LookupApp(host string) *Application {
	host = strings.ToLower(host)
	az.mu.RLock()
	app := az.hostToApp[host]
	az.mu.RUnlock()
	return app
}

// isAdmin reports whether any of groups is an admin group.
// Callers must hold at least az.mu.RLock.
func (az *Authorizer) isAdmin(groups []string) bool {
	for _, g := range groups {
		if az.adminGroups[g] {
			return true
		}
	}
	return false
}

// buildMaps derives the lookup maps from cfg.
func buildMaps(cfg *Config) (map[string]*Application, []*Application, map[string]bool) {
	hostToApp := make(map[string]*Application, len(cfg.Applications))
	applications := make([]*Application, 0, len(cfg.Applications))
	for _, app := range cfg.Applications {
		hostToApp[app.Host] = app
		applications = append(applications, app)
	}

	adminGroups := make(map[string]bool, len(cfg.AdminGroups))
	for _, g := range cfg.AdminGroups {
		adminGroups[g] = true
	}

	return hostToApp, applications, adminGroups
}
