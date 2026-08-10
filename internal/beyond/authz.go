package beyond

import (
	"strings"
	"sync"
)

// Authorizer enforces group-based access policy for HTTP applications.
// All methods are safe for concurrent use.
type Authorizer struct {
	mu          sync.RWMutex
	hostToApp   map[string]*Application // HTTP host -> app
	adminGroups map[string]bool
}

// NewAuthorizer builds an Authorizer from cfg.
func NewAuthorizer(cfg *Config) *Authorizer {
	az := &Authorizer{}
	az.hostToApp, az.adminGroups = buildMaps(cfg)
	return az
}

// Reload atomically replaces the internal maps with those derived from cfg.
func (az *Authorizer) Reload(cfg *Config) {
	hostToApp, adminGroups := buildMaps(cfg)
	az.mu.Lock()
	az.hostToApp = hostToApp
	az.adminGroups = adminGroups
	az.mu.Unlock()
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
	for _, ug := range userGroups {
		for _, ag := range app.AllowedGroups {
			if ug == ag {
				return true, app
			}
		}
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
func buildMaps(cfg *Config) (map[string]*Application, map[string]bool) {
	hostToApp := make(map[string]*Application, len(cfg.Applications))
	for _, app := range cfg.Applications {
		hostToApp[app.Host] = app
	}

	adminGroups := make(map[string]bool, len(cfg.AdminGroups))
	for _, g := range cfg.AdminGroups {
		adminGroups[g] = true
	}

	return hostToApp, adminGroups
}
