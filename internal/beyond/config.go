package beyond

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the full beyond configuration.
type Config struct {
	Sessions     SessionConfig           `yaml:"sessions"`
	Portal       *PortalConfig           `yaml:"portal"`
	AdminGroups  []string                `yaml:"admin_groups"`
	Applications map[string]*Application `yaml:"applications"`
}

// PortalConfig enables the authenticated application directory on its own
// host. The portal is deliberately separate from Applications: it is a Beyond
// surface, not a proxied resource, and any authenticated user may open it even
// when their current group set grants no applications.
type PortalConfig struct {
	Host  string `yaml:"host"`
	Title string `yaml:"title"`
}

// SessionConfig controls session lifetimes.
type SessionConfig struct {
	HTTPLifetime time.Duration `yaml:"http_lifetime"`
}

// Application represents a proxied HTTP application.
type Application struct {
	Name                  string                 `yaml:"-"` // populated from map key after parse
	Upstream              string                 `yaml:"upstream"`
	Host                  string                 `yaml:"host"`
	DisplayName           string                 `yaml:"display_name"`
	Description           string                 `yaml:"description"`
	LaunchURL             string                 `yaml:"launch_url"`
	AllowedGroups         []string               `yaml:"allowed_groups"`
	GrafanaRoleProjection *GrafanaRoleProjection `yaml:"grafana_role_projection"`
	BearerAuth            *BearerAuthConfig      `yaml:"bearer_auth"`
	CredentialAuth        *CredentialAuthConfig  `yaml:"credential_auth"`
	MintAuth              *MintAuthConfig        `yaml:"mint_auth"`
	// PassthroughAuthSchemes lists Authorization header schemes (the word
	// before the first space, e.g. "Token") that bypass edge authentication
	// entirely. A request whose Authorization header matches one of these
	// schemes is proxied directly to the upstream; the upstream is
	// responsible for authenticating every such request itself.
	//
	// Trust model: beyond does NOT verify these credentials. Only configure
	// this for upstreams that authenticate every request independently —
	// e.g. NetBox API tokens. Adding an app's scheme here without a
	// corresponding upstream auth check silently opens that app to any
	// bearer the client can fabricate.
	//
	// "Bearer" is explicitly disallowed: it would bypass bearer_auth OIDC
	// verification, which is beyond's own edge-auth mechanism for JWTs.
	PassthroughAuthSchemes []string `yaml:"passthrough_auth_schemes"`
}

// BearerAuthConfig enables OIDC access-token authentication for an
// application: a request carrying `Authorization: Bearer <jwt>` is verified
// at the edge (signature via JWKS, issuer, audience, expiry) and its groups
// claim feeds the same allowed_groups / admin_groups policy the cookie path
// uses. Apps without this block reject bearer-carrying requests outright.
//
// Issuer and JWKSURL are deliberately separate (split-horizon): the token's
// `iss` is the host the operator's machine hit (public Authentik), while
// beyond fetches keys from the in-cluster Authentik service. Audience is the
// provider's OAuth2 client ID.
type BearerAuthConfig struct {
	Issuer   string `yaml:"issuer"`
	JWKSURL  string `yaml:"jwks_url"`
	Audience string `yaml:"audience"`
}

// CredentialAuthConfig enables per-request validation of composite
// "<username>:<app-password>" credentials against Authentik's OAuth2 token
// endpoint via the client-credentials grant. It targets third-party agent
// harnesses (the AI gateway) whose client contract is a single static string
// sent as `Authorization: Bearer <cred>` or `x-api-key: <cred>` — they cannot
// perform an OIDC browser flow.
//
// The credential is an Authentik app password, NOT an API token: its blast
// radius is bounded to applications whose policy bindings admit the user, and
// Authentik enforces user is_active plus the gateway app's policy bindings
// inside the grant itself. Beyond decodes the returned JWT's claims and injects
// X-Beyond-* identity headers, then strips the credential before proxying so it
// never reaches the (auth-less) upstream.
//
// TokenURL is the in-cluster Authentik token endpoint (plain HTTP, same trust
// posture as bearer_auth's jwks_url fetch). ClientID identifies the gateway's
// OAuth2 provider.
type CredentialAuthConfig struct {
	TokenURL string `yaml:"token_url"`
	ClientID string `yaml:"client_id"`
	// CredentialHeader, when set, names a custom header (e.g. "x-agw-key")
	// that carries the composite credential for upstreams whose clients also
	// send an unrelated credential in the standard Authorization/x-api-key
	// headers (e.g. Anthropic OAuth passthrough for official Claude Code
	// clients). When a request carries this header, ITS value
	// authenticates as the composite credential, and on success ONLY this
	// header is stripped before proxying — Authorization and x-api-key are
	// forwarded to the upstream untouched. When the header is absent from a
	// given request, the existing Authorization/x-api-key flow applies
	// unchanged (both consulted per extractCredential's precedence, both
	// stripped on success).
	CredentialHeader string `yaml:"credential_header"`
}

// MintAuthConfig turns an application into the Authentik app-password mint
// page. A mint app is NOT a proxy — it has no upstream; its bespoke handler
// runs a dedicated, scoped OIDC flow and, inside the callback, calls
// Authentik's token API AS THE USER to create an app password, rendering the
// composite `<username>:<key>`
// once. The whole value-add over Authentik's own UI is a sane expiry (the cap,
// not the +30-min default) and the assembled composite behind one URL.
//
// The mint OAuth client is deliberately DISTINCT from beyond's login client:
// it requests the `goauthentik.io/api` scope (so the code-exchange access token
// is an Authentik API bearer for the user), which must never land on the
// widely-held login session cookie. Reusing the login client for minting was
// considered and rejected for exactly that reason.
//
// Issuer is the PUBLIC Authentik URL: the browser is redirected there AND the
// code exchange happens there, because Authentik stamps the id_token `iss` with
// the issuing host and the verifier checks it (exchanging in-cluster would fail
// verification — the id_token iss would be the internal hostname). The public
// round-trip can stay within the private network via beyond's own load
// balancer, same as the login path.
// Only APIURL (token-create/view_key, which use the token as an opaque bearer
// with no iss check) points at the in-cluster host.
type MintAuthConfig struct {
	// ClientID is the dedicated mint OAuth2 public client (PKCE, no secret).
	ClientID string `yaml:"client_id"`
	// Issuer is the public OIDC issuer URL: browser redirect target, code
	// exchange target, and the expected id_token iss (all must be the same host).
	Issuer string `yaml:"issuer"`
	// APIURL is the in-cluster Authentik API base (e.g. .../api/v3), used for
	// the token-create + view_key calls with the user's access token as bearer.
	APIURL string `yaml:"api_url"`
	// TokenLifetime is the requested app-password expiry, derived from
	// TokenLifetimeRaw in populate(). Must be ≤ the user's Authentik lifetime
	// cap; Authentik rejects an over-cap request, which the handler surfaces as
	// a clean error.
	TokenLifetime time.Duration `yaml:"-"`
	// TokenLifetimeRaw is the on-the-wire form, e.g. "365d". time.ParseDuration
	// has no day unit, so parseExtendedDuration handles the `Nd` suffix (and
	// falls back to time.ParseDuration for h/m/s). Kept separate from the parsed
	// value so YAML never tries (and fails) to decode "365d" into a Duration.
	TokenLifetimeRaw string `yaml:"token_lifetime"`
	// TokenScopeName is the API scope the mint client carries; the handler does
	// not send it on the wire (scopes are fixed by the OAuth client config), but
	// it is recorded here for config clarity and future assertions. Defaults to
	// "goauthentik.io/api".
	TokenScopeName string `yaml:"token_scope_name"`
}

// GrafanaRoleProjection maps verified identity groups to a Grafana org role
// and emits it as an app-specific header for Grafana's auth.proxy Role field.
type GrafanaRoleProjection struct {
	Header      string            `yaml:"header"`
	DefaultRole string            `yaml:"default_role"`
	Rules       []GrafanaRoleRule `yaml:"rules"`
}

// GrafanaRoleRule assigns Role when the user has any listed group. Rules are
// evaluated in YAML order, so operators can put higher-privilege roles first.
type GrafanaRoleRule struct {
	Groups []string `yaml:"groups"`
	Role   string   `yaml:"role"`
}

// LoadConfig reads the YAML file at path, applies defaults, and validates the result.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyDefaults(&cfg)

	if err := cfg.populate(); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// defaultMintTokenScopeName is the API scope the mint OAuth client carries.
const defaultMintTokenScopeName = "goauthentik.io/api"

// applyDefaults sets zero-value fields to their documented defaults.
func applyDefaults(cfg *Config) {
	if cfg.Sessions.HTTPLifetime == 0 {
		cfg.Sessions.HTTPLifetime = 12 * time.Hour
	}
	if cfg.Portal != nil && cfg.Portal.Title == "" {
		cfg.Portal.Title = "Beyond"
	}
	for _, app := range cfg.Applications {
		if app != nil && app.MintAuth != nil && app.MintAuth.TokenScopeName == "" {
			app.MintAuth.TokenScopeName = defaultMintTokenScopeName
		}
	}
}

// populate sets derived fields that cannot be expressed in YAML.
func (cfg *Config) populate() error {
	if cfg.Portal != nil {
		cfg.Portal.Host = strings.ToLower(cfg.Portal.Host)
	}
	for name, app := range cfg.Applications {
		if app == nil {
			return fmt.Errorf("application %q has no configuration", name)
		}
		app.Name = name
		// DNS host names are case-insensitive, but the inbound Host header
		// carries whatever case the client sent. Canonicalize to lowercase
		// here so both the duplicate-host check below and the lookup path
		// (authz.go) compare apples to apples — otherwise "App.example.com"
		// and "app.example.com" could be two apps, and routing would hinge on
		// the exact Host-header case.
		app.Host = strings.ToLower(app.Host)
		if app.DisplayName == "" {
			app.DisplayName = name
		}
		if app.LaunchURL == "" && app.Host != "" {
			app.LaunchURL = (&url.URL{Scheme: "https", Host: app.Host, Path: "/"}).String()
		}

		// Parse the mint token_lifetime here (not at validate time) so the
		// derived Duration is available to the handler. A malformed value is a
		// hard config error surfaced at boot.
		if app.MintAuth != nil && app.MintAuth.TokenLifetimeRaw != "" {
			d, err := parseExtendedDuration(app.MintAuth.TokenLifetimeRaw)
			if err != nil {
				return fmt.Errorf("application %q: mint_auth.token_lifetime %q: %w", name, app.MintAuth.TokenLifetimeRaw, err)
			}
			app.MintAuth.TokenLifetime = d
		}
	}
	return nil
}

// parseExtendedDuration parses a duration string that may use a trailing `d`
// (days) unit, which time.ParseDuration does not support. A bare `<N>d` is
// interpreted as N*24h; any other form is delegated to time.ParseDuration.
// Mixed forms like "365d12h" are NOT supported (kept simple; the mint config
// only ever needs a whole-day cap). Days are exact 24h units — the mint expiry
// is an approximate cap, not a calendar-aware date, so DST/leap concerns don't
// apply.
func parseExtendedDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid day duration: %w", err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("day duration must be positive (got %d)", days)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// maxHTTPLifetime bounds the session lifetime. Sessions cache the user's
// groups for their whole lifetime (the cookie-path authZ decision is frozen at
// login), so an over-long lifetime extends the window in which a
// privilege-revocation goes unenforced. 24h matches a daily re-auth policy and
// keeps that frozen-authZ window bounded.
const maxHTTPLifetime = 24 * time.Hour

// validate checks all required fields and cross-cutting constraints.
func (cfg *Config) validate() error {
	// Session lifetime must be positive and bounded. applyDefaults has already
	// substituted 12h for an unset (zero) value, so anything <= 0 here is an
	// explicit misconfiguration: a negative lifetime mints cookies with
	// Max-Age=0 and a past ExpiresAt, so every login produces no usable
	// session — a silent infinite IdP redirect loop. Reject it loudly instead.
	if cfg.Sessions.HTTPLifetime <= 0 {
		return fmt.Errorf("sessions.http_lifetime must be positive (got %s)", cfg.Sessions.HTTPLifetime)
	}
	if cfg.Sessions.HTTPLifetime > maxHTTPLifetime {
		return fmt.Errorf("sessions.http_lifetime %s exceeds the maximum of %s", cfg.Sessions.HTTPLifetime, maxHTTPLifetime)
	}

	if cfg.Portal != nil {
		if cfg.Portal.Host == "" {
			return fmt.Errorf("portal.host is required")
		}
		if cfg.Portal.Title == "" {
			return fmt.Errorf("portal.title is required")
		}
		if containsCtrl(cfg.Portal.Title) {
			return fmt.Errorf("portal.title contains control characters")
		}
	}

	// Validate applications.
	seenHosts := make(map[string]string) // host -> app name
	for name, app := range cfg.Applications {
		// A mint app has no upstream — it IS the upstream (a bespoke handler
		// that renders HTML, not a proxy). Relax the upstream requirement for
		// it only; every other app must proxy somewhere.
		if app.MintAuth == nil {
			if app.Upstream == "" {
				return fmt.Errorf("application %q: upstream is required", name)
			}
			u, err := url.Parse(app.Upstream)
			if err != nil {
				return fmt.Errorf("application %q: invalid upstream URL: %w", name, err)
			}
			if u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("application %q: upstream must have scheme and host (got %q)", name, app.Upstream)
			}
		}
		if app.Host == "" {
			return fmt.Errorf("application %q: host is required", name)
		}
		if cfg.Portal != nil && app.Host == cfg.Portal.Host {
			return fmt.Errorf("application %q: host %q conflicts with portal host", name, app.Host)
		}
		if app.DisplayName == "" {
			return fmt.Errorf("application %q: display_name is required", name)
		}
		if containsCtrl(app.DisplayName) || containsCtrl(app.Description) {
			return fmt.Errorf("application %q: display metadata contains control characters", name)
		}
		if err := validateLaunchURL(name, app); err != nil {
			return err
		}
		if len(app.AllowedGroups) == 0 {
			return fmt.Errorf("application %q: allowed_groups is required", name)
		}
		if err := validateGrafanaRoleProjection(name, app.GrafanaRoleProjection); err != nil {
			return err
		}
		if err := validateBearerAuth(name, app.BearerAuth); err != nil {
			return err
		}
		if err := validateCredentialAuth(name, app); err != nil {
			return err
		}
		if err := validateMintAuth(name, app); err != nil {
			return err
		}
		if err := validatePassthroughAuthSchemes(name, app.PassthroughAuthSchemes); err != nil {
			return err
		}
		if prev, ok := seenHosts[app.Host]; ok {
			return fmt.Errorf("duplicate host %q: used by both %q and %q", app.Host, prev, name)
		}
		seenHosts[app.Host] = name
	}

	return nil
}

func validateLaunchURL(appName string, app *Application) error {
	u, err := url.Parse(app.LaunchURL)
	if err != nil {
		return fmt.Errorf("application %q: launch_url is not a valid URL: %w", appName, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("application %q: launch_url must be an absolute https URL (got %q)", appName, app.LaunchURL)
	}
	if !strings.EqualFold(u.Hostname(), app.Host) {
		return fmt.Errorf("application %q: launch_url host %q must match application host %q", appName, u.Hostname(), app.Host)
	}
	return nil
}

func validateBearerAuth(appName string, ba *BearerAuthConfig) error {
	if ba == nil {
		return nil
	}
	if ba.Issuer == "" {
		return fmt.Errorf("application %q: bearer_auth.issuer is required", appName)
	}
	if ba.JWKSURL == "" {
		return fmt.Errorf("application %q: bearer_auth.jwks_url is required", appName)
	}
	if ba.Audience == "" {
		return fmt.Errorf("application %q: bearer_auth.audience is required", appName)
	}
	return nil
}

func validateCredentialAuth(appName string, app *Application) error {
	ca := app.CredentialAuth
	if ca == nil {
		return nil
	}
	if ca.TokenURL == "" {
		return fmt.Errorf("application %q: credential_auth.token_url is required", appName)
	}
	// token_url must be an absolute http(s) URL: beyond POSTs to it directly
	// per request, so a relative or scheme-less value is a misconfiguration
	// that would only surface as a runtime dial failure. Mirror the
	// upstream-URL validation above.
	u, err := url.Parse(ca.TokenURL)
	if err != nil {
		return fmt.Errorf("application %q: credential_auth.token_url is not a valid URL: %w", appName, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("application %q: credential_auth.token_url must be an absolute http(s) URL (got %q)", appName, ca.TokenURL)
	}
	if ca.ClientID == "" {
		return fmt.Errorf("application %q: credential_auth.client_id is required", appName)
	}
	// credential_auth and bearer_auth both claim `Authorization: Bearer` — an
	// app configured for both has ambiguous dispatch, so forbid the overlap.
	if app.BearerAuth != nil {
		return fmt.Errorf("application %q: credential_auth and bearer_auth are mutually exclusive (both claim Authorization: Bearer)", appName)
	}
	// credential_auth validates the credential at the edge and MUST strip it
	// before proxying; passthrough forwards the Authorization header to the
	// upstream unvalidated. Combining them would leak the credential to an
	// upstream that isn't supposed to see it, so forbid the overlap.
	if len(app.PassthroughAuthSchemes) > 0 {
		return fmt.Errorf("application %q: credential_auth and passthrough_auth_schemes are mutually exclusive (the credential must never reach the upstream unvalidated)", appName)
	}
	if ca.CredentialHeader != "" {
		// Must be a syntactically valid, untrimmed HTTP header name — mirrors
		// validateProjectionHeader's check below. Without this, a value with
		// whitespace/separators would pass config validation yet could never
		// be sent as a real header (net/http canonicalizes to the token
		// grammar), silently making the configured path unreachable.
		if strings.TrimSpace(ca.CredentialHeader) != ca.CredentialHeader || !isHTTPToken(ca.CredentialHeader) {
			return fmt.Errorf("application %q: credential_auth.credential_header %q is not a valid HTTP header name", appName, ca.CredentialHeader)
		}
		// Reusing "Authorization" or "x-api-key" as the custom credential_header
		// name would silently change strip semantics: those names are also
		// consulted (and stripped) via the standard extractCredential path, so
		// pointing credential_header at one of them would be confusing and wrong.
		// The whole point of credential_header is a name DISTINCT from the
		// standard headers.
		if strings.EqualFold(ca.CredentialHeader, "Authorization") || strings.EqualFold(ca.CredentialHeader, "x-api-key") {
			return fmt.Errorf("application %q: credential_auth.credential_header must not be \"Authorization\" or \"x-api-key\" (those are the standard headers this feature exists to bypass)", appName)
		}
		// Host, Content-Length, Transfer-Encoding, and Trailer are valid HTTP
		// tokens but net/http's server strips them out of r.Header into
		// dedicated Request fields before a handler ever sees them
		// (Request.Host, ContentLength, TransferEncoding, Trailer).
		// hasCustomCredentialHeader reads only r.Header, so configuring one
		// of these would pass every other check yet make the credential
		// permanently unobservable — reject it at config load instead of
		// failing silently at runtime.
		for _, reserved := range []string{"Host", "Content-Length", "Transfer-Encoding", "Trailer"} {
			if strings.EqualFold(ca.CredentialHeader, reserved) {
				return fmt.Errorf("application %q: credential_auth.credential_header must not be %q (net/http does not expose it via r.Header, so it can never be read)", appName, reserved)
			}
		}
	}
	return nil
}

// mustBeAbsoluteHTTPURL returns an error unless raw parses as an absolute
// http(s) URL with a host. Shared by the mint-auth URL fields, same shape as
// validateCredentialAuth's token_url check.
func mustBeAbsoluteHTTPURL(appName, field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("application %q: %s is not a valid URL: %w", appName, field, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("application %q: %s must be an absolute http(s) URL (got %q)", appName, field, raw)
	}
	return nil
}

func validateMintAuth(appName string, app *Application) error {
	ma := app.MintAuth
	if ma == nil {
		return nil
	}
	// A mint app is not a proxy app: it does the app-password minting itself and
	// has no upstream. Combining it with any proxy-auth mode is a category error
	// (mint has no request to proxy) and would also make dispatch ambiguous, so
	// forbid the overlaps explicitly — mirrors validateCredentialAuth.
	if app.CredentialAuth != nil {
		return fmt.Errorf("application %q: mint_auth and credential_auth are mutually exclusive (a mint app is not a proxy app)", appName)
	}
	if app.BearerAuth != nil {
		return fmt.Errorf("application %q: mint_auth and bearer_auth are mutually exclusive (a mint app is not a proxy app)", appName)
	}
	if len(app.PassthroughAuthSchemes) > 0 {
		return fmt.Errorf("application %q: mint_auth and passthrough_auth_schemes are mutually exclusive (a mint app is not a proxy app)", appName)
	}
	if app.Upstream != "" {
		return fmt.Errorf("application %q: mint_auth apps must not set upstream (a mint app does not proxy)", appName)
	}

	if ma.ClientID == "" {
		return fmt.Errorf("application %q: mint_auth.client_id is required", appName)
	}
	if ma.Issuer == "" {
		return fmt.Errorf("application %q: mint_auth.issuer is required", appName)
	}
	// issuer is browser-facing (it drives the authorization redirect and must
	// match the id_token `iss`), so it must be https — unlike token_url/api_url,
	// which are legitimately in-cluster plain HTTP. Requiring https here rejects
	// the footgun of routing the auth flow over cleartext.
	if u, err := url.Parse(ma.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("application %q: mint_auth.issuer must be an absolute https URL (got %q)", appName, ma.Issuer)
	}
	if ma.APIURL == "" {
		return fmt.Errorf("application %q: mint_auth.api_url is required", appName)
	}
	if err := mustBeAbsoluteHTTPURL(appName, "mint_auth.api_url", ma.APIURL); err != nil {
		return err
	}
	// TokenLifetimeRaw is required and must have parsed to a positive duration
	// in populate(). A zero TokenLifetime with a non-empty raw value can't
	// happen (parseExtendedDuration rejects non-positive), so the raw-empty
	// check is the real gate.
	if ma.TokenLifetimeRaw == "" {
		return fmt.Errorf("application %q: mint_auth.token_lifetime is required", appName)
	}
	if ma.TokenLifetime <= 0 {
		return fmt.Errorf("application %q: mint_auth.token_lifetime must be positive", appName)
	}
	return nil
}

func validatePassthroughAuthSchemes(appName string, schemes []string) error {
	for i, s := range schemes {
		if s == "" {
			return fmt.Errorf("application %q: passthrough_auth_schemes[%d] is empty", appName, i)
		}
		if strings.ContainsAny(s, " \t\r\n") {
			return fmt.Errorf("application %q: passthrough_auth_schemes[%d] %q must not contain whitespace", appName, i, s)
		}
		// Bearer would bypass the OIDC edge-auth path (bearer_auth). Disallow
		// it explicitly so operators can't accidentally open the JWT path to
		// unverified tokens by listing "Bearer" here.
		if strings.EqualFold(s, "Bearer") {
			return fmt.Errorf("application %q: passthrough_auth_schemes[%d]: \"Bearer\" is not allowed — use bearer_auth for JWT verification", appName, i)
		}
	}
	return nil
}

func validateGrafanaRoleProjection(appName string, projection *GrafanaRoleProjection) error {
	if projection == nil {
		return nil
	}
	if err := validateProjectionHeader(projection.Header); err != nil {
		return fmt.Errorf("application %q: grafana_role_projection.header: %w", appName, err)
	}
	if !isValidGrafanaRole(projection.DefaultRole) {
		return fmt.Errorf("application %q: grafana_role_projection.default_role %q must be one of Admin, Editor, Viewer, None",
			appName, projection.DefaultRole)
	}
	if len(projection.Rules) == 0 {
		return fmt.Errorf("application %q: grafana_role_projection.rules is required", appName)
	}
	for i, rule := range projection.Rules {
		if len(rule.Groups) == 0 {
			return fmt.Errorf("application %q: grafana_role_projection.rules[%d].groups is required", appName, i)
		}
		for j, group := range rule.Groups {
			if group == "" {
				return fmt.Errorf("application %q: grafana_role_projection.rules[%d].groups[%d] is empty", appName, i, j)
			}
			if containsCtrl(group) {
				return fmt.Errorf("application %q: grafana_role_projection.rules[%d].groups[%d] contains control characters",
					appName, i, j)
			}
		}
		if !isValidGrafanaRole(rule.Role) {
			return fmt.Errorf("application %q: grafana_role_projection.rules[%d].role %q must be one of Admin, Editor, Viewer, None",
				appName, i, rule.Role)
		}
	}
	return nil
}

func validateProjectionHeader(header string) error {
	if header == "" {
		return fmt.Errorf("is required")
	}
	if strings.TrimSpace(header) != header || !isHTTPToken(header) {
		return fmt.Errorf("%q is not a valid HTTP header name", header)
	}
	if !strings.HasPrefix(strings.ToLower(header), beyondHeaderPrefix) {
		return fmt.Errorf("%q must use the X-Beyond-* namespace so inbound spoofed values are stripped", header)
	}
	return nil
}

func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func isValidGrafanaRole(role string) bool {
	switch role {
	case "Admin", "Editor", "Viewer", "None":
		return true
	default:
		return false
	}
}
