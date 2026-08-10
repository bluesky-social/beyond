package beyond

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig holds the parameters needed to initialise an OIDCAuth.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string

	// TLSSkipVerify disables TLS certificate verification for server-to-server
	// OIDC calls (discovery, token exchange, JWKS fetch). This is needed when
	// beyond runs in-cluster and reaches the identity provider via a ClusterIP
	// with a self-signed certificate. Browser-facing redirects are unaffected.
	TLSSkipVerify bool
}

// OIDCAuth handles the OIDC/OAuth 2 authorisation code flow with PKCE.
// All methods are safe for concurrent use after construction.
type OIDCAuth struct {
	provider   *oidc.Provider
	config     oauth2.Config
	verifier   *oidc.IDTokenVerifier
	httpClient *http.Client // non-nil when TLSSkipVerify is enabled
}

// NewOIDCAuth performs OIDC provider discovery and returns a ready-to-use
// OIDCAuth.  ctx is used only for the discovery HTTP request.
func NewOIDCAuth(ctx context.Context, cfg OIDCConfig) (*OIDCAuth, error) {
	// When TLSSkipVerify is set, use a custom HTTP client that doesn't verify
	// the OIDC provider's TLS certificate. This is needed when beyond runs
	// in-cluster and talks to an identity provider with a self-signed cert.
	var httpClient *http.Client
	if cfg.TLSSkipVerify {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for in-cluster self-signed certs
			},
		}
		ctx = oidc.ClientContext(ctx, httpClient)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc provider discovery: %w", err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCAuth{
		provider:   provider,
		config:     oauthCfg,
		verifier:   verifier,
		httpClient: httpClient,
	}, nil
}

// mintScopes are the scopes the mint OAuth client requests. The load-bearing
// addition over the login client is goauthentik.io/api, so the code-exchange
// access token is an Authentik API bearer for the user; `groups` lets the
// callback enforce allowed_groups from the id_token before any token-create.
//
// `email` and `profile` are required too: the callback builds the composite as
// `<email>:<key>` (email hard-fails identity normalization if absent) and uses
// name/preferred_username for the display fallback — and Authentik only releases
// those claims when their scopes are requested. A minimal scope list
// (`openid groups goauthentik.io/api`) would be inconsistent with the
// requirement to render an email composite. Carrying email/profile here does
// NOT widen the sensitive surface: the risk to avoid is the API scope landing
// on the widely-held LOGIN client, not email/profile on this dedicated mint
// client (the login client already carries both).
var mintScopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "goauthentik.io/api"}

// NewMintOIDCAuth builds an OIDCAuth for the app-password mint flow. It is a
// SEPARATE instance from the login OIDCAuth (never reuse the login client for
// this): it uses the mint client_id and the mintScopes, so its access token
// carries the API scope. The login path's OIDCAuth is untouched — its scopes
// and its token-discarding HandleCallback stay byte-for-byte unchanged.
//
// The mint client is public (PKCE, no secret), so ClientSecret is left empty.
func NewMintOIDCAuth(ctx context.Context, cfg OIDCConfig) (*OIDCAuth, error) {
	var httpClient *http.Client
	if cfg.TLSSkipVerify {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for in-cluster self-signed certs
			},
		}
		ctx = oidc.ClientContext(ctx, httpClient)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("mint oidc provider discovery: %w", err)
	}

	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       mintScopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &OIDCAuth{
		provider:   provider,
		config:     oauthCfg,
		verifier:   verifier,
		httpClient: httpClient,
	}, nil
}

// HandleMintCallback is HandleCallback for the mint flow: it validates state,
// exchanges the code (sending PKCE), verifies the id_token + nonce, and returns
// the normalized identity ALONGSIDE the raw OAuth access token.
//
// The access token is the one thing the login-path HandleCallback deliberately
// discards. The mint callback needs it as the Authentik API bearer (the user's
// own authority) for the token-create call, so this variant surfaces it. The
// caller MUST treat it as a live secret: it lives for one handler stack frame
// and must never be written to a cookie, the DB, or a log.
//
// The code exchange goes against the DISCOVERED (public) token endpoint, NOT
// an in-cluster override. This matters: Authentik stamps the id_token `iss`
// with the host that issued it, and the verifier (built from public discovery)
// checks `iss` against the public issuer. Exchanging in-cluster would return a
// token whose iss is the in-cluster hostname, failing verification (the login
// path exchanges publicly for exactly this reason). The public round-trip can
// stay within the private network via beyond's own load balancer — the same
// posture the login path relies on. The API calls (token-create/view_key) DO
// hit the in-cluster host,
// but those use the access token as an opaque bearer (looked up by string,
// no iss check), so no split-horizon problem there.
func (o *OIDCAuth) HandleMintCallback(
	ctx context.Context,
	r *http.Request,
	expectedState, codeVerifier, expectedNonce, redirectURL string,
) (identity *Identity, accessToken string, err error) {
	gotState := r.URL.Query().Get("state")
	if gotState != expectedState {
		return nil, "", fmt.Errorf("state mismatch: expected %q, got %q", expectedState, gotState)
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, "", fmt.Errorf("missing code in callback")
	}

	exchangeCtx := ctx
	if o.httpClient != nil {
		exchangeCtx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}
	oauthToken, err := o.config.Exchange(
		exchangeCtx,
		code,
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
		oauth2.VerifierOption(codeVerifier),
	)
	if err != nil {
		return nil, "", fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, "", fmt.Errorf("no id_token in token response")
	}

	// go-oidc fetches JWKS lazily during Verify using the HTTP client on the
	// per-call context (defaulting to http.DefaultClient). When TLSSkipVerify is
	// set for the in-cluster self-signed posture, inject the insecure client so
	// the JWKS fetch honors it too — the exchange above already does.
	verifyCtx := ctx
	if o.httpClient != nil {
		verifyCtx = oidc.ClientContext(ctx, o.httpClient)
	}
	idToken, err := o.verifier.Verify(verifyCtx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("id_token verification: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(expectedNonce)) != 1 {
		return nil, "", fmt.Errorf("nonce mismatch")
	}

	var claims struct {
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, "", fmt.Errorf("extracting id_token claims: %w", err)
	}

	identity, err = validateAndNormalizeIdentity(
		claims.Email,
		claims.Name,
		claims.PreferredUsername,
		claims.Groups,
	)
	if err != nil {
		return nil, "", err
	}
	return identity, oauthToken.AccessToken, nil
}

// GenerateAuthParams creates a fresh random state token, PKCE code_verifier,
// and OIDC nonce. The state is a hex-encoded random value; the code_verifier
// is a base64url-encoded random value as required by RFC 7636; the nonce is a
// base64url-encoded random value bound into the id_token and verified on
// callback (OIDC core §3.1.2.1, replay defense-in-depth).
func (o *OIDCAuth) GenerateAuthParams() (state, codeVerifier, nonce string) {
	stateBuf := make([]byte, 16)
	if _, err := rand.Read(stateBuf); err != nil {
		panic(fmt.Sprintf("beyond: rand.Read: %v", err))
	}
	state = hex.EncodeToString(stateBuf)

	verifierBuf := make([]byte, 32)
	if _, err := rand.Read(verifierBuf); err != nil {
		panic(fmt.Sprintf("beyond: rand.Read: %v", err))
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBuf)

	nonceBuf := make([]byte, 16)
	if _, err := rand.Read(nonceBuf); err != nil {
		panic(fmt.Sprintf("beyond: rand.Read: %v", err))
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceBuf)

	return state, codeVerifier, nonce
}

// HandleLogin builds the OIDC authorization URL with PKCE (S256) and a nonce
// using the provided state, codeVerifier, and nonce, and redirects the browser
// (302).
//
// redirectURL is derived dynamically from the request's Host header by the
// caller so that each application subdomain uses its own callback endpoint.
// This avoids cross-host cookie scoping problems where the OIDC state cookie
// set on one host is invisible to the callback on another.
func (o *OIDCAuth) HandleLogin(w http.ResponseWriter, r *http.Request, state, codeVerifier, nonce, redirectURL string) {
	// Derive the S256 code challenge: BASE64URL(SHA256(code_verifier)).
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	authURL := o.config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback validates the state parameter, exchanges the authorisation
// code for tokens (sending the PKCE code_verifier), verifies the id_token,
// and returns the user's Identity.
//
// redirectURL must match the value sent in the corresponding HandleLogin call.
// The caller reconstructs it from the callback request's Host header — since
// the callback arrives on the same host that initiated the login, the two
// always agree.
func (o *OIDCAuth) HandleCallback(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	expectedState, codeVerifier, expectedNonce, redirectURL string,
) (*Identity, error) {
	gotState := r.URL.Query().Get("state")
	if gotState != expectedState {
		return nil, fmt.Errorf("state mismatch: expected %q, got %q", expectedState, gotState)
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("missing code in callback")
	}

	// Exchange the code for tokens, sending the PKCE verifier.
	// redirect_uri is passed explicitly so it matches the authorization request.
	// If TLSSkipVerify is enabled, inject the insecure HTTP client into the
	// context so the token exchange also skips certificate verification.
	exchangeCtx := ctx
	if o.httpClient != nil {
		exchangeCtx = context.WithValue(ctx, oauth2.HTTPClient, o.httpClient)
	}
	oauthToken, err := o.config.Exchange(
		exchangeCtx,
		code,
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
		oauth2.VerifierOption(codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	// Extract and verify the raw id_token string.
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}

	// go-oidc fetches JWKS lazily during Verify using the HTTP client on the
	// per-call context (defaulting to http.DefaultClient). When TLSSkipVerify is
	// set for the in-cluster self-signed posture, inject the insecure client so
	// the JWKS fetch honors it too — the code exchange above already does. Dormant
	// when the login issuer is a publicly-trusted host, but the gap would bite
	// the moment login verification reaches an in-cluster self-signed JWKS.
	verifyCtx := ctx
	if o.httpClient != nil {
		verifyCtx = oidc.ClientContext(ctx, o.httpClient)
	}
	idToken, err := o.verifier.Verify(verifyCtx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification: %w", err)
	}

	// Verify the nonce binds this id_token to the auth request we initiated
	// (OIDC core §3.1.2.1). go-oidc surfaces the claim on IDToken.Nonce but
	// does not compare it; we do the constant-time compare here.
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(expectedNonce)) != 1 {
		return nil, fmt.Errorf("nonce mismatch")
	}

	// Extract the claims we care about.  Validation, normalization, and
	// the display-name fallback chain all live in identity.go; keeping
	// this function focused on the OIDC plumbing makes the security
	// policy auditable in one place.
	var claims struct {
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extracting id_token claims: %w", err)
	}

	return validateAndNormalizeIdentity(
		claims.Email,
		claims.Name,
		claims.PreferredUsername,
		claims.Groups,
	)
}
