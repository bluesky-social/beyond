// Package tokenverify validates Authentik-issued OIDC access tokens on the
// resource-server side: signature (via JWKS), issuer, audience, expiry, and
// then a pluggable authorization predicate over the claims.
//
// Authentication and authorization are deliberately separate:
//
//   - Verifier does AUTHENTICATION ONLY (is this a real, unexpired token from
//     the right issuer for the right audience?). It is group-agnostic.
//   - Authorizer does AUTHORIZATION (is this verified identity allowed?). The
//     lib ships RequireAnyGroup / RequireAllGroups; a tool can supply any
//     predicate. This keeps the group policy a per-tool decision, so a CLI
//     whose users live in a group disjoint from another tool's adopts the lib
//     with config, not a fork.
//
// Split-horizon by design: the token's `iss` is the PUBLIC host the operator's
// browser hit, but the resource server (running inside the cluster) fetches the
// JWKS from the IN-CLUSTER Authentik service. The issuer verified against and
// the URL keys are fetched from are therefore DIFFERENT hosts — which is why we
// use oidc.NewVerifier + oidc.NewRemoteKeySet (decoupled) rather than
// oidc.NewProvider (which forces discovery-URL == issuer). Signing keys are
// host-independent, so in-cluster JWKS verifies a publicly-issued token fine.
//
// Verification is offline: NewRemoteKeySet fetches the JWKS lazily on first use
// and caches it in-process (keyed by `kid`, refetched only on an unknown kid),
// so there is no boot-time network dependency and steady-state requests make no
// call to Authentik.
package tokenverify

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims is the subset of access-token claims the gate reads.
//
// `sub` is the ONLY guaranteed identity claim on an access token. `groups`,
// `email`, and `preferred_username` ride scope mappings that must be bound to
// the ACCESS token (not just the ID token / userinfo) at the Authentik
// provider — a deliberate provider config step, verified by decoding a real
// token, NOT assumed. Authorization should key on `sub` + `groups`; treat
// email/preferred_username as best-effort enrichment for audit logs.
type Claims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// HasGroup reports whether the claims contain the named group. Authentik may
// emit groups in any order and (mis)configuration can duplicate them, so this
// is a membership test, never an index/uniqueness assumption.
func (c *Claims) HasGroup(name string) bool {
	for _, g := range c.Groups {
		if g == name {
			return true
		}
	}
	return false
}

// Verifier does AUTHENTICATION ONLY: validate a raw bearer (signature, issuer,
// audience, expiry) and return the parsed claims. A non-nil error means the
// token is invalid and the request must be rejected. It is deliberately
// group-agnostic — authorization is a separate concern (see Authorizer).
// Interface so handlers/tests can supply a fake.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Claims, error)
}

// oidcVerifier is the production Verifier. It is constructed synchronously and
// never blocks: oidc.NewRemoteKeySet stores the JWKS URL and defers the actual
// fetch to the first Verify call, so there is no boot-time dependency on
// Authentik being reachable.
type oidcVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// New builds the split-horizon verifier: it requires `issuer` on the token
// (the `iss` the operator's browser host produced) while fetching keys from
// `jwksURL` (in-cluster, reachable from the resource server). These are
// intentionally different
// hosts — see the package doc. `audience` is the access-token `aud` (the OIDC
// client ID).
//
// No requiredGroup parameter: authorization is a separate concern (Authorizer)
// so this verifier is reusable by any tool regardless of its group policy.
func New(ctx context.Context, issuer, jwksURL, audience string) Verifier {
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
	v := oidc.NewVerifier(issuer, keySet, &oidc.Config{ClientID: audience})
	return &oidcVerifier{verifier: v}
}

func (v *oidcVerifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := tok.Claims(&claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// Authorizer is AUTHORIZATION: a predicate over verified claims. A non-nil
// error means "authenticated, but not allowed" (a handler maps it to 403).
// This is the seam that keeps group policy flexible per-tool — the lib bakes in
// no single group. Compose a policy from the constructors below, or write your
// own predicate.
type Authorizer func(*Claims) error

// ErrForbidden-style errors carry the human-readable reason; handlers surface
// the message in the 403 body.

// RequireAnyGroup passes if the claims contain AT LEAST ONE of the named groups
// (logical OR). The common case: a tool gates on RequireAnyGroup("engineering")
// or, for an audience spanning groups, RequireAnyGroup("engineering","platform").
//
// Zero groups = deny-all: an Authorizer that always rejects. This guards
// against an accidentally-unconfigured tool serving every authenticated user.
func RequireAnyGroup(groups ...string) Authorizer {
	return func(c *Claims) error {
		if len(groups) == 0 {
			return fmt.Errorf("not authorized: no groups configured (deny-all)")
		}
		for _, g := range groups {
			if c.HasGroup(g) {
				return nil
			}
		}
		return fmt.Errorf("not authorized: requires membership in any of %v", groups)
	}
}

// RequireAllGroups passes only if the claims contain EVERY named group (logical
// AND) — for tools that want an intersection (e.g. "platform" AND "on-call").
// Provided for completeness; most tools want RequireAnyGroup.
//
// Zero groups = deny-all, the SAME as RequireAnyGroup, and this is an EXPLICIT
// guard, not the natural behavior: a naive All-loop over an empty slice returns
// nil (vacuous truth) and would fail OPEN, admitting every authenticated user.
// The len(groups)==0 short-circuit below is what prevents that.
func RequireAllGroups(groups ...string) Authorizer {
	return func(c *Claims) error {
		if len(groups) == 0 {
			return fmt.Errorf("not authorized: no groups configured (deny-all)")
		}
		for _, g := range groups {
			if !c.HasGroup(g) {
				return fmt.Errorf("not authorized: requires membership in all of %v", groups)
			}
		}
		return nil
	}
}
