package tokenverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TestVerifier_SplitHorizonRoundTrip is the real-crypto proof of the
// split-horizon design: the verifier is told the issuer is one host (as a
// laptop-issued token would carry), but fetches the JWKS from a DIFFERENT host
// (an httptest server standing in for the in-cluster Authentik service). A
// token signed by that key, with that issuer/audience, must verify; tokens
// with the wrong issuer, wrong audience, or expired must not.
//
// This is what would catch a regression where issuer and JWKS-URL got
// recoupled (e.g. reverting to oidc.NewProvider), which is the exact mistake
// the in-cluster deploy must avoid.
func TestVerifier_SplitHorizonRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key-1"
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}

	// JWKS server — a DIFFERENT host than the issuer string below.
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksSrv.Close()

	const (
		issuer   = "https://auth.example.com/application/o/some-app/"
		audience = "test-client-id"
	)
	// Verifier: issuer is the public-host string; keys come from jwksSrv.URL.
	v := New(context.Background(), issuer, jwksSrv.URL, audience)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}

	mint := func(iss, aud string, exp time.Time, groups []string) string {
		claims := map[string]any{
			"iss":    iss,
			"aud":    aud,
			"sub":    "op-1",
			"exp":    exp.Unix(),
			"iat":    time.Now().Add(-time.Minute).Unix(),
			"groups": groups,
		}
		s, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("valid token verifies and carries groups", func(t *testing.T) {
		tok := mint(issuer, audience, time.Now().Add(time.Hour), []string{"platform"})
		claims, err := v.Verify(context.Background(), tok)
		if err != nil {
			t.Fatalf("expected valid token to verify: %v", err)
		}
		if claims.Subject != "op-1" || !claims.HasGroup("platform") {
			t.Errorf("claims = %+v", claims)
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		tok := mint("https://evil.example/", audience, time.Now().Add(time.Hour), []string{"platform"})
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Error("expected wrong-issuer token to be rejected")
		}
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		tok := mint(issuer, "some-other-client", time.Now().Add(time.Hour), []string{"platform"})
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Error("expected wrong-audience token to be rejected")
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		tok := mint(issuer, audience, time.Now().Add(-time.Hour), []string{"platform"})
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Error("expected expired token to be rejected")
		}
	})

	// Algorithm confinement: the verifier must pin RS256 (from the JWKS key's
	// declared alg) and reject algorithm-substitution attacks. These close the
	// alg=none / RS256<->HS256 confusion testing gap.
	t.Run("alg=none rejected", func(t *testing.T) {
		// Hand-craft an unsigned ("alg":"none") JWT with an empty signature
		// segment and otherwise-valid claims. go-jose won't mint these, so we
		// assemble the compact serialization directly.
		b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
		hdr := b64([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := b64(fmt.Appendf(nil,
			`{"iss":%q,"aud":%q,"sub":"op-1","exp":%d,"iat":%d}`,
			issuer, audience, time.Now().Add(time.Hour).Unix(), time.Now().Add(-time.Minute).Unix()))
		unsigned := hdr + "." + payload + "."
		if _, err := v.Verify(context.Background(), unsigned); err == nil {
			t.Error("expected alg=none token to be rejected")
		}
	})

	t.Run("HS256 key-confusion rejected", func(t *testing.T) {
		// Classic RS256->HS256 confusion: sign with HMAC using the RSA public
		// key material as the secret. A verifier that doesn't pin the alg
		// would validate this against the public key.
		pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		hmacSigner, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.HS256, Key: pubDER},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
		)
		if err != nil {
			t.Fatalf("building HS256 signer: %v", err)
		}
		tok, err := jwt.Signed(hmacSigner).Claims(map[string]any{
			"iss": issuer, "aud": audience, "sub": "op-1",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Add(-time.Minute).Unix(),
		}).Serialize()
		if err != nil {
			t.Fatalf("minting HS256 token: %v", err)
		}
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Error("expected HS256 key-confusion token to be rejected")
		}
	})
}

func TestRequireAnyGroup(t *testing.T) {
	c := &Claims{Groups: []string{"authentik Admins", "platform"}}

	// any-of: platform matches even though engineering doesn't
	if err := RequireAnyGroup("engineering", "platform")(c); err != nil {
		t.Errorf("any-of(engineering,platform) should pass for a platform member: %v", err)
	}
	// no overlap → deny
	if err := RequireAnyGroup("data-science")(c); err == nil {
		t.Error("any-of(data-science) should deny a non-member")
	}
	// CRITICAL: zero groups must deny-all, never allow
	if err := RequireAnyGroup()(c); err == nil {
		t.Error("RequireAnyGroup() with zero groups must deny-all")
	}
}

func TestRequireAllGroups(t *testing.T) {
	c := &Claims{Groups: []string{"platform", "on-call"}}

	if err := RequireAllGroups("platform", "on-call")(c); err != nil {
		t.Errorf("all-of should pass when claims contain every group: %v", err)
	}
	// missing one → deny
	if err := RequireAllGroups("platform", "secops")(c); err == nil {
		t.Error("all-of should deny when a required group is missing")
	}
	// CRITICAL: zero groups must deny-all (NOT vacuous-truth allow)
	if err := RequireAllGroups()(c); err == nil {
		t.Error("RequireAllGroups() with zero groups must deny-all (fail-closed)")
	}
}

func TestHasGroupOrderIndependent(t *testing.T) {
	c := &Claims{Groups: []string{"a", "b", "c"}}
	for _, g := range []string{"a", "b", "c"} {
		if !c.HasGroup(g) {
			t.Errorf("HasGroup(%q) = false, want true", g)
		}
	}
	if c.HasGroup("d") {
		t.Error("HasGroup(d) = true, want false")
	}
}
