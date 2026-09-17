package beyond

import (
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Identity is the verified user identity derived from an OIDC id_token.
// It is the single source of truth used throughout beyond — for session
// storage, authorization checks, access logging, and the identity headers
// injected onto proxied requests. Instances are only ever created through
// validateAndNormalizeIdentity, which enforces the invariants documented
// on each field.
//
// Invariants guaranteed by the constructor:
//
//   - Email is non-empty, contains '@', fits in maxEmailLen bytes, and
//     contains no ASCII control characters. It is safe to use as an HTTP
//     header value and as a stable user identifier.
//   - Name is at most maxNameLen bytes, truncated at a rune boundary, and
//     contains no ASCII control characters. It may be empty when the IdP
//     provided neither `name`, `preferred_username`, nor an email with a
//     local-part to fall back to.
//   - Groups contains at most maxGroups entries; each entry is at most
//     maxGroupLen bytes (truncated at a rune boundary), contains no ASCII
//     control characters, and does not contain the '|' character that
//     beyond uses as the X-Beyond-Groups delimiter.
type Identity struct {
	Email  string
	Name   string
	Groups []string
}

// Identity validation limits.
//
// These caps defend against three concrete failure modes:
//
//  1. Browser-cookie size. Browsers drop cookies larger than ~4096 bytes.
//     A pathological name or group list could otherwise silently invalidate
//     the user's session.
//  2. HTTP-header validity. Go's net/http transport rejects requests whose
//     header values contain ASCII control characters (< 0x20 except tab, or
//     0x7F), producing opaque 502s. We reject these at login instead.
//  3. Log-line width. Truncating early keeps individual log lines bounded
//     even if an IdP misbehaves. (Note: truncation bounds VALUE WIDTH, not
//     metric-label CARDINALITY — which is why user identity is never a
//     Prometheus label; per-user data lives in bounded ClickHouse rows.)
//
// Values are chosen generously — a real human name easily fits in 256
// bytes, RFC 5321 caps email at 254 bytes, 128 bytes is far more than any
// realistic group name, and no organisation has 256 distinct groups per
// user that any app needs to know about.
const (
	maxEmailLen = 254 // RFC 5321 §4.5.3.1.3
	maxNameLen  = 256
	maxGroupLen = 128
	maxGroups   = 256

	// groupDelimiter separates group names in the X-Beyond-Groups header.
	// A literal '|' inside any group name would break this framing, so
	// validateAndNormalizeIdentity rejects group names containing it.
	groupDelimiter = "|"
)

// Identity-header names. Centralising these constants makes it obvious
// which headers beyond owns and keeps the Handler's strip loop in sync
// with the proxy's injection loop — adding a new header requires changes
// in exactly one place.
const (
	headerBeyondUser   = "X-Beyond-User"
	headerBeyondEmail  = "X-Beyond-Email"
	headerBeyondName   = "X-Beyond-Name"
	headerBeyondGroups = "X-Beyond-Groups"

	// beyondHeaderPrefix is the (case-insensitive) prefix used to detect
	// and strip any inbound identity headers before we inject our own.
	// Any header whose lowercased name starts with this prefix is removed.
	beyondHeaderPrefix = "x-beyond-"
)

// validateAndNormalizeIdentity takes the raw claim values extracted from an
// OIDC id_token and returns a clean Identity, or an error describing the
// first invariant violated.
//
// The function is deliberately strict on two things and lenient on a third:
//
//   - Strict: ASCII control characters anywhere, and '|' in group names.
//     These are signs of a misconfigured or malicious IdP; we prefer to
//     fail the login clearly than to produce opaque 502s later when Go's
//     transport rejects the outgoing identity header.
//   - Strict: missing / malformed email. Email is beyond's stable user
//     identifier, and "no identifier" is never a usable state.
//   - Lenient: over-length strings and over-long group lists. These get
//     truncated (at rune boundaries, so UTF-8 stays well-formed), because
//     locking a user out over a too-long display name is worse than
//     showing a shortened one.
//
// The display-name resolution (fallback from `name` → `preferred_username`
// → email local-part) is applied *after* validation of all three inputs,
// so a control character in `preferred_username` fails the login even
// when we would have used `name`. This is intentional: a malformed claim
// is a signal worth surfacing, regardless of whether we were going to
// use it.
func validateAndNormalizeIdentity(email, name, preferredUsername string, groups []string) (*Identity, error) {
	// Email: required, strictly validated. Failures here are hard
	// rejections because without a stable identifier nothing downstream
	// works correctly.
	if email == "" {
		return nil, fmt.Errorf("oidc: email claim is missing")
	}
	if len(email) > maxEmailLen {
		return nil, fmt.Errorf("oidc: email claim exceeds %d bytes", maxEmailLen)
	}
	if containsCtrl(email) {
		return nil, fmt.Errorf("oidc: email claim contains control characters")
	}
	// Cheap structural check — we don't try to implement RFC 5322, just
	// to reject obvious garbage like empty-local-part or no-'@' values.
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return nil, fmt.Errorf("oidc: email claim %q is not a valid address", email)
	}

	// Name & preferred_username: control-char reject, length truncate.
	// Validate before truncating so a long name with control characters
	// fails loudly instead of being truncated into something that happens
	// to be clean.
	if containsCtrl(name) {
		return nil, fmt.Errorf("oidc: name claim contains control characters")
	}
	if containsCtrl(preferredUsername) {
		return nil, fmt.Errorf("oidc: preferred_username claim contains control characters")
	}
	// Strip Unicode bidirectional/RTL override characters. These are invisible
	// but reorder surrounding text when rendered, so they let a crafted display
	// name spoof another identity in any audit-log viewer or admin UI that
	// renders X-Beyond-Name (e.g. "alice‮evil" rendering as "alicelive").
	// We strip (lenient) rather than reject so a legitimate name is never a
	// login failure; the chars carry no legitimate meaning in a display name.
	name = stripBidi(truncateAtRune(name, maxNameLen))
	preferredUsername = stripBidi(truncateAtRune(preferredUsername, maxNameLen))

	// Groups: trim to max count, validate+truncate each entry.
	if len(groups) > maxGroups {
		groups = groups[:maxGroups]
	}
	cleanGroups := make([]string, 0, len(groups))
	for i, g := range groups {
		if containsCtrl(g) {
			return nil, fmt.Errorf("oidc: group index %d contains control characters", i)
		}
		if strings.Contains(g, groupDelimiter) {
			return nil, fmt.Errorf("oidc: group index %d contains delimiter %q", i, groupDelimiter)
		}
		cleanGroups = append(cleanGroups, truncateAtRune(g, maxGroupLen))
	}

	return &Identity{
		Email:  email,
		Name:   resolveDisplayName(name, preferredUsername, email),
		Groups: cleanGroups,
	}, nil
}

// sanitizeGroups makes a group-name slice safe to use as an X-Beyond-Groups
// header value and as policy-match keys, applying the SAME caps as
// validateAndNormalizeIdentity but LENIENTLY: invalid entries (control chars
// or the '|' delimiter) are dropped rather than failing the request, and the
// list is capped at maxGroups. It is used for groups re-resolved from the
// Authentik API mid-session (which never passed through the strict login-time
// validation). Dropping a malformed group only ever removes access (the group
// can't match policy), never grants it, so leniency here is safe.
func sanitizeGroups(groups []string) []string {
	if len(groups) > maxGroups {
		groups = groups[:maxGroups]
	}
	clean := make([]string, 0, len(groups))
	for _, g := range groups {
		if g == "" || containsCtrl(g) || strings.Contains(g, groupDelimiter) {
			continue
		}
		clean = append(clean, truncateAtRune(g, maxGroupLen))
	}
	return clean
}

// resolveDisplayName picks a human-readable display name from the available
// claims. Called only after all three inputs have been validated, so it
// does not need to worry about control characters or over-long strings.
//
// Fallback order:
//
//  1. `name` — the standard OIDC "Full Name" claim.
//  2. `preferred_username` — set by many IdPs (including Authentik) when
//     `name` is empty.
//  3. email local-part — last-ditch fallback so downstream apps always
//     have *something* human-readable to display. Requires a non-leading
//     '@' in the email; otherwise we return the whole email unchanged
//     (which, by the constructor's email validation, is at least known to
//     be well-formed).
//
// Returns "" only in the impossible case where email has no '@' *and*
// both name claims are empty — which validateAndNormalizeIdentity rules
// out upstream.
func resolveDisplayName(name, preferredUsername, email string) string {
	if name != "" {
		return name
	}
	if preferredUsername != "" {
		return preferredUsername
	}
	if idx := strings.IndexByte(email, '@'); idx > 0 {
		return email[:idx]
	}
	return email
}

// isBidiControl reports whether r is a Unicode bidirectional formatting /
// override code point. These are invisible but reorder rendered text, enabling
// display-name spoofing. The set covers the explicit directional formatting
// and isolate characters plus the standalone marks:
//
//	U+200E LRM, U+200F RLM, U+061C ALM,
//	U+202A..U+202E (LRE RLE PDF LRO RLO),
//	U+2066..U+2069 (LRI RLI FSI PDI).
func isBidiControl(r rune) bool {
	switch r {
	case 0x200E, 0x200F, 0x061C: // LRM, RLM, ALM
		return true
	}
	return (r >= 0x202A && r <= 0x202E) || // LRE RLE PDF LRO RLO
		(r >= 0x2066 && r <= 0x2069) // LRI RLI FSI PDI
}

// stripBidi removes all Unicode bidi/RTL control characters from s. Returns s
// unchanged when it contains none (the common case), avoiding an allocation.
func stripBidi(s string) string {
	hasBidi := false
	for _, r := range s {
		if isBidiControl(r) {
			hasBidi = true
			break
		}
	}
	if !hasBidi {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isBidiControl(r) {
			return -1 // drop
		}
		return r
	}, s)
}

// containsCtrl reports whether s contains any ASCII control character —
// bytes in the range 0x00–0x1F or 0x7F (DEL). Tab (0x09) is included in
// the reject set: it is syntactically valid in HTTP header values per
// RFC 7230, but has no legitimate place inside an email, display name,
// or group identifier, and its presence is a reliable signal of an
// injection attempt or a broken IdP.
//
// The check operates on bytes, not runes, because the specific threat
// (HTTP header-value validation, log-line injection) is byte-oriented:
// a '\n' byte inside a multi-byte UTF-8 sequence is still a '\n' to
// every consumer of the string.
func containsCtrl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// truncateAtRune returns s capped at maxBytes, backing up to the nearest
// UTF-8 rune start boundary so that the result is always well-formed
// UTF-8 (never ends mid-multi-byte-sequence).
//
// Input that is already ≤ maxBytes is returned unchanged.
func truncateAtRune(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Walk back from maxBytes until we find a rune-start byte. utf8.RuneStart
	// returns true for any byte that begins a rune (either ASCII or the
	// leading byte of a multi-byte sequence). Continuation bytes (0b10xxxxxx)
	// return false.
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// injectBeyondHeaders strips any X-Beyond-* headers and replaces them with
// the caller-verified identity headers, in that order.
//
// It is called from the ReverseProxy Rewrite hook against the OUTBOUND
// request (pr.Out), which the stdlib has already run through
// removeHopByHopHeaders. That placement is load-bearing: injecting onto the
// inbound request instead would let a client erase the headers we set by
// naming them in a `Connection:` token list (the stdlib deletes
// Connection-listed headers from the outbound request before this hook runs).
//
// Two properties are enforced here:
//
//  1. Anti-spoofing. A client cannot smuggle identity headers through beyond
//     by setting X-Beyond-* themselves; the strip loop clears the whole
//     namespace before we inject anything.
//  2. Empty-value suppression. Fields that happen to be empty (notably
//     X-Beyond-Name on legacy sessions issued before the Name field was
//     added) are not written at all, rather than written as empty
//     headers. This keeps the semantics consistent: "no header present"
//     and "empty header present" look identical to downstream code, but
//     some downstreams treat an empty header as a signal to overwrite
//     stored values (Grafana's auth.proxy is one such downstream).
//
// Pairs with beyondHeaderPrefix / headerBeyondUser / etc. so that adding
// a new identity header requires only one place to change.
func injectBeyondHeaders(r *http.Request, identity *Identity) {
	// Strip anything that looks like an identity header on the inbound
	// request. Iterating a copy is unnecessary because deletion during
	// a range over an http.Header (which is a map) is legal in Go.
	for key := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), beyondHeaderPrefix) {
			delete(r.Header, key)
		}
	}

	setHeaderIfNonEmpty(r.Header, headerBeyondUser, identity.Email)
	setHeaderIfNonEmpty(r.Header, headerBeyondEmail, identity.Email)
	setHeaderIfNonEmpty(r.Header, headerBeyondName, identity.Name)
	setHeaderIfNonEmpty(r.Header, headerBeyondGroups, strings.Join(identity.Groups, groupDelimiter))
}

// setHeaderIfNonEmpty sets h[key] = value only if value is non-empty. See
// injectBeyondHeaders for the rationale on why empty values are suppressed
// rather than set as blank headers.
func setHeaderIfNonEmpty(h http.Header, key, value string) {
	if value == "" {
		return
	}
	h.Set(key, value)
}
