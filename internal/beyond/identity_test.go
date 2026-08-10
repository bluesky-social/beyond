package beyond

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// validateAndNormalizeIdentity
// ---------------------------------------------------------------------------

func TestValidateAndNormalizeIdentity_AcceptsValidClaims(t *testing.T) {
	t.Parallel()

	id, err := validateAndNormalizeIdentity(
		"alice@example.com",
		"Alice Example",
		"alice",
		[]string{"engineering", "platform"},
	)
	require.NoError(t, err)
	require.NotNil(t, id)

	assert.Equal(t, "alice@example.com", id.Email)
	assert.Equal(t, "Alice Example", id.Name)
	assert.Equal(t, []string{"engineering", "platform"}, id.Groups)
}

func TestValidateAndNormalizeIdentity_Email(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		email   string
		wantErr string
	}{
		{"missing", "", "missing"},
		{"no @", "alice-example.com", "not a valid address"},
		{"leading @", "@example.com", "not a valid address"},
		{"trailing @", "alice@", "not a valid address"},
		{"over max length", strings.Repeat("a", maxEmailLen-10) + "@example.com", "exceeds"},
		{"control character (CR)", "alice\r@example.com", "control characters"},
		{"control character (LF)", "alice\n@example.com", "control characters"},
		{"control character (NUL)", "alice\x00@example.com", "control characters"},
		{"control character (DEL)", "alice\x7f@example.com", "control characters"},
		{"control character (tab)", "alice\t@example.com", "control characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateAndNormalizeIdentity(tt.email, "Alice", "", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateAndNormalizeIdentity_Name_RejectsControlCharacters(t *testing.T) {
	t.Parallel()
	// Any ASCII control character in name or preferred_username must cause
	// a hard login failure, not a silent strip. See the commentary on
	// containsCtrl for why — CRLF-laden headers cause opaque 502s at Go's
	// transport layer, and we'd rather surface the failure at login.
	cases := []struct {
		name              string
		nameClaim         string
		preferredUsername string
		wantErr           string
	}{
		{"CR in name", "Alice\r", "", "name claim"},
		{"LF in name", "Alice\n", "", "name claim"},
		{"CRLF in name", "Alice\r\nX-Injected: yes", "", "name claim"},
		{"NUL in name", "Alice\x00", "", "name claim"},
		{"DEL in name", "Alice\x7f", "", "name claim"},
		{"tab in name", "Alice\tBob", "", "name claim"},
		{"CR in preferred_username", "", "alice\r", "preferred_username"},
		{"LF in preferred_username", "", "alice\n", "preferred_username"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateAndNormalizeIdentity(
				"alice@example.com", tt.nameClaim, tt.preferredUsername, nil,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateAndNormalizeIdentity_Name_TruncatesWhenTooLong(t *testing.T) {
	t.Parallel()
	// Over-long names are truncated, not rejected: display names are
	// cosmetic, and locking a user out over an IdP attribute they may
	// not even control is worse than shortening it.
	long := strings.Repeat("a", maxNameLen+100)
	id, err := validateAndNormalizeIdentity("alice@example.com", long, "", nil)
	require.NoError(t, err)
	assert.Len(t, id.Name, maxNameLen, "name must be truncated to maxNameLen")
	// Every byte must still be the original character, not garbage.
	assert.Equal(t, strings.Repeat("a", maxNameLen), id.Name)
}

// TestValidateAndNormalizeIdentity_Name_StripsBidi is the L-11 regression test:
// Unicode bidi/RTL override characters must be stripped from the display name
// so they can't reorder rendered text in audit-log viewers or admin UIs.
func TestValidateAndNormalizeIdentity_Name_StripsBidi(t *testing.T) {
	t.Parallel()
	const rlo = "\u202E" // RIGHT-TO-LEFT OVERRIDE
	const pdf = "\u202C" // POP DIRECTIONAL FORMATTING
	const rlm = "\u200F" // RIGHT-TO-LEFT MARK

	id, err := validateAndNormalizeIdentity("alice@example.com", "Alice"+rlo+"evil"+pdf+rlm, "", nil)
	require.NoError(t, err, "bidi chars are stripped, not rejected")
	assert.Equal(t, "Aliceevil", id.Name, "all bidi/RTL control chars must be stripped from the name")

	// A clean name is returned unchanged (and not re-allocated unnecessarily).
	id2, err := validateAndNormalizeIdentity("bob@example.com", "Bob Plain", "", nil)
	require.NoError(t, err)
	assert.Equal(t, "Bob Plain", id2.Name)

	// stripBidi covers the isolate range too (U+2066 LRI, U+2069 PDI).
	assert.Equal(t, "ab", stripBidi("a\u2066\u2069b"))
}

func TestValidateAndNormalizeIdentity_Name_TruncationPreservesUTF8(t *testing.T) {
	t.Parallel()
	// Build a string whose byte length is exactly maxNameLen+1 but whose
	// final multi-byte rune straddles the cutoff, so naive byte-slicing
	// would produce invalid UTF-8. The truncator must back up to the
	// previous rune start and return well-formed UTF-8.
	//
	// "é" is 2 bytes in UTF-8 (0xC3 0xA9). We pad with ASCII up to a
	// position that forces the é to be split.
	padding := strings.Repeat("x", maxNameLen-1)
	input := padding + "é" + "y"
	require.Greater(t, len(input), maxNameLen)

	id, err := validateAndNormalizeIdentity("alice@example.com", input, "", nil)
	require.NoError(t, err)

	// Result must be strictly shorter than maxNameLen (we backed up past
	// the split rune) and must be valid UTF-8.
	assert.LessOrEqual(t, len(id.Name), maxNameLen)
	assert.Equal(t, padding, id.Name,
		"truncator must back up to the previous rune boundary, yielding the padding only")
}

func TestValidateAndNormalizeIdentity_DisplayNameFallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		nameClaim         string
		preferredUsername string
		email             string
		want              string
	}{
		{"prefers name", "Alice Example", "alice", "alice@example.com", "Alice Example"},
		{"falls back to preferred_username", "", "alice", "alice@example.com", "alice"},
		{"falls back to email local-part", "", "", "alice@example.com", "alice"},
		{"dotted local-part", "", "", "alice.example@example.com", "alice.example"},
		// Leading '@' can't actually reach this path because the email
		// validator rejects it; tested separately in the Email matrix.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, err := validateAndNormalizeIdentity(tt.email, tt.nameClaim, tt.preferredUsername, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, id.Name)
		})
	}
}

// resolveDisplayName is only called after email validation has enforced
// that email contains a non-leading '@', but we still test the unhappy
// path directly to pin the documented behaviour against regressions.
func TestResolveDisplayName_DirectUnitTest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		claimName         string
		preferredUsername string
		email             string
		want              string
	}{
		{"prefers name", "Alice Example", "alice", "alice@example.com", "Alice Example"},
		{"falls back to preferred_username", "", "alice", "alice@example.com", "alice"},
		{"falls back to email local-part", "", "", "alice@example.com", "alice"},
		{"leading @ in email returns whole email", "", "", "@example.com", "@example.com"},
		{"uses whole email when no @", "", "", "alice", "alice"},
		{"empty all around", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolveDisplayName(tt.claimName, tt.preferredUsername, tt.email)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateAndNormalizeIdentity_Groups_RejectsControlChars(t *testing.T) {
	t.Parallel()
	_, err := validateAndNormalizeIdentity(
		"alice@example.com", "Alice", "",
		[]string{"engineering", "plat\nform"},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group index 1")
	assert.Contains(t, err.Error(), "control characters")
}

func TestValidateAndNormalizeIdentity_Groups_RejectsDelimiter(t *testing.T) {
	t.Parallel()
	// A '|' in a group name would destroy the X-Beyond-Groups framing
	// and allow one claimed group to be parsed as two by the downstream.
	_, err := validateAndNormalizeIdentity(
		"alice@example.com", "Alice", "",
		[]string{"engineering", "platform|extra"},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group index 1")
	assert.Contains(t, err.Error(), "delimiter")
}

func TestValidateAndNormalizeIdentity_Groups_TruncatesCount(t *testing.T) {
	t.Parallel()
	// Build an over-long groups list and assert we get only the first
	// maxGroups entries through.
	groups := make([]string, maxGroups+50)
	for i := range groups {
		groups[i] = "group"
	}

	id, err := validateAndNormalizeIdentity("alice@example.com", "Alice", "", groups)
	require.NoError(t, err)
	assert.Len(t, id.Groups, maxGroups)
}

func TestValidateAndNormalizeIdentity_Groups_TruncatesEachEntry(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("g", maxGroupLen+100)
	id, err := validateAndNormalizeIdentity(
		"alice@example.com", "Alice", "",
		[]string{long, "short"},
	)
	require.NoError(t, err)
	require.Len(t, id.Groups, 2)
	assert.Len(t, id.Groups[0], maxGroupLen, "first group must be truncated")
	assert.Equal(t, "short", id.Groups[1], "short group must be preserved")
}

func TestValidateAndNormalizeIdentity_Groups_NilIsAllowed(t *testing.T) {
	t.Parallel()
	id, err := validateAndNormalizeIdentity("alice@example.com", "Alice", "", nil)
	require.NoError(t, err)
	assert.NotNil(t, id.Groups, "Groups must be non-nil (may be empty)")
	assert.Empty(t, id.Groups)
}

// ---------------------------------------------------------------------------
// containsCtrl
// ---------------------------------------------------------------------------

func TestContainsCtrl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain ASCII", "hello", false},
		{"UTF-8 multibyte", "Alice Éxample 日本語", false},
		{"space ok", "hello world", false},
		{"leading NUL", "\x00hello", true},
		{"embedded CR", "hi\rthere", true},
		{"embedded LF", "hi\nthere", true},
		{"trailing tab", "hi\t", true},
		{"DEL", "hi\x7f", true},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, containsCtrl(tt.in))
		})
	}
}

// ---------------------------------------------------------------------------
// truncateAtRune
// ---------------------------------------------------------------------------

func TestTruncateAtRune(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		maxBytes int
		want     string
	}{
		{"short unchanged", "hello", 10, "hello"},
		{"exact fit unchanged", "hello", 5, "hello"},
		{"ASCII over limit", "helloworld", 5, "hello"},
		{"empty", "", 10, ""},
		// The 2-byte "é" starts at the last position and would be split
		// by a naive byte-slice at maxBytes=7. Truncator must back up to
		// the previous rune boundary, yielding "hello w".
		{"multibyte split mid-rune", "hello wé", 8, "hello w"},
		// Here "é" fits entirely within the limit.
		{"multibyte fits exactly", "helloé", 7, "helloé"},
		{"multibyte fits under limit", "héllo", 10, "héllo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncateAtRune(tt.input, tt.maxBytes)
			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, len(got), tt.maxBytes)
		})
	}
}

// ---------------------------------------------------------------------------
// injectBeyondHeaders
// ---------------------------------------------------------------------------

func TestInjectBeyondHeaders_SetsAllHeadersForFullIdentity(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	injectBeyondHeaders(r, &Identity{
		Email:  "alice@example.com",
		Name:   "Alice Example",
		Groups: []string{"engineering", "platform"},
	})
	assert.Equal(t, "alice@example.com", r.Header.Get(headerBeyondUser))
	assert.Equal(t, "alice@example.com", r.Header.Get(headerBeyondEmail))
	assert.Equal(t, "Alice Example", r.Header.Get(headerBeyondName))
	assert.Equal(t, "engineering|platform", r.Header.Get(headerBeyondGroups))
}

func TestInjectBeyondHeaders_SkipsEmptyName(t *testing.T) {
	t.Parallel()
	// A legacy session (from before the Name field existed) decrypts
	// with Name="". We must NOT send a blank X-Beyond-Name — downstreams
	// using sync_ttl to periodically refresh the user record would
	// otherwise overwrite the stored display name with "".
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	injectBeyondHeaders(r, &Identity{
		Email:  "alice@example.com",
		Name:   "",
		Groups: []string{"engineering"},
	})
	_, present := r.Header[headerBeyondName]
	assert.False(t, present, "X-Beyond-Name must be absent when Name is empty")
}

func TestInjectBeyondHeaders_SkipsEmptyGroups(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	injectBeyondHeaders(r, &Identity{
		Email:  "alice@example.com",
		Name:   "Alice",
		Groups: nil,
	})
	_, present := r.Header[headerBeyondGroups]
	assert.False(t, present, "X-Beyond-Groups must be absent when Groups is empty")
}

func TestInjectBeyondHeaders_StripsIncomingBeyondHeaders(t *testing.T) {
	t.Parallel()
	// Even headers that beyond doesn't itself emit (e.g. X-Beyond-Admin
	// that some future version might add) must be stripped, because an
	// attacker could otherwise pre-seed claims we don't yet validate.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Beyond-User", "attacker@evil.com")
	r.Header.Set("X-Beyond-Email", "attacker@evil.com")
	r.Header.Set("X-Beyond-Name", "Attacker Evil")
	r.Header.Set("X-Beyond-Groups", "authentik Admins")
	r.Header.Set("X-Beyond-Admin", "true")        // forward-looking
	r.Header.Set("x-beyond-lowercase", "spoofed") // case-insensitive strip

	injectBeyondHeaders(r, &Identity{
		Email:  "real@example.com",
		Name:   "Real User",
		Groups: []string{"engineering"},
	})

	assert.Equal(t, "real@example.com", r.Header.Get("X-Beyond-User"))
	assert.Equal(t, "real@example.com", r.Header.Get("X-Beyond-Email"))
	assert.Equal(t, "Real User", r.Header.Get("X-Beyond-Name"))
	assert.Equal(t, "engineering", r.Header.Get("X-Beyond-Groups"))

	// The pre-existing non-canonical headers must have been wiped.
	_, present := r.Header["X-Beyond-Admin"]
	assert.False(t, present, "forward-looking X-Beyond-Admin must be stripped")
	_, present = r.Header["X-Beyond-Lowercase"]
	assert.False(t, present, "lowercase X-Beyond-* must be stripped case-insensitively")
}

func TestInjectBeyondHeaders_EmptyIdentityLeavesRequestEmpty(t *testing.T) {
	t.Parallel()
	// Pathological: no email, no name, no groups. Upstream should see
	// no identity headers at all rather than blanks that imply identity.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	injectBeyondHeaders(r, &Identity{})
	for key := range r.Header {
		assert.False(t, strings.HasPrefix(strings.ToLower(key), beyondHeaderPrefix),
			"no X-Beyond-* header should be set for an empty identity (got %q)", key)
	}
}
