package beyond

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSessionManager returns a SessionManager with a fixed 32-byte key and a
// 1-hour lifetime, suitable for use in tests.
func testSessionManager(t *testing.T) *SessionManager {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	sm, err := NewSessionManager([][]byte{key}, time.Hour)
	require.NoError(t, err)
	return sm
}

// cookieFromRecorder returns the named Set-Cookie header value recorded by w.
func cookieFromRecorder(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	resp := w.Result()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSessionManager_RoundTrip(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	original := &SessionData{
		Email:     "alice@example.com",
		Name:      "Alice Example",
		Groups:    []string{"engineering", "platform"},
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}

	// Save the session to a response recorder.
	w := httptest.NewRecorder()
	require.NoError(t, sm.Save(w, original))

	cookie := cookieFromRecorder(t, w, sessionCookieName)
	require.NotNil(t, cookie, "expected Set-Cookie header for %q", sessionCookieName)

	// Cookie security attributes.
	assert.Equal(t, sessionCookieName, cookie.Name)
	assert.True(t, cookie.HttpOnly, "cookie must be HttpOnly")
	assert.True(t, cookie.Secure, "cookie must be Secure")
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)

	// Load the session from a synthesised request carrying that cookie.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	loaded, err := sm.Load(req)
	require.NoError(t, err)
	require.NotNil(t, loaded, "expected a loaded session")

	assert.Equal(t, original.Email, loaded.Email)
	assert.Equal(t, original.Name, loaded.Name, "Name must round-trip through the session cookie")
	assert.Equal(t, original.Groups, loaded.Groups)
	assert.WithinDuration(t, original.ExpiresAt, loaded.ExpiresAt, time.Second)
}

// TestSessionManager_LegacySessionWithoutName_Decodes verifies that
// sessions encrypted before the Name field was added to SessionData
// continue to decode cleanly after the field is added. This is the
// guarantee that lets us ship the Name change without invalidating
// every active session at deploy time — the JSON unmarshal treats a
// missing `name` key as Name="", which flows through the rest of the
// code path unchanged (and, per injectBeyondHeaders, suppresses the
// X-Beyond-Name header entirely).
func TestSessionManager_LegacySessionWithoutName_Decodes(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	// Encrypt a JSON blob that looks exactly like a pre-Name-field
	// session cookie: {email, groups, expires_at, type}. This is the
	// literal shape produced by an older beyond binary before the
	// `name` field was added to SessionData.
	legacy := []byte(`{
		"email": "legacy@example.com",
		"groups": ["engineering"],
		"expires_at": "` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano) + `",
		"type": "cookie"
	}`)

	nonce := make([]byte, sm.primary.NonceSize())
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	ciphertext := sm.primary.Seal(nonce, nonce, legacy, nil)
	cookieValue := base64.RawURLEncoding.EncodeToString(ciphertext)

	// Now load it via the public Load path, which is what a real
	// in-flight request would go through.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieValue})

	loaded, err := sm.Load(req)
	require.NoError(t, err)
	require.NotNil(t, loaded, "legacy cookie must decode cleanly")

	assert.Equal(t, "legacy@example.com", loaded.Email)
	assert.Equal(t, []string{"engineering"}, loaded.Groups)
	assert.Equal(t, "", loaded.Name, "missing `name` key must leave Name empty")
}

func TestSessionManager_Expired(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	data := &SessionData{
		Email:     "bob@example.com",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(-time.Minute), // already in the past
	}

	w := httptest.NewRecorder()
	require.NoError(t, sm.Save(w, data))

	cookie := cookieFromRecorder(t, w, sessionCookieName)
	require.NotNil(t, cookie)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	loaded, err := sm.Load(req)
	assert.NoError(t, err)
	assert.Nil(t, loaded, "expired session should return nil")
}

func TestSessionManager_NoCookie(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Deliberately no cookie.

	loaded, err := sm.Load(req)
	assert.NoError(t, err)
	assert.Nil(t, loaded, "missing cookie should return nil")
}

func TestSessionManager_TamperedCookie(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "this-is-not-a-valid-encrypted-value!!!",
	})

	loaded, err := sm.Load(req)
	assert.NoError(t, err)
	assert.Nil(t, loaded, "tampered cookie should return nil")
}

func TestSessionManager_EncryptDecryptToken(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	original := &SessionData{
		Type:      tokenTypeOIDCState,
		Email:     "cli-user@example.com",
		Groups:    []string{"engineering", "platform"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Truncate(time.Second),
	}

	token, err := sm.EncryptToken(original)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Decrypt on the same manager.
	loaded, err := sm.DecryptTokenWithType(token, tokenTypeOIDCState)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, original.Email, loaded.Email)
	assert.Equal(t, original.Groups, loaded.Groups)

	// Decrypt on a different manager with the same key (simulates different pod).
	sm2 := testSessionManager(t)
	loaded2, err := sm2.DecryptTokenWithType(token, tokenTypeOIDCState)
	require.NoError(t, err)
	require.NotNil(t, loaded2, "token must be valid across manager instances with the same key")
	assert.Equal(t, original.Email, loaded2.Email)
}

func TestSessionManager_DecryptToken_Expired(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	token, err := sm.EncryptToken(&SessionData{
		Type:      tokenTypeOIDCState,
		Email:     "user@example.com",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)

	loaded, err := sm.DecryptTokenWithType(token, tokenTypeOIDCState)
	assert.NoError(t, err)
	assert.Nil(t, loaded, "expired token should return nil")
}

func TestSessionManager_DecryptToken_InvalidInput(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	loaded, err := sm.DecryptTokenWithType("not-a-valid-token!!!", tokenTypeOIDCState)
	assert.NoError(t, err)
	assert.Nil(t, loaded)

	// Different key cannot decrypt.
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(i + 100)
	}
	sm2, err := NewSessionManager([][]byte{otherKey}, time.Hour)
	require.NoError(t, err)

	token, err := sm.EncryptToken(&SessionData{
		Type:      tokenTypeOIDCState,
		Email:     "a@b.com", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	loaded, err = sm2.DecryptTokenWithType(token, tokenTypeOIDCState)
	assert.NoError(t, err)
	assert.Nil(t, loaded, "token encrypted with different key should return nil")
}

func TestSessionManager_KeyRotation(t *testing.T) {
	t.Parallel()
	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i + 1)
	}
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}

	// Encrypt with old key only.
	smOld, err := NewSessionManager([][]byte{oldKey}, time.Hour)
	require.NoError(t, err)
	token, err := smOld.EncryptToken(&SessionData{
		Type:      tokenTypeOIDCState,
		Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// Rotated manager: new key is primary, old key is kept for decryption.
	smRotated, err := NewSessionManager([][]byte{newKey, oldKey}, time.Hour)
	require.NoError(t, err)

	// Old token should still decrypt.
	data, err := smRotated.DecryptTokenWithType(token, tokenTypeOIDCState)
	require.NoError(t, err)
	require.NotNil(t, data)
	assert.Equal(t, "alice@example.com", data.Email)

	// New token encrypted by rotated manager should also decrypt.
	newToken, err := smRotated.EncryptToken(&SessionData{
		Type:      tokenTypeOIDCState,
		Email: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	data2, err := smRotated.DecryptTokenWithType(newToken, tokenTypeOIDCState)
	require.NoError(t, err)
	require.NotNil(t, data2)
	assert.Equal(t, "bob@example.com", data2.Email)

	// New token should NOT decrypt with old-key-only manager.
	data3, err := smOld.DecryptTokenWithType(newToken, tokenTypeOIDCState)
	assert.NoError(t, err)
	assert.Nil(t, data3, "new-key token should not decrypt with old-key-only manager")
}

func TestSessionManager_KeyRotation_Cookie(t *testing.T) {
	t.Parallel()
	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i + 1)
	}
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 50)
	}

	// Save a cookie with the old key.
	smOld, err := NewSessionManager([][]byte{oldKey}, time.Hour)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	require.NoError(t, smOld.Save(w, &SessionData{
		Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour),
	}))
	cookie := cookieFromRecorder(t, w, sessionCookieName)
	require.NotNil(t, cookie)

	// Rotated manager should be able to load the old cookie.
	smRotated, err := NewSessionManager([][]byte{newKey, oldKey}, time.Hour)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	loaded, err := smRotated.Load(req)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "alice@example.com", loaded.Email)
}

func TestSessionManager_KeyRotation_ThreeKeys(t *testing.T) {
	t.Parallel()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key3 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i + 1)
		key2[i] = byte(i + 50)
		key3[i] = byte(i + 100)
	}

	// Encrypt with key1.
	sm1, err := NewSessionManager([][]byte{key1}, time.Hour)
	require.NoError(t, err)
	token, err := sm1.EncryptToken(&SessionData{
		Type:      tokenTypeOIDCState,
		Email: "old@example.com", ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// Manager with key3 primary, key2 and key1 as old keys.
	smAll, err := NewSessionManager([][]byte{key3, key2, key1}, time.Hour)
	require.NoError(t, err)

	// Should still decrypt the key1-encrypted token.
	data, err := smAll.DecryptTokenWithType(token, tokenTypeOIDCState)
	require.NoError(t, err)
	require.NotNil(t, data)
	assert.Equal(t, "old@example.com", data.Email)
}

func TestNewSessionManager_NoKeys(t *testing.T) {
	t.Parallel()
	_, err := NewSessionManager([][]byte{}, time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one session key")
}

func TestNewSessionManager_WrongKeySize(t *testing.T) {
	t.Parallel()
	_, err := NewSessionManager([][]byte{make([]byte, 16)}, time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestSessionManager_Clear(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	w := httptest.NewRecorder()
	sm.Clear(w)

	cookie := cookieFromRecorder(t, w, sessionCookieName)
	require.NotNil(t, cookie, "expected Set-Cookie header for %q after Clear", sessionCookieName)
	assert.Equal(t, -1, cookie.MaxAge, "Clear must set MaxAge=-1 to expire the cookie")
}

func TestSessionManager_TokenTypeSeparation(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	// An OIDC-state token decrypts via DecryptTokenWithType(tokenTypeOIDCState).
	state, err := sm.EncryptToken(&SessionData{
		Type:      tokenTypeOIDCState,
		Email:     "user@example.com",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	loaded, err := sm.DecryptTokenWithType(state, tokenTypeOIDCState)
	require.NoError(t, err)
	require.NotNil(t, loaded, "oidc-state token must decrypt with its own type")
	assert.Equal(t, "user@example.com", loaded.Email)

	// An OIDC-state token must NOT be usable as a session cookie (cross-context
	// confusion guard).
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: state})
	fromCookie, err := sm.Load(req)
	assert.NoError(t, err)
	assert.Nil(t, fromCookie, "oidc-state token must not be accepted as a session cookie")

	// A session cookie must NOT be usable as an OIDC-state blob.
	w := httptest.NewRecorder()
	require.NoError(t, sm.Save(w, &SessionData{
		Email:     "user@example.com",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	cookieVal := cookieFromRecorder(t, w, sessionCookieName)
	require.NotNil(t, cookieVal)

	fromState, err := sm.DecryptTokenWithType(cookieVal.Value, tokenTypeOIDCState)
	assert.NoError(t, err)
	assert.Nil(t, fromState, "session cookie must not be accepted as an oidc-state blob")
}

func TestSessionManager_StrictTypeEnforcement(t *testing.T) {
	t.Parallel()
	sm := testSessionManager(t)

	// Create a token with no type field by encrypting raw JSON directly,
	// simulating a legacy token from before type enforcement.
	data := &SessionData{
		Email:     "user@example.com",
		Groups:    []string{"engineering"},
		ExpiresAt: time.Now().Add(time.Hour),
		// Type intentionally left empty.
	}
	plaintext, err := json.Marshal(data)
	require.NoError(t, err)

	nonce := make([]byte, sm.primary.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	ciphertext := sm.primary.Seal(nonce, nonce, plaintext, nil)
	token := base64.RawURLEncoding.EncodeToString(ciphertext)

	// Must be rejected by DecryptTokenWithType (expects oidc-state type).
	loaded, err := sm.DecryptTokenWithType(token, tokenTypeOIDCState)
	assert.NoError(t, err)
	assert.Nil(t, loaded, "token without type must be rejected")

	// Must be rejected by Load (expects "cookie" type).
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	fromCookie, err := sm.Load(req)
	assert.NoError(t, err)
	assert.Nil(t, fromCookie, "token without type must not be accepted as cookie")
}

// Compile-time interface checks for responseWriter.
var _ http.Hijacker = (*responseWriter)(nil)
var _ http.Flusher = (*responseWriter)(nil)
