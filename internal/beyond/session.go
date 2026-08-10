package beyond

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const sessionCookieName = "_beyond_session"

// Token type constants control which contexts a SessionData blob is valid in.
// Each encryption path stamps a type; each decryption path rejects mismatches.
const (
	tokenTypeCookie    = "cookie"     // browser session cookie
	tokenTypeOIDCState = "oidc"       // OIDC flow state cookie
	tokenTypeMintState = "mint_state" // app-password mint OIDC flow state cookie
	tokenTypeMintCSRF  = "mint_csrf"  // app-password mint confirmation-page CSRF token
)

// SessionData holds the authenticated user information stored inside
// encrypted cookies and bearer tokens.
type SessionData struct {
	Email     string    `json:"email"`
	Name      string    `json:"name,omitempty"`
	Groups    []string  `json:"groups"`
	ExpiresAt time.Time `json:"expires_at"`
	Type      string    `json:"type,omitempty"`

	// OIDC state fields (only populated when Type == tokenTypeOIDCState).
	OIDCState       string `json:"oidc_state,omitempty"`
	OIDCVerifier    string `json:"oidc_verifier,omitempty"`
	OIDCNonce       string `json:"oidc_nonce,omitempty"`
	OIDCOriginalURL string `json:"oidc_original_url,omitempty"`
	// MintPurpose carries the user-supplied purpose label through the OIDC
	// round-trip (only populated when Type == tokenTypeMintState). It is
	// human-bookkeeping only — it names the key in Authentik but does NOT
	// restrict which services the key works with.
	MintPurpose string `json:"mint_purpose,omitempty"`
}

// SessionManager encrypts and decrypts session cookies using AES-256-GCM.
// It supports key rotation: encryption always uses the primary (first) key,
// while decryption tries all keys. This allows graceful rotation by adding
// a new key and retiring the old one after existing sessions expire.
//
// All methods are safe for concurrent use.
type SessionManager struct {
	primary  cipher.AEAD   // used for encryption
	allKeys  []cipher.AEAD // tried in order for decryption
	lifetime time.Duration
}

// NewSessionManager creates a SessionManager using the provided 32-byte AES
// keys. The first key is the primary (used for encryption); all keys are tried
// for decryption to support rotation.
//
// To rotate keys: add the new key as the first element and keep the old key(s)
// until all sessions encrypted with them have expired.
func NewSessionManager(keys [][]byte, lifetime time.Duration) (*SessionManager, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one session key is required")
	}

	var allGCMs []cipher.AEAD
	for i, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("session key %d must be exactly 32 bytes (got %d)", i, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating AES cipher for key %d: %w", i, err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("creating GCM for key %d: %w", i, err)
		}
		allGCMs = append(allGCMs, gcm)
	}

	return &SessionManager{
		primary:  allGCMs[0],
		allKeys:  allGCMs,
		lifetime: lifetime,
	}, nil
}

// Save encrypts data and writes it as a secure session cookie to w.
func (sm *SessionManager) Save(w http.ResponseWriter, data *SessionData) error {
	data.Type = tokenTypeCookie
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshalling session data: %w", err)
	}

	nonce := make([]byte, sm.primary.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := sm.primary.Seal(nonce, nonce, plaintext, nil)
	value := base64.RawURLEncoding.EncodeToString(ciphertext)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sm.lifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Load reads the session cookie from r, decrypts and validates it.
// Returns (nil, nil) when the cookie is absent, invalid, or expired — callers
// should treat a nil result as "no active session" rather than an error.
// Tries all keys in order to support key rotation.
func (sm *SessionManager) Load(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, nil
	}

	plaintext := sm.tryDecrypt(raw)
	if plaintext == nil {
		return nil, nil
	}

	var data SessionData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, nil
	}

	if time.Now().After(data.ExpiresAt) {
		return nil, nil
	}

	// Reject tokens that weren't created as cookies.
	if data.Type != tokenTypeCookie {
		return nil, nil
	}

	return &data, nil
}

// EncryptToken encrypts a typed SessionData blob into a self-contained,
// URL-safe token string. Unlike session cookies these tokens are not tied to a
// browser and can be validated by any server instance sharing the same session
// key. The sole live caller is the OIDC-state cookie (tokenTypeOIDCState).
//
// data.Type MUST be set: a typed blob with the wrong/empty type would be
// silently rejected at decrypt time by DecryptTokenWithType, so we fail loudly
// at encrypt time instead of stamping a default that could mask a caller bug.
func (sm *SessionManager) EncryptToken(data *SessionData) (string, error) {
	if data.Type == "" {
		return "", fmt.Errorf("EncryptToken: data.Type must be set")
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshalling token data: %w", err)
	}

	nonce := make([]byte, sm.primary.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := sm.primary.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// DecryptTokenWithType decrypts a token and validates that its type matches
// expectedType. Used by the OIDC state flow, which stores a typed blob.
func (sm *SessionManager) DecryptTokenWithType(token string, expectedType string) (*SessionData, error) {
	return sm.decryptTokenWithType(token, expectedType)
}

func (sm *SessionManager) decryptTokenWithType(token string, expectedType string) (*SessionData, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, nil
	}

	plaintext := sm.tryDecrypt(raw)
	if plaintext == nil {
		return nil, nil
	}

	var data SessionData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, nil
	}

	if time.Now().After(data.ExpiresAt) {
		return nil, nil
	}

	// Reject tokens with the wrong type.
	if data.Type != expectedType {
		return nil, nil
	}

	return &data, nil
}

// tryDecrypt attempts to decrypt raw with each key in order. Returns the
// plaintext on the first successful decryption, or nil if none succeed.
func (sm *SessionManager) tryDecrypt(raw []byte) []byte {
	for _, gcm := range sm.allKeys {
		nonceSize := gcm.NonceSize()
		if len(raw) < nonceSize {
			continue
		}
		nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err == nil {
			return plaintext
		}
	}
	return nil
}

// Clear instructs the browser to delete the session cookie by setting MaxAge=-1.
func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
