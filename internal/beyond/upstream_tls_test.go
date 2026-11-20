package beyond

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA is a certificate authority generated for one test. Nothing about it
// is committed: every run makes fresh keys.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key}
}

// pem returns the CA's certificate, PEM-encoded.
func (ca *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// serverCert issues a serving certificate for names. A name that parses as an
// IP address becomes an IP SAN, any other a DNS SAN.
func (ca *testCA) serverCert(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsBackend is an HTTPS upstream that records what reaches its handler. A
// request beyond refuses to send, because it could not verify the upstream,
// never gets that far.
type tlsBackend struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests int
	last     *http.Request
}

// backendAddr is the address every tlsBackend listens on; a serving
// certificate has to name it for the upstream URL to verify.
const backendAddr = "127.0.0.1"

func newTLSBackend(t *testing.T, cert tls.Certificate) *tlsBackend {
	t.Helper()
	b := &tlsBackend{}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.requests++
		b.last = r.Clone(r.Context())
		b.mu.Unlock()
		_, _ = w.Write([]byte("backend ok"))
	}))
	b.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	b.srv.EnableHTTP2 = true
	// Several tests provoke handshakes the client aborts; the server logging
	// each one would bury real failures.
	b.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	b.srv.StartTLS()
	t.Cleanup(b.srv.Close)
	return b
}

func (b *tlsBackend) requestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests
}

// upstreamTLSApp is one application of a test config. Its host is
// <name>.example.com.
type upstreamTLSApp struct {
	name         string
	upstream     string
	caFile       string // empty: no upstream_ca_file
	preserveHost bool
}

// newUpstreamTLSHandler builds a Handler the way the server does: from YAML,
// through LoadConfig.
func newUpstreamTLSHandler(t *testing.T, apps ...upstreamTLSApp) (*Handler, *SessionManager) {
	t.Helper()
	var cfgYAML strings.Builder
	cfgYAML.WriteString("applications:\n")
	for _, app := range apps {
		fmt.Fprintf(&cfgYAML, "  %s:\n", app.name)
		fmt.Fprintf(&cfgYAML, "    upstream: %s\n", app.upstream)
		fmt.Fprintf(&cfgYAML, "    host: %s.example.com\n", app.name)
		fmt.Fprintf(&cfgYAML, "    allowed_groups: [engineering]\n")
		if app.caFile != "" {
			fmt.Fprintf(&cfgYAML, "    upstream_ca_file: %s\n", app.caFile)
		}
		if app.preserveHost {
			fmt.Fprintf(&cfgYAML, "    preserve_host: true\n")
		}
	}
	cfg, err := LoadConfig(writeTempFile(t, cfgYAML.String()))
	require.NoError(t, err)

	sm := testSessionManager(t)
	al := &AccessLogger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	return NewHandler(cfg, sm, al), sm
}

// getApp sends an authenticated, authorized GET for the named test
// application through the handler.
func getApp(t *testing.T, h *Handler, sm *SessionManager, name string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = name + ".example.com"
	setSession(t, sm, req, "alice@example.com", []string{"engineering"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

// writeCAFile writes a PEM bundle to a new file and returns its path.
func writeCAFile(t *testing.T, bundle []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(path, bundle, 0o600))
	return path
}

// upstreamCAConfig renders a one-application config whose upstream and
// upstream_ca_file are the given values.
func upstreamCAConfig(upstream, caFile string) string {
	return fmt.Sprintf(`
applications:
  pinned:
    upstream: %s
    upstream_ca_file: %s
    host: pinned.example.com
    allowed_groups: [engineering]
`, upstream, caFile)
}

func TestLoadConfig_UpstreamCAFileRequiresHTTPSUpstream(t *testing.T) {
	t.Parallel()
	caFile := writeCAFile(t, newTestCA(t, "test CA").pem())

	_, err := LoadConfig(writeTempFile(t, upstreamCAConfig("http://upstream.internal:8080", caFile)))

	require.Error(t, err)
	assert.Contains(t, err.Error(), `application "pinned"`)
	assert.Contains(t, err.Error(), "upstream_ca_file requires an https upstream")
}

func TestLoadConfig_UpstreamCAFileMissing(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "absent.crt")

	_, err := LoadConfig(writeTempFile(t, upstreamCAConfig("https://upstream.internal", missing)))

	require.Error(t, err)
	assert.Contains(t, err.Error(), `application "pinned": upstream_ca_file`)
	assert.Contains(t, err.Error(), missing)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// A bundle that does not parse completely must not load at all: trusting the
// certificates that happened to parse would leave an application working
// until its upstream moved to the CA that was dropped.
func TestLoadConfig_UpstreamCAFileUnparseable(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	require.NoError(t, err)
	valid := ca.pem()

	tests := []struct {
		name        string
		bundle      []byte
		errContains string
	}{
		{
			name:        "empty file",
			bundle:      nil,
			errContains: "no certificates",
		},
		{
			name:        "not PEM",
			bundle:      []byte("this is not a certificate\n"),
			errContains: "no certificates",
		},
		{
			name:        "a block that is not a certificate",
			bundle:      append(append([]byte{}, valid...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...),
			errContains: `"PRIVATE KEY"`,
		},
		{
			name:        "a certificate block that is not a certificate",
			bundle:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}),
			errContains: "certificate 1",
		},
		{
			name:        "a truncated certificate after a valid one",
			bundle:      append(append([]byte{}, valid...), valid[:len(valid)/2]...),
			errContains: "malformed PEM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			caFile := writeCAFile(t, tt.bundle)

			_, err := LoadConfig(writeTempFile(t, upstreamCAConfig("https://upstream.internal", caFile)))

			require.Error(t, err)
			assert.Contains(t, err.Error(), `application "pinned": upstream_ca_file`)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestUpstreamCA_ProxiesToUpstreamSignedByConfiguredCA(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	backend := newTLSBackend(t, ca.serverCert(t, backendAddr))
	h, sm := newUpstreamTLSHandler(t, upstreamTLSApp{
		name:     "pinned",
		upstream: backend.srv.URL,
		caFile:   writeCAFile(t, ca.pem()),
	})

	resp := getApp(t, h, sm, "pinned")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "backend ok", string(body))
	assert.Equal(t, 1, backend.requestCount())
}

// Applications that share an upstream URL must not share a proxy unless they
// share its trust: whichever is served first would otherwise decide how the
// upstream is verified for the others.
func TestUpstreamCA_PoolDoesNotShareTrustAcrossApplications(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	otherCA := newTestCA(t, "other CA")

	const (
		pinned      = "pinned"       // trusts the CA that signed the backend
		plain       = "plain"        // no upstream_ca_file: system roots
		pinnedOther = "pinned-other" // trusts a CA that did not sign the backend
	)
	want := map[string]int{
		pinned:      http.StatusOK,
		plain:       http.StatusBadGateway,
		pinnedOther: http.StatusBadGateway,
	}

	orders := [][]string{
		{pinned, plain, pinnedOther, pinned},
		{plain, pinned, pinnedOther, plain},
		{pinnedOther, pinned, plain, pinnedOther},
	}
	for _, order := range orders {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			t.Parallel()
			backend := newTLSBackend(t, ca.serverCert(t, backendAddr))
			h, sm := newUpstreamTLSHandler(t,
				upstreamTLSApp{name: pinned, upstream: backend.srv.URL, caFile: writeCAFile(t, ca.pem())},
				upstreamTLSApp{name: plain, upstream: backend.srv.URL},
				upstreamTLSApp{name: pinnedOther, upstream: backend.srv.URL, caFile: writeCAFile(t, otherCA.pem())},
			)

			for i, name := range order {
				resp := getApp(t, h, sm, name)
				assert.Equal(t, want[name], resp.StatusCode, "request %d, application %s", i+1, name)
			}
		})
	}
}
