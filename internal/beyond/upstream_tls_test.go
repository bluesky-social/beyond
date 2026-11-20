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

// lastRequest returns the most recent request to reach the handler.
func (b *tlsBackend) lastRequest(t *testing.T) *http.Request {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	require.NotNil(t, b.last, "no request reached the backend")
	return b.last
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

// An Application built by hand, not by LoadConfig, has upstream_ca_file set
// and nothing loaded from it. Proxying it with the system roots would trust
// more than its configuration says.
func TestProxyPool_RefusesApplicationWhoseCAFileWasNotLoaded(t *testing.T) {
	t.Parallel()
	app := &Application{
		Name:           "pinned",
		Upstream:       "https://upstream.internal",
		UpstreamCAFile: "/etc/beyond/upstream-ca/ca.crt",
	}

	_, err := NewProxyPool().Get(app)

	require.Error(t, err)
	assert.Contains(t, err.Error(), `application "pinned"`)
	assert.Contains(t, err.Error(), "upstream_ca_file")
}

// Roots for a plain-http upstream would verify nothing. LoadConfig rejects
// that configuration; the proxy must not build it either.
func TestNewBeyondProxy_RefusesRootsForNonHTTPSUpstream(t *testing.T) {
	t.Parallel()
	roots := x509.NewCertPool()
	roots.AddCert(newTestCA(t, "test CA").cert)

	_, err := newBeyondProxy("http://upstream.internal:8080", roots)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestUpstreamCA_RejectsUpstreamSignedByAnotherCA(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	otherCA := newTestCA(t, "other CA")
	backend := newTLSBackend(t, otherCA.serverCert(t, backendAddr))
	h, sm := newUpstreamTLSHandler(t, upstreamTLSApp{
		name:     "pinned",
		upstream: backend.srv.URL,
		caFile:   writeCAFile(t, ca.pem()),
	})

	resp := getApp(t, h, sm, "pinned")

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Zero(t, backend.requestCount(), "the request, with its identity headers, must not be sent to an unverified upstream")
}

func TestUpstreamCA_RejectsUpstreamCertificateForAnotherName(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	// Signed by the trusted CA, but not for the address in the upstream URL.
	backend := newTLSBackend(t, ca.serverCert(t, "elsewhere.internal.example"))
	h, sm := newUpstreamTLSHandler(t, upstreamTLSApp{
		name:     "pinned",
		upstream: backend.srv.URL,
		caFile:   writeCAFile(t, ca.pem()),
	})

	resp := getApp(t, h, sm, "pinned")

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Zero(t, backend.requestCount())
}

// preserve_host changes the Host header sent to the upstream. It must not
// change the name the upstream's certificate is verified for, which stays the
// host of the upstream URL.
func TestUpstreamCA_PreserveHostDoesNotChangeTheVerifiedName(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")

	t.Run("certificate for the upstream URL host is accepted", func(t *testing.T) {
		t.Parallel()
		backend := newTLSBackend(t, ca.serverCert(t, backendAddr))
		h, sm := newUpstreamTLSHandler(t, upstreamTLSApp{
			name:         "pinned",
			upstream:     backend.srv.URL,
			caFile:       writeCAFile(t, ca.pem()),
			preserveHost: true,
		})

		resp := getApp(t, h, sm, "pinned")

		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "pinned.example.com", backend.lastRequest(t).Host)
	})

	t.Run("certificate for the preserved host is rejected", func(t *testing.T) {
		t.Parallel()
		backend := newTLSBackend(t, ca.serverCert(t, "pinned.example.com"))
		h, sm := newUpstreamTLSHandler(t, upstreamTLSApp{
			name:         "pinned",
			upstream:     backend.srv.URL,
			caFile:       writeCAFile(t, ca.pem()),
			preserveHost: true,
		})

		resp := getApp(t, h, sm, "pinned")

		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
		assert.Zero(t, backend.requestCount())
	})
}

// Without upstream_ca_file an https upstream is verified against the system
// roots, as it was before the setting existed: a private CA is not trusted
// just because some application names it.
func TestUpstreamCA_ApplicationWithoutItCannotReachPrivateCAUpstream(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	backend := newTLSBackend(t, ca.serverCert(t, backendAddr))
	h, sm := newUpstreamTLSHandler(t, upstreamTLSApp{name: "plain", upstream: backend.srv.URL})

	resp := getApp(t, h, sm, "plain")

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Zero(t, backend.requestCount())
}

// A bundle may hold several CAs, which is how a CA is replaced without an
// outage: trust old and new, move the upstream, drop the old.
func TestUpstreamCA_BundleMayHoldSeveralCAs(t *testing.T) {
	t.Parallel()
	oldCA := newTestCA(t, "old CA")
	newCA := newTestCA(t, "new CA")
	caFile := writeCAFile(t, append(oldCA.pem(), newCA.pem()...))
	oldBackend := newTLSBackend(t, oldCA.serverCert(t, backendAddr))
	newBackend := newTLSBackend(t, newCA.serverCert(t, backendAddr))
	h, sm := newUpstreamTLSHandler(t,
		upstreamTLSApp{name: "on-old", upstream: oldBackend.srv.URL, caFile: caFile},
		upstreamTLSApp{name: "on-new", upstream: newBackend.srv.URL, caFile: caFile},
	)

	assert.Equal(t, http.StatusOK, getApp(t, h, sm, "on-old").StatusCode)
	assert.Equal(t, http.StatusOK, getApp(t, h, sm, "on-new").StatusCode)
}

// The bundle is read once, by LoadConfig. A file that changes afterwards (a
// mounted ConfigMap is updated in place) changes nothing until the process
// restarts and loads its config again.
func TestUpstreamCA_BundleIsReadOnceWhenConfigLoads(t *testing.T) {
	t.Parallel()
	loadedCA := newTestCA(t, "CA in the file at load")
	laterCA := newTestCA(t, "CA written to the file afterwards")
	caFile := writeCAFile(t, loadedCA.pem())
	loadedBackend := newTLSBackend(t, loadedCA.serverCert(t, backendAddr))
	laterBackend := newTLSBackend(t, laterCA.serverCert(t, backendAddr))
	h, sm := newUpstreamTLSHandler(t,
		upstreamTLSApp{name: "on-loaded", upstream: loadedBackend.srv.URL, caFile: caFile},
		upstreamTLSApp{name: "on-later", upstream: laterBackend.srv.URL, caFile: caFile},
	)

	require.NoError(t, os.WriteFile(caFile, laterCA.pem(), 0o600))

	assert.Equal(t, http.StatusOK, getApp(t, h, sm, "on-loaded").StatusCode)
	assert.Equal(t, http.StatusBadGateway, getApp(t, h, sm, "on-later").StatusCode)
	assert.Zero(t, laterBackend.requestCount())
}

// An https upstream reached through http.DefaultTransport negotiates HTTP/2.
// One reached through the upstream_ca_file transport must too.
func TestUpstreamCA_UpstreamStillNegotiatesHTTP2(t *testing.T) {
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
	assert.Equal(t, 2, backend.lastRequest(t).ProtoMajor)
}

func TestLoadConfig_UpstreamCAFileLoadsExactlyTheBundle(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t, "test CA")
	otherCA := newTestCA(t, "other CA")
	caFile := writeCAFile(t, append(ca.pem(), otherCA.pem()...))

	cfg, err := LoadConfig(writeTempFile(t, upstreamCAConfig("https://upstream.internal", caFile)))
	require.NoError(t, err)

	want := x509.NewCertPool()
	want.AddCert(ca.cert)
	want.AddCert(otherCA.cert)
	got := cfg.Applications["pinned"].upstreamRoots
	require.NotNil(t, got)
	assert.True(t, got.Equal(want), "the loaded roots must be the bundle's certificates and nothing else, system roots included")
}

// The 52 applications without upstream_ca_file must proxy exactly as before:
// a ReverseProxy with no Transport, which is http.DefaultTransport.
func TestProxyPool_ApplicationWithoutCAFileHasNoTransportOfItsOwn(t *testing.T) {
	t.Parallel()
	pool := NewProxyPool()

	for _, upstream := range []string{"http://upstream.internal:8080", "https://upstream.internal"} {
		bp, err := pool.Get(&Application{Name: "plain", Upstream: upstream})
		require.NoError(t, err)
		assert.Nil(t, bp.rp.Transport, upstream)
	}
}

// The upstream_ca_file transport must be http.DefaultTransport with different
// roots and nothing else: same pooling, timeouts, proxy and HTTP/2 behaviour.
func TestNewUpstreamCATransport_DiffersFromDefaultOnlyInRoots(t *testing.T) {
	t.Parallel()
	roots := x509.NewCertPool()
	roots.AddCert(newTestCA(t, "test CA").cert)
	base, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok)

	tr, err := newUpstreamCATransport(roots)
	require.NoError(t, err)

	require.NotNil(t, tr.TLSClientConfig)
	assert.Same(t, roots, tr.TLSClientConfig.RootCAs)
	assert.False(t, tr.TLSClientConfig.InsecureSkipVerify)
	assert.Empty(t, tr.TLSClientConfig.ServerName, "the verified name must come from the upstream URL")
	assert.Nil(t, tr.TLSClientConfig.VerifyPeerCertificate)
	assert.Nil(t, tr.TLSClientConfig.VerifyConnection)

	assert.Equal(t, base.ForceAttemptHTTP2, tr.ForceAttemptHTTP2)
	assert.Equal(t, base.MaxIdleConns, tr.MaxIdleConns)
	assert.Equal(t, base.MaxIdleConnsPerHost, tr.MaxIdleConnsPerHost)
	assert.Equal(t, base.MaxConnsPerHost, tr.MaxConnsPerHost)
	assert.Equal(t, base.IdleConnTimeout, tr.IdleConnTimeout)
	assert.Equal(t, base.TLSHandshakeTimeout, tr.TLSHandshakeTimeout)
	assert.Equal(t, base.ExpectContinueTimeout, tr.ExpectContinueTimeout)
	assert.Equal(t, base.ResponseHeaderTimeout, tr.ResponseHeaderTimeout)
	assert.Equal(t, base.DisableKeepAlives, tr.DisableKeepAlives)
	assert.Equal(t, base.DisableCompression, tr.DisableCompression)
	assert.Equal(t, base.Proxy == nil, tr.Proxy == nil)

	// The clone must not have handed its roots back to the transport every
	// other application uses.
	if base.TLSClientConfig != nil {
		assert.Nil(t, base.TLSClientConfig.RootCAs)
	}
}
