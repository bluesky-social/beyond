package beyond

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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
