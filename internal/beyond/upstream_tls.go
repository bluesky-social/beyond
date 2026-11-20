package beyond

import (
	"crypto/x509"
	"fmt"
	"os"
)

// loadUpstreamCAFile reads the PEM bundle named by an application's
// upstream_ca_file into a certificate pool.
func loadUpstreamCAFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(data)
	return roots, nil
}
