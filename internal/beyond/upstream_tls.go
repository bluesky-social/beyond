package beyond

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// newUpstreamCATransport returns the transport for an application that sets
// upstream_ca_file: a copy of http.DefaultTransport, which every other
// application's proxy uses, that verifies the upstream against roots instead
// of the system roots. Setting RootCAs replaces the system roots; it does not
// add to them. The name verified is the host of the URL being dialled, which
// is the application's upstream.
//
// Each call returns a new transport, so its connections are never shared with
// an application that has different roots.
func newUpstreamCATransport(roots *x509.CertPool) (*http.Transport, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("beyond: http.DefaultTransport is a %T, not an *http.Transport", http.DefaultTransport)
	}
	transport := base.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.RootCAs = roots
	return transport, nil
}

// loadUpstreamCAFile reads the PEM bundle named by an application's
// upstream_ca_file into a certificate pool.
func loadUpstreamCAFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle: %w", err)
	}
	roots, err := parseCABundle(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CA bundle %s: %w", path, err)
	}
	return roots, nil
}

// parseCABundle parses a PEM bundle in which every block must be a valid
// certificate. Text between blocks is allowed, as in the annotated bundles
// distributions ship.
//
// x509.CertPool.AppendCertsFromPEM is not used because it skips whatever it
// cannot parse: a bundle with one good and one damaged certificate would load,
// and the application would work until its upstream moved to the CA that was
// silently dropped.
func parseCABundle(data []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	blocks := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %d is a %q, not a CERTIFICATE", blocks, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", blocks, err)
		}
		roots.AddCert(cert)
	}
	// pem.Decode steps over a block it cannot decode (a truncated or corrupted
	// one) and carries on, so compare what it returned with what the file
	// claims to hold.
	if begins := bytes.Count(data, []byte("-----BEGIN ")); begins != blocks {
		return nil, fmt.Errorf("malformed PEM: %d of %d blocks could not be decoded", begins-blocks, begins)
	}
	if blocks == 0 {
		return nil, errors.New("no certificates found")
	}
	return roots, nil
}
