package beyond

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustResolver(t *testing.T, cidrs ...string) *clientIPResolver {
	t.Helper()
	prefixes, err := parseTrustedProxies(cidrs)
	require.NoError(t, err)
	return &clientIPResolver{trusted: prefixes}
}

func TestClientIPResolver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        []string // one entry per X-Forwarded-For header line
		want       string
	}{
		{
			name:       "no trusted proxies ignores XFF",
			remoteAddr: "10.61.17.86:44321",
			xff:        []string{"198.51.100.23"},
			want:       "10.61.17.86",
		},
		{
			name:       "untrusted peer ignores XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.9:5000", // peer not in trusted range
			xff:        []string{"198.51.100.23"},
			want:       "203.0.113.9",
		},
		{
			name:       "trusted peer returns single XFF client (ALB case)",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.61.17.86:44321",
			xff:        []string{"198.51.100.23"},
			want:       "198.51.100.23",
		},
		{
			name:       "spoofed left entry is ignored",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.61.17.86:44321",
			// Client forged 1.2.3.4; the trusted ALB appended the real client to
			// the right. Right-to-left walk returns the real client.
			xff:  []string{"1.2.3.4, 198.51.100.23"},
			want: "198.51.100.23",
		},
		{
			name:       "multi-hop trusted chain returns first untrusted",
			trusted:    []string{"10.0.0.0/8", "172.16.0.0/12"},
			remoteAddr: "10.61.17.86:44321",
			// client -> corp-proxy(172.16) -> ALB(10.x). XFF appended L-to-R.
			xff:  []string{"198.51.100.23, 172.16.4.4"},
			want: "198.51.100.23",
		},
		{
			name:       "all-internal chain falls back to leftmost",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.61.17.86:44321",
			xff:        []string{"10.1.1.1, 10.2.2.2"},
			want:       "10.1.1.1",
		},
		{
			name:       "trusted peer with empty XFF falls back to peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.61.17.86:44321",
			want:       "10.61.17.86",
		},
		{
			name:       "XFF split across multiple header lines",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.61.17.86:44321",
			xff:        []string{"1.2.3.4", "198.51.100.23, 10.9.9.9"},
			want:       "198.51.100.23",
		},
		{
			name:       "malformed XFF entry is skipped",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.61.17.86:44321",
			xff:        []string{"not-an-ip, 198.51.100.23"},
			want:       "198.51.100.23",
		},
		{
			name:       "IPv6 client via trusted IPv6 proxy",
			trusted:    []string{"fd00::/8"},
			remoteAddr: "[fd00::1]:44321",
			xff:        []string{"2001:db8::1234"},
			want:       "2001:db8::1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := mustResolver(t, tt.trusted...)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, line := range tt.xff {
				req.Header.Add("X-Forwarded-For", line)
			}
			assert.Equal(t, tt.want, res.clientIP(req))
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	t.Run("valid CIDRs, blanks skipped", func(t *testing.T) {
		t.Parallel()
		got, err := parseTrustedProxies([]string{"10.0.0.0/8", "  ", "192.168.0.0/16"})
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})

	t.Run("bare IP without prefix is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := parseTrustedProxies([]string{"10.0.0.1"})
		assert.Error(t, err)
	})

	t.Run("garbage is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := parseTrustedProxies([]string{"not-a-cidr"})
		assert.Error(t, err)
	})
}
