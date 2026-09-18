package beyond

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// clientIPResolver derives the true client IP of a request, optionally trusting
// X-Forwarded-For entries appended by a configured set of proxy CIDRs.
//
// When trusted is empty (the default), X-Forwarded-For is ignored entirely and
// the immediate TCP peer (RemoteAddr) is used — the safe, spoof-proof behavior
// for a directly-exposed proxy. Operators running behind a load balancer (e.g.
// an AWS ALB in EKS, whose RemoteAddr is an internal VPC address) configure
// their LB/VPC CIDRs here so the real client IP can be recovered from XFF.
type clientIPResolver struct {
	trusted []netip.Prefix
}

// clientIP returns the client IP for r as a string (no port).
//
// Algorithm:
//  1. Parse the immediate peer from RemoteAddr.
//  2. If no trusted proxies are configured, or the peer is not itself a trusted
//     proxy, return the peer. X-Forwarded-For is untrusted in this case because
//     the peer could be an arbitrary client that fabricated it.
//  3. The peer is a trusted proxy, so walk X-Forwarded-For right-to-left and
//     return the first (rightmost) entry that is NOT a trusted proxy — that is
//     the closest hop the trust chain did not vouch for, i.e. the real client.
//     A client that prepends a forged XFF entry cannot win: our trusted proxy
//     appends the client's real IP to the RIGHT of anything the client sent, so
//     the forged value sits to the left and is never reached.
//
// If every XFF entry is a trusted proxy (an all-internal chain), the leftmost
// valid entry is returned. If XFF is empty or unparseable, the peer is returned.
func (res *clientIPResolver) clientIP(r *http.Request) string {
	peerStr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peerStr = host
	}

	// No trust configured, or the peer isn't a trusted proxy: never look at XFF.
	peer, err := netip.ParseAddr(peerStr)
	if err != nil || !res.isTrusted(peer) {
		return peerStr
	}

	// The peer is a trusted proxy: parse the forwarding chain and find the
	// rightmost untrusted hop.
	chain := parseForwardedFor(r)
	if len(chain) == 0 {
		return peerStr
	}
	for _, addr := range slices.Backward(chain) {
		if !res.isTrusted(addr) {
			return addr.Unmap().String()
		}
	}

	// Whole chain was trusted (an all-internal forwarding path) — the leftmost
	// entry is as close to the origin as the header goes.
	return chain[0].Unmap().String()
}

// isTrusted reports whether addr falls within any configured trusted-proxy CIDR.
func (res *clientIPResolver) isTrusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range res.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseForwardedFor returns the ordered list of valid IPs from all
// X-Forwarded-For header values on r (left-to-right, as received). Entries that
// do not parse as bare IPs are skipped rather than aborting the walk, so one
// malformed hop cannot mask the real client IP.
func parseForwardedFor(r *http.Request) []netip.Addr {
	var out []netip.Addr
	for _, header := range r.Header.Values("X-Forwarded-For") {
		for part := range strings.SplitSeq(header, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// XFF entries are bare IPs, but tolerate an accidental :port or a
			// bracketed IPv6 form defensively.
			addr, err := netip.ParseAddr(part)
			if err != nil {
				if host, _, splitErr := net.SplitHostPort(part); splitErr == nil {
					addr, err = netip.ParseAddr(host)
				}
			}
			if err != nil {
				continue
			}
			out = append(out, addr)
		}
	}
	return out
}

// parseTrustedProxies parses a list of CIDR strings into prefixes, failing
// loudly on any malformed entry so a typo surfaces at boot rather than silently
// disabling trusted-proxy resolution.
func parseTrustedProxies(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted-proxy CIDR %q: %w", raw, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// clientIPContextKey is the context key under which the resolved client IP is
// carried from Handler.ServeHTTP to downstream consumers (access logging and
// the outbound X-Forwarded-For header). A private type prevents collisions.
type clientIPContextKey struct{}

// withClientIP returns a context carrying the resolved client IP.
func withClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, ip)
}

// clientIPFromContext returns the client IP resolved at the edge, if present.
func clientIPFromContext(ctx context.Context) (string, bool) {
	ip, ok := ctx.Value(clientIPContextKey{}).(string)
	return ip, ok
}
