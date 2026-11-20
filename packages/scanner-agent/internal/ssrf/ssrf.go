// Package ssrf enforces the WebSurfaceHQ SSRF blocklist at the point of
// execution, ported from apps/api/app/core/ssrf.py (Python stays the source
// of truth; this package re-checks before any exec that takes a domain or
// host, so a compromised or mistaken caller cannot bypass the Python check).
//
// Blocked, before any connection or exec is attempted:
//   - IPv4 private / loopback / link-local / reserved ranges: 10/8,
//     172.16/12, 192.168/16, 127/8, 169.254/16 (incl. cloud metadata
//     169.254.169.254), 0/8, plus CGNAT 100.64/10, benchmarking 198.18/15,
//     documentation TEST-NETs, multicast 224/4 and reserved 240/4.
//   - Hostnames: localhost (and *.localhost), *.local, *.internal,
//     metadata.google.internal.
//   - IPv6 private / special ranges: fc00::/7 (unique-local), fe80::/10
//     (link-local), ::1 (loopback), :: (unspecified), ::/96
//     (IPv4-compatible IPv6 — covers ::127.0.0.1, which no other check
//     catches), documentation 2001:db8::/32, benchmarking 2001:2::/48,
//     ORCHID 2001:10::/28, discard-only 100::/64, plus IPv4-mapped
//     IPv6 (::ffff:127.0.0.1 is 127.0.0.1 and must be blocked as such).
//   - DNS rebinding: the hostname is resolved TWICE and both resolutions
//     are checked; a second resolution that introduces a non-global IP is
//     rejected. Fail closed on an unresolvable host.
//
// TOCTOU honesty note (same as ssrf.py): resolving + checking immediately
// before exec narrows the rebinding window but does not close it — the DNS
// answer can still change between the check and the tool's connect. Fully
// rebinding-proof fetching needs a transport pinned to the checked IP,
// which is out of scope for this exec-based agent. This package does not
// pretend otherwise.
package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// BlockedHostSuffixes mirrors ssrf.py BLOCKED_HOST_SUFFIXES.
var BlockedHostSuffixes = []string{
	".local",
	".localhost",
	".internal",
	".metadata.google.internal",
}

// BlockedHosts mirrors ssrf.py BLOCKED_HOSTS.
var BlockedHosts = map[string]bool{
	"localhost":                true,
	"metadata.google.internal": true,
}

// blockedPrefixes is the explicit CIDR deny-list. It is a superset of the
// ranges named in ssrf.py: Python's ip.is_global is False for every one of
// these (private, loopback, link-local, CGNAT/shared, benchmarking,
// documentation, multicast, reserved, unspecified). Anything not matched
// here AND globally routable is allowed; anything else is rejected.
var blockedPrefixes = mustPrefixes([]string{
	"0.0.0.0/8",       // "this network" (0/8)
	"10.0.0.0/8",      // RFC1918
	"100.64.0.0/10",   // CGNAT shared address space
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local (incl. cloud metadata 169.254.169.254)
	"172.16.0.0/12",   // RFC1918
	"192.0.0.0/24",    // IETF protocol assignments (incl. 192.0.0.0/29)
	"192.0.2.0/24",    // TEST-NET-1 documentation
	"192.168.0.0/16",  // RFC1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2 documentation
	"203.0.113.0/24",  // TEST-NET-3 documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved
	"fc00::/7",        // IPv6 unique-local
	"fe80::/10",       // IPv6 link-local
	"::1/128",         // IPv6 loopback
	"::/128",          // IPv6 unspecified
	"::/96",           // IPv4-compatible IPv6 (RFC 4291): covers ::127.0.0.1
	"2001:db8::/32",   // IPv6 documentation (RFC 3849)
	"2001:2::/48",     // IPv6 benchmarking (RFC 5180)
	"2001:10::/28",    // ORCHID (RFC 4843)
	"100::/64",        // IPv6 discard-only (RFC 6666)
	"2001::/32",       // Teredo (RFC 4380): embeds an obfuscated IPv4 in its low 32 bits
})

func mustPrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic(fmt.Sprintf("ssrf: bad builtin prefix %q: %v", c, err))
		}
		out = append(out, p)
	}
	return out
}

// UnsafeError is returned when a host fails the SSRF checks. The message
// names the reason (private IP, blocked suffix, unresolvable host) but never
// echoes credentials or a full URL with userinfo.
type UnsafeError struct{ Reason string }

func (e *UnsafeError) Error() string { return e.Reason }

// unwrapIP parses an IP literal, unwrapping IPv4-mapped IPv6
// (::ffff:127.0.0.1 is 127.0.0.1 and must be blocked as such).
func unwrapIP(value string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	if ip.Is4In6() {
		return ip.Unmap(), nil
	}
	return ip, nil
}

// isPublic reports whether ip is a globally routable public address:
// not in any blocked prefix and a global unicast address.
//
// The explicit prefix list above is the ONLY layer that rejects IPv4
// private / CGNAT / benchmarking addresses: netip's IsGlobalUnicast
// returns true for 10.0.0.1, 100.64.0.1 and 198.18.0.1 (verified
// 16 Nov 2026), and likewise true for ::127.0.0.1, 2001:db8::1,
// 2001:2::1, 2001:10::1 and 100::1 — so the IsGlobalUnicast call below
// is NOT a backstop for those. It only catches ranges neither the list
// nor Go's notion of global-unicast knows about (e.g. future special
// ranges); never rely on it alone.
func isPublic(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	// Second layer, not a substitute for the list above: catches
	// special ranges the explicit list does not name (e.g. future
	// IANA assignments). It does NOT catch the IPv4 privates or the
	// IPv6 special ranges listed above — those are caught by the list.
	return ip.IsGlobalUnicast()
}

// CheckResolvedIPs rejects if ANY resolved IP is not a globally routable
// public address. Mirrors ssrf.py check_resolved_ips.
func CheckResolvedIPs(ips []string) error {
	for _, raw := range ips {
		ip, err := unwrapIP(raw)
		if err != nil {
			return &UnsafeError{Reason: fmt.Sprintf("unparseable resolved IP: %q", raw)}
		}
		if !isPublic(ip) {
			return &UnsafeError{Reason: fmt.Sprintf("resolved IP %s is not a public address (%s)", raw, ip)}
		}
	}
	return nil
}

// Resolver resolves a host to IP addresses. It exists so tests can inject
// a fake resolver (e.g. one that flips its answer between calls, to prove
// the rebinding check); production code uses DefaultResolver.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// systemResolver adapts net.DefaultResolver to the Resolver interface.
type systemResolver struct{}

func (systemResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		out = append(out, ip)
	}
	return out, nil
}

// DefaultResolver is the system resolver (honours /etc/hosts, so
// "localhost" resolves even without DNS — same as ssrf.py resolve_all).
var DefaultResolver Resolver = systemResolver{}

// resolveAll resolves host to every A/AAAA address (deduplicated, order
// kept). Fail closed: an unresolvable host is an error.
func resolveAll(ctx context.Context, r Resolver, host string) ([]string, error) {
	addrs, err := r.LookupIP(ctx, host)
	if err != nil {
		return nil, &UnsafeError{Reason: fmt.Sprintf("cannot resolve host: %s", host)}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, a := range addrs {
		s := a.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, &UnsafeError{Reason: fmt.Sprintf("cannot resolve host: %s", host)}
	}
	return out, nil
}

// checkHostname applies the hostname/IP-literal blocklist before any DNS
// lookup. Mirrors ssrf.py _check_hostname.
func checkHostname(host string) error {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return &UnsafeError{Reason: "empty hostname"}
	}
	if BlockedHosts[h] {
		return &UnsafeError{Reason: fmt.Sprintf("blocked hostname: %s", h)}
	}
	for _, suffix := range BlockedHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return &UnsafeError{Reason: fmt.Sprintf("blocked hostname suffix: %s", h)}
		}
	}
	if ip, err := unwrapIP(h); err == nil {
		if !isPublic(ip) {
			return &UnsafeError{Reason: fmt.Sprintf("blocked IP literal: %s", h)}
		}
	}
	return nil
}

// CheckHost raises (returns) an UnsafeError unless host is safe to scan:
// hostname blocklist, IP-literal check, first DNS resolution checked,
// second DNS resolution checked (rebinding: the second set must not
// introduce a private IP). Mirrors ssrf.py assert_url_safe minus the
// URL scheme/userinfo checks, which do not apply to bare hosts.
func CheckHost(ctx context.Context, r Resolver, host string) error {
	if err := checkHostname(host); err != nil {
		return err
	}
	if r == nil {
		r = DefaultResolver
	}
	// Resolution 1: every address must be public.
	first, err := resolveAll(ctx, r, host)
	if err != nil {
		return err
	}
	if err := CheckResolvedIPs(first); err != nil {
		return err
	}
	// Resolution 2 (DNS-rebinding check): the answer must not flip to a
	// private IP between lookups. Legitimate round-robin answers that stay
	// public are allowed; only a private introduction is rejected.
	second, err := resolveAll(ctx, r, host)
	if err != nil {
		return err
	}
	return CheckResolvedIPs(second)
}

// CheckHostDefault is CheckHost with the system resolver and a 10s
// resolution timeout. This is the call sites use.
func CheckHostDefault(host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return CheckHost(ctx, DefaultResolver, host)
}

// ValidateHostname reports whether host looks like a bare hostname or IP
// literal. The allowed charset is exactly [A-Za-z0-9.-] — anything else
// (semicolons, underscores, slashes, colons, whitespace, brackets, …)
// is rejected, so a hostile value cannot smuggle shell metacharacters or
// URL syntax past this check into a tool argument. It does NOT do DNS or
// blocklist checks — use CheckHost for that. Call sites strip an optional
// scheme before calling this.
func ValidateHostname(host string) error {
	if host == "" {
		return &UnsafeError{Reason: "empty hostname"}
	}
	if len(host) > 253 {
		return &UnsafeError{Reason: "hostname too long"}
	}
	// Charset gate: only letters, digits, hyphens and dots. This is the
	// whole character check — the old ContainsAny denylist let through
	// characters it did not name (e.g. ';' and '_').
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '.') {
			return &UnsafeError{Reason: fmt.Sprintf("hostname contains illegal characters: %q", host)}
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return &UnsafeError{Reason: fmt.Sprintf("bad hostname label in %q", host)}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return &UnsafeError{Reason: fmt.Sprintf("bad hostname label in %q", host)}
		}
	}
	return nil
}

// StripScheme removes an optional http:// or https:// prefix (and a single
// trailing slash) from a user-supplied host value so "https://example.com"
// and "example.com" mean the same host. Anything with userinfo, a port or
// a path is rejected by ValidateHostname afterwards.
func StripScheme(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	return strings.TrimSuffix(h, "/")
}
