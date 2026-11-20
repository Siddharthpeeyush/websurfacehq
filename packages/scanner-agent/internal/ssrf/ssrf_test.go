package ssrf

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
)

// fakeResolver returns canned answers; answers are consumed in order so a
// test can simulate a DNS answer that flips between resolutions.
type fakeResolver struct {
	answers [][]string
	calls   int
	err     error
}

func (f *fakeResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	idx := f.calls
	if idx >= len(f.answers) {
		idx = len(f.answers) - 1
	}
	f.calls++
	out := make([]netip.Addr, 0, len(f.answers[idx]))
	for _, s := range f.answers[idx] {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, nil
}

func TestCheckResolvedIPs_BlockedRanges(t *testing.T) {
	blocked := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"127.0.0.1", "127.0.0.2",
		"169.254.169.254", "169.254.0.1",
		"0.0.0.0", "0.1.2.3",
		"100.64.0.1",                               // CGNAT
		"198.18.0.1",                               // benchmarking
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // TEST-NETs
		"224.0.0.1",          // multicast
		"240.0.0.1",          // reserved
		"fc00::1", "fd00::1", // IPv6 unique-local
		"fe80::1", // IPv6 link-local
		"::1", "::",
		"::127.0.0.1",      // IPv4-compatible IPv6 loopback (::/96)
		"2001:db8::1",      // IPv6 documentation
		"2001:2::1",        // IPv6 benchmarking
		"2001:10::1",       // ORCHID
		"100::1",           // IPv6 discard-only
		"2001::1",          // Teredo (embeds an obfuscated IPv4)
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"::ffff:10.0.0.1",  // IPv4-mapped private
		"::ffff:192.168.1.1",
	}
	for _, ip := range blocked {
		if err := CheckResolvedIPs([]string{ip}); err == nil {
			t.Errorf("CheckResolvedIPs(%q): expected rejection, got nil", ip)
		}
	}
}

func TestCheckResolvedIPs_PublicPass(t *testing.T) {
	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "142.250.80.4",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"::ffff:8.8.8.8", // IPv4-mapped public is public
	}
	for _, ip := range public {
		if err := CheckResolvedIPs([]string{ip}); err != nil {
			t.Errorf("CheckResolvedIPs(%q): expected pass, got %v", ip, err)
		}
	}
}

func TestCheckResolvedIPs_MixedListRejected(t *testing.T) {
	// One private IP among public ones must still reject (ANY rule).
	if err := CheckResolvedIPs([]string{"8.8.8.8", "10.0.0.1"}); err == nil {
		t.Error("mixed list with a private IP must be rejected")
	}
}

func TestCheckResolvedIPs_Unparseable(t *testing.T) {
	if err := CheckResolvedIPs([]string{"not-an-ip"}); err == nil {
		t.Error("unparseable IP must be rejected")
	}
}

func TestCheckHost_BlockedHostnames(t *testing.T) {
	blocked := []string{
		"localhost", "LOCALHOST", "localhost.",
		"foo.localhost", "foo.local", "foo.internal",
		"metadata.google.internal", "x.metadata.google.internal",
	}
	for _, h := range blocked {
		r := &fakeResolver{answers: [][]string{{"8.8.8.8"}}}
		if err := CheckHost(context.Background(), r, h); err == nil {
			t.Errorf("CheckHost(%q): expected rejection, got nil", h)
		}
	}
}

func TestCheckHost_BlockedIPLiterals(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0"}
	for _, h := range blocked {
		r := &fakeResolver{answers: [][]string{{"8.8.8.8"}}}
		if err := CheckHost(context.Background(), r, h); err == nil {
			t.Errorf("CheckHost(%q): expected rejection, got nil", h)
		}
	}
}

func TestCheckHost_PublicHostnamePasses(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"93.184.216.34"}, {"93.184.216.34"}}}
	if err := CheckHost(context.Background(), r, "example.com"); err != nil {
		t.Errorf("public host must pass, got %v", err)
	}
	if r.calls != 2 {
		t.Errorf("expected 2 resolutions (rebinding check), got %d", r.calls)
	}
}

func TestCheckHost_RebindingSecondResolutionFlipsPrivate(t *testing.T) {
	// First answer public, second answer private: must reject.
	r := &fakeResolver{answers: [][]string{{"93.184.216.34"}, {"10.0.0.5"}}}
	if err := CheckHost(context.Background(), r, "evil.example.com"); err == nil {
		t.Error("rebinding flip to private IP must be rejected")
	}
}

func TestCheckHost_RebindingFirstResolutionPrivate(t *testing.T) {
	r := &fakeResolver{answers: [][]string{{"192.168.1.1"}, {"93.184.216.34"}}}
	if err := CheckHost(context.Background(), r, "evil.example.com"); err == nil {
		t.Error("private first resolution must be rejected")
	}
}

func TestCheckHost_RoundRobinPublicPasses(t *testing.T) {
	// Legitimate round-robin: different public IPs across resolutions pass.
	r := &fakeResolver{answers: [][]string{{"93.184.216.34"}, {"93.184.216.35"}}}
	if err := CheckHost(context.Background(), r, "example.com"); err != nil {
		t.Errorf("public round-robin must pass, got %v", err)
	}
}

func TestCheckHost_UnresolvableFailsClosed(t *testing.T) {
	r := &fakeResolver{err: fmt.Errorf("no such host")}
	if err := CheckHost(context.Background(), r, "nonexistent.invalid"); err == nil {
		t.Error("unresolvable host must fail closed")
	}
}

func TestValidateHostname(t *testing.T) {
	valid := []string{"example.com", "sub.example.com", "potatomuzik.me", "8.8.8.8", "a-b.example-2.com"}
	for _, h := range valid {
		if err := ValidateHostname(h); err != nil {
			t.Errorf("ValidateHostname(%q): expected valid, got %v", h, err)
		}
	}
	invalid := []string{
		"", "http://example.com", "https://example.com", "example.com/path",
		"user@example.com", "example.com:8080", "exa mple.com",
		"exam;ple.com", "exa_mple.com",
		"example.com\n", "-bad.example.com", "bad-.example.com",
		"example..com", "[::1]",
	}
	for _, h := range invalid {
		if err := ValidateHostname(h); err == nil {
			t.Errorf("ValidateHostname(%q): expected rejection, got nil", h)
		}
	}
}

func TestStripScheme(t *testing.T) {
	if got := StripScheme("https://example.com/"); got != "example.com" {
		t.Errorf("StripScheme https: got %q", got)
	}
	if got := StripScheme("http://example.com"); got != "example.com" {
		t.Errorf("StripScheme http: got %q", got)
	}
	if got := StripScheme("example.com"); got != "example.com" {
		t.Errorf("StripScheme bare: got %q", got)
	}
}
