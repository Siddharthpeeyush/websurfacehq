// Package dnsenum implements the dns_enum stage: Certificate Transparency
// subdomains from the crt.sh API plus a Go stdlib DNS lookup of the domain
// itself. No external tool binary is needed for this stage.
//
// Safety: the domain is SSRF-checked (internal/ssrf) before any fetch.
// The crt.sh fetch uses a transport with Proxy: nil — the trust_env=False
// equivalent — so no proxy environment variable can route the request
// elsewhere, and redirects are NOT followed (a redirect target is a new
// URL that has not been checked). The response body is capped at 10 MiB.
package dnsenum

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"websurfacehq/scanner-agent/internal/parsers"
	"websurfacehq/scanner-agent/internal/ssrf"
)

// MaxCRTBodyBytes caps the crt.sh response (10 MiB — far above any real
// certificate list for one domain).
const MaxCRTBodyBytes = 10 << 20

// DNSRecords is the stdlib DNS lookup of the domain itself.
type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

// Result is the dns_enum stage result.
type Result struct {
	Domain            string     `json:"domain"`
	Subdomains        []string   `json:"subdomains"`
	Count             int        `json:"count"`
	Sources           []string   `json:"sources"`
	DNS               DNSRecords `json:"dns"`
	DroppedPrivateIPs []string   `json:"dropped_private_ips,omitempty"`
}

// HTTPClient is the minimal interface FetchCRT needs, so tests can inject
// a fake transport.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewClient builds the crt.sh client: no proxy from the environment
// (trust_env=False equivalent), no redirect following, 30s dial/TLS
// timeouts inside the caller's overall stage timeout.
func NewClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // never via env proxy
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects
		},
	}
}

// FetchCRT fetches https://crt.sh/?q=%.<domain>&output=json and parses it.
// The caller must have SSRF-checked domain already; this function re-checks
// defensively so it is safe to call standalone. A nil resolver uses the
// system resolver.
func FetchCRT(ctx context.Context, client HTTPClient, resolver ssrf.Resolver, domain string) ([]string, error) {
	if resolver == nil {
		resolver = ssrf.DefaultResolver
	}
	if err := ssrf.CheckHost(ctx, resolver, domain); err != nil {
		return nil, err
	}
	if client == nil {
		client = NewClient()
	}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request: %w", err)
	}
	req.Header.Set("User-Agent", "WebSurfaceHQ-scanner-agent/1.0 (recon; contact: security@websurfacehq.com)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxCRTBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("crt.sh read: %w", err)
	}
	if len(body) > MaxCRTBodyBytes {
		return nil, fmt.Errorf("crt.sh response exceeds %d bytes", MaxCRTBodyBytes)
	}
	return parsers.ParseCRT(body, domain)
}

// LookupDNS resolves the domain itself with the system resolver: A,
// AAAA and CNAME. Every resolved IP is filtered through the SSRF check
// (ssrf.CheckResolvedIPs) BEFORE it is emitted: a rebinding flip that
// turns a public answer into a private one must never leak a private IP
// into a stage result. Private addresses are DROPPED (not a stage
// failure — the crt.sh list is the primary output) and recorded in the
// dropped list returned by LookupDNSWithResolver. A lookup failure for
// one record type is tolerated (returns what resolved); total failure
// returns empty records, not an error.
func LookupDNS(ctx context.Context, domain string) DNSRecords {
	rec, _ := LookupDNSWithResolver(ctx, nil, domain)
	return rec
}

// LookupDNSWithResolver is LookupDNS with an injected resolver (tests
// use a fake that returns a private IP) and returns the dropped private
// addresses alongside the records. A nil resolver uses the system
// resolver.
func LookupDNSWithResolver(ctx context.Context, resolver ssrf.Resolver, domain string) (DNSRecords, []string) {
	rec := DNSRecords{}
	dropped := []string{}
	if resolver == nil {
		resolver = ssrf.DefaultResolver
	}
	if addrs, err := resolver.LookupIP(ctx, domain); err == nil {
		for _, a := range addrs {
			ip := a
			if ip.Is4In6() {
				ip = ip.Unmap()
			}
			s := ip.String()
			if err := ssrf.CheckResolvedIPs([]string{s}); err != nil {
				// Rebinder / sink answer: drop the private address
				// and record it so the caller can see what was cut.
				dropped = append(dropped, s)
				continue
			}
			if ip.Is4() {
				rec.A = append(rec.A, s)
			} else {
				rec.AAAA = append(rec.AAAA, s)
			}
		}
	}
	// CNAME is a name, not an address: it is informational only and the
	// agent never connects to it, so no SSRF filter applies to it.
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, domain); err == nil {
		rec.CNAME = cname
	}
	sort.Strings(rec.A)
	sort.Strings(rec.AAAA)
	sort.Strings(dropped)
	return rec, dropped
}

// Run executes the dns_enum stage: crt.sh + stdlib DNS, merged and deduped.
// A nil resolver uses the system resolver.
func Run(ctx context.Context, client HTTPClient, resolver ssrf.Resolver, domain string) (*Result, error) {
	subs, err := FetchCRT(ctx, client, resolver, domain)
	if err != nil {
		return nil, err
	}
	dns, dropped := LookupDNSWithResolver(ctx, resolver, domain)
	seen := map[string]bool{}
	out := []string{}
	for _, s := range subs {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return &Result{
		Domain:            domain,
		Subdomains:        out,
		Count:             len(out),
		Sources:           []string{"crt.sh", "dns"},
		DNS:               dns,
		DroppedPrivateIPs: dropped,
	}, nil
}
