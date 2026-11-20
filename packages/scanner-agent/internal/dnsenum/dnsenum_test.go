package dnsenum

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClient returns a canned crt.sh body.
type fakeClient struct {
	body   string
	status int
}

func (f *fakeClient) Do(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

// fakeResolver always resolves to a public IP, so these tests do not
// depend on this VM's DNS: the cell resolver answers every name with a
// synthetic 198.18/15 sink address (even nonexistent.invalid resolves),
// which the SSRF check correctly refuses as non-global. See the
// workstream report for the live-smoke implication.
type fakeResolver struct{}

func (fakeResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

func TestFetchCRT_ParsesFixture(t *testing.T) {
	// A fake client avoids the network; the body is the crtsh.json
	// fixture. The SSRF check still runs for real (via fakeResolver).
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "crtsh.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	subs, err := FetchCRT(context.Background(), &fakeClient{body: string(data), status: 200}, fakeResolver{}, "example.com")
	if err != nil {
		t.Fatalf("FetchCRT: %v", err)
	}
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if len(subs) != len(want) {
		t.Fatalf("subs = %v, want %v", subs, want)
	}
	for i := range want {
		if subs[i] != want[i] {
			t.Errorf("subs[%d] = %q, want %q", i, subs[i], want[i])
		}
	}
}

func TestFetchCRT_Non200(t *testing.T) {
	_, err := FetchCRT(context.Background(), &fakeClient{body: "{}", status: 500}, fakeResolver{}, "example.com")
	if err == nil {
		t.Error("HTTP 500 from crt.sh must error")
	}
}

func TestFetchCRT_BlockedHost(t *testing.T) {
	// localhost must be refused before any HTTP call (the fake client
	// would return 200 — if FetchCRT called it, the test would fail).
	_, err := FetchCRT(context.Background(), &fakeClient{body: "[]", status: 200}, fakeResolver{}, "localhost")
	if err == nil {
		t.Error("localhost must be refused by FetchCRT")
	}
}

func TestLookupDNS_Localhost(t *testing.T) {
	// LookupDNS is stdlib-only and must not error the stage: it returns
	// whatever resolved (localhost resolves via /etc/hosts).
	rec := LookupDNS(context.Background(), "localhost")
	if len(rec.A) == 0 && rec.CNAME == "" {
		t.Log("localhost produced no records (resolver-dependent, tolerated)")
	}
}

// mixedResolver returns a public and a private address per family, to
// prove the SSRF filter drops the private ones (M15).
type mixedResolver struct{}

func (mixedResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}, nil
}

func TestLookupDNS_DropsPrivateIPs(t *testing.T) {
	// Drop + record: private addresses must never be emitted, and the
	// caller must be able to see what was cut.
	rec, dropped := LookupDNSWithResolver(context.Background(), mixedResolver{}, "example.com")
	if len(rec.A) != 1 || rec.A[0] != "93.184.216.34" {
		t.Errorf("A = %v, want [93.184.216.34]", rec.A)
	}
	if len(rec.AAAA) != 1 || rec.AAAA[0] != "2606:4700:4700::1111" {
		t.Errorf("AAAA = %v, want [2606:4700:4700::1111]", rec.AAAA)
	}
	wantDropped := []string{"10.0.0.5", "2001:db8::1"}
	if len(dropped) != len(wantDropped) {
		t.Fatalf("dropped = %v, want %v", dropped, wantDropped)
	}
	for i := range wantDropped {
		if dropped[i] != wantDropped[i] {
			t.Errorf("dropped[%d] = %q, want %q", i, dropped[i], wantDropped[i])
		}
	}
}

func TestRun_RecordsDroppedPrivateIPs(t *testing.T) {
	// The drop must surface in the stage result as dropped_private_ips.
	// The resolver answers public for FetchCRT's two SSRF resolutions,
	// then flips to a mixed answer for the LookupDNS step (the
	// rebinding-flip shape: a private IP appearing after the check).
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "crtsh.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	resolver := &orderedResolver{answers: [][]string{
		{"93.184.216.34"},
		{"93.184.216.34"},
		{"10.0.0.5", "93.184.216.34", "2001:db8::1", "2606:4700:4700::1111"},
	}}
	res, err := Run(context.Background(), &fakeClient{body: string(data), status: 200}, resolver, "example.com")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.DroppedPrivateIPs) != 2 {
		t.Errorf("DroppedPrivateIPs = %v, want 2 entries", res.DroppedPrivateIPs)
	}
	if len(res.DNS.A) != 1 || res.DNS.A[0] != "93.184.216.34" {
		t.Errorf("DNS.A = %v, want only the public address", res.DNS.A)
	}
}

// orderedResolver returns canned answers in call order (last answer
// repeats), so a test can simulate a DNS answer that flips between the
// SSRF check and the later lookup.
type orderedResolver struct {
	answers [][]string
	calls   int
}

func (r *orderedResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	idx := r.calls
	if idx >= len(r.answers) {
		idx = len(r.answers) - 1
	}
	r.calls++
	out := make([]netip.Addr, 0, len(r.answers[idx]))
	for _, s := range r.answers[idx] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}
