package parsers

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestParseSubfinder_Fixture(t *testing.T) {
	// SYNTHETIC fixture (see testdata/README.md).
	subs, skipped, err := ParseSubfinder(readFixture(t, "subfinder.jsonl"))
	if err != nil {
		t.Fatalf("ParseSubfinder: %v", err)
	}
	// 7 lines: 5 valid (one duplicate host, one upper-case), 1 malformed
	// line, 1 empty-host line. Expect 4 deduped lower-case hosts.
	want := []Subdomain{
		{Host: "api.example.com", Source: "dnsdumpster"},
		{Host: "example.com", Source: "crtsh"},
		{Host: "mail.example.com", Source: "virustotal"},
		{Host: "www.example.com", Source: "crtsh"},
	}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("subs = %+v, want %+v", subs, want)
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2 (malformed line + empty host)", skipped)
	}
}

func TestParseSubfinder_EmptyAndArray(t *testing.T) {
	subs, skipped, err := ParseSubfinder([]byte(""))
	if err != nil || len(subs) != 0 || skipped != 0 {
		t.Errorf("empty input: subs=%v skipped=%d err=%v", subs, skipped, err)
	}
	// JSON array form must also parse.
	subs, _, err = ParseSubfinder([]byte(`[{"host":"a.example.com","source":"x"}]`))
	if err != nil || len(subs) != 1 || subs[0].Host != "a.example.com" {
		t.Errorf("array input: subs=%v err=%v", subs, err)
	}
	// All-malformed input is an error (wrong tool / wrong flags), not a
	// silent empty result.
	if _, _, err := ParseSubfinder([]byte("garbage\nmore garbage\n")); err == nil {
		t.Error("all-malformed input must error")
	}
	// Extra/unknown fields are tolerated.
	subs, _, err = ParseSubfinder([]byte(`{"host":"b.example.com","source":"x","ip":"1.2.3.4","unknown_field":123}`))
	if err != nil || len(subs) != 1 {
		t.Errorf("extra fields: subs=%v err=%v", subs, err)
	}
}

func TestParseCRT_Fixture(t *testing.T) {
	// SYNTHETIC fixture (see testdata/README.md).
	subs, err := ParseCRT(readFixture(t, "crtsh.json"), "example.com")
	if err != nil {
		t.Fatalf("ParseCRT: %v", err)
	}
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("subs = %v, want %v", subs, want)
	}
}

func TestParseCRT_MalformedAndUnrelated(t *testing.T) {
	if _, err := ParseCRT([]byte("not json"), "example.com"); err == nil {
		t.Error("malformed crt.sh JSON must error")
	}
	subs, err := ParseCRT([]byte(`[{"common_name":"other.org","name_value":"other.org"}]`), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("unrelated names must be dropped, got %v", subs)
	}
	// Wildcard is unwildcarded; name_value newlines split.
	subs, err = ParseCRT([]byte(`[{"common_name":"*.example.com","name_value":"*.example.com\ndeep.sub.example.com"}]`), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"deep.sub.example.com", "example.com"}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("subs = %v, want %v", subs, want)
	}
}

func TestParseHttpx_RealCapture(t *testing.T) {
	// REAL httpx output captured 2026-11-16 04:29 UTC against
	// potatomuzik.me (owner's own domain, recon GET only, 5 req/s).
	// Proves the parser against the tool's actual schema, including the
	// "a" IP array and "tls_version" field the synthetic fixture was
	// corrected to match.
	results, skipped, err := ParseHttpx(readFixture(t, "httpx.real.jsonl"))
	if err != nil {
		t.Fatalf("ParseHttpx(real): %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 for a real capture", skipped)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].StatusCode != 200 || results[0].Title != "PotatoMuzik" {
		t.Errorf("first result wrong: %+v", results[0])
	}
	if results[0].IP != "198.18.166.126" {
		t.Errorf("first result IP = %q, want the \"a\" array value", results[0].IP)
	}
	if results[0].TLS == nil || results[0].TLS.SubjectCN != "potatomuzik.me" || results[0].TLS.TLSVersion != "tls13" {
		t.Errorf("first result TLS wrong: %+v", results[0].TLS)
	}
	// "webserver" and "content_type" must survive parsing (review fix
	// B1): the Python runner reads them for tech fingerprinting.
	if results[0].Webserver != "Netlify" || results[0].ContentType != "text/html" {
		t.Errorf("first result webserver/content_type = %q/%q, want Netlify/text/html", results[0].Webserver, results[0].ContentType)
	}
	if results[1].Webserver != "Netlify" || results[1].ContentType != "text/plain" {
		t.Errorf("second result webserver/content_type = %q/%q, want Netlify/text/plain", results[1].Webserver, results[1].ContentType)
	}
	foundNetlify := false
	for _, tech := range results[0].Technologies {
		if tech == "Netlify" {
			foundNetlify = true
		}
	}
	if !foundNetlify {
		t.Errorf("tech = %v, want Netlify in it", results[0].Technologies)
	}
	if results[1].StatusCode != 301 || results[1].Host != "www.potatomuzik.me" {
		t.Errorf("second result wrong: %+v", results[1])
	}
}

func TestParseSubfinder_RealCapture(t *testing.T) {
	// REAL subfinder v2.17.0 output captured 2026-11-16 04:24 UTC against
	// potatomuzik.me: empty (0 subdomains found in ~12 ms — no provider
	// keys configured in this environment). Empty input must parse to
	// zero results, not an error.
	subs, skipped, err := ParseSubfinder(readFixture(t, "subfinder.real.jsonl"))
	if err != nil {
		t.Fatalf("ParseSubfinder(real): %v", err)
	}
	if len(subs) != 0 || skipped != 0 {
		t.Errorf("subs=%v skipped=%d, want empty", subs, skipped)
	}
}

func TestParseNaabu_RealCapture(t *testing.T) {
	// REAL naabu v2.7.0 output captured 2026-11-16 04:42 UTC: CONNECT
	// scan of 127.0.0.1:18080 (a local python listener). Real naabu
	// emits {"ip","timestamp","port","protocol","tls"} — NO "host"
	// field, so the parser must fall back to the IP as the host.
	ports, skipped, err := ParseNaabu(readFixture(t, "naabu.real.jsonl"))
	if err != nil {
		t.Fatalf("ParseNaabu(real): %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 for a real capture", skipped)
	}
	want := []OpenPort{{Host: "127.0.0.1", IP: "127.0.0.1", Port: 18080, Protocol: "tcp"}}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("ports = %+v, want %+v", ports, want)
	}
}

func TestParseKatana_RealCapture(t *testing.T) {
	// REAL katana output captured 2026-11-16 04:39 UTC against
	// potatomuzik.me: a single ERROR line (TLS handshake failure in
	// this VM — katana could not fetch the site here). An error line is
	// not a crawled URL: zero results, one skipped, no parse error.
	urls, skipped, err := ParseKatana(readFixture(t, "katana.real.jsonl"))
	if err != nil {
		t.Fatalf("ParseKatana(real): %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("urls = %+v, want none (error line is not a crawl result)", urls)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the error line)", skipped)
	}
}

func TestParseNaabu_Fixture(t *testing.T) {
	// SYNTHETIC fixture (see testdata/README.md).
	ports, skipped, err := ParseNaabu(readFixture(t, "naabu.jsonl"))
	if err != nil {
		t.Fatalf("ParseNaabu: %v", err)
	}
	want := []OpenPort{
		{Host: "example.com", IP: "93.184.216.34", Port: 80, Protocol: "tcp"},
		{Host: "example.com", IP: "93.184.216.34", Port: 443, Protocol: "tcp"},
	}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("ports = %+v, want %+v", ports, want)
	}
	// Skipped: port 99999 (out of range), empty host+IP with port 22,
	// malformed line = 3.
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}
}

func TestParseNaabu_Empty(t *testing.T) {
	ports, skipped, err := ParseNaabu([]byte(""))
	if err != nil || len(ports) != 0 || skipped != 0 {
		t.Errorf("empty input: ports=%v skipped=%d err=%v", ports, skipped, err)
	}
}

func TestParseHttpx_Fixture(t *testing.T) {
	// SYNTHETIC fixture (see testdata/README.md).
	results, skipped, err := ParseHttpx(readFixture(t, "httpx.jsonl"))
	if err != nil {
		t.Fatalf("ParseHttpx: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if results[0].URL != "https://example.com" || results[0].StatusCode != 200 ||
		results[0].Title != "Example Domain" || len(results[0].Technologies) != 1 ||
		results[0].TLS == nil || results[0].TLS.SubjectCN != "example.com" {
		t.Errorf("first result wrong: %+v", results[0])
	}
	// Real httpx reports IPs in "a", not "ip" — the parser must pick it
	// up from there; and the TLS version field is "tls_version".
	if results[0].IP != "93.184.216.34" {
		t.Errorf("first result IP = %q, want 93.184.216.34 (from \"a\")", results[0].IP)
	}
	if results[0].TLS.TLSVersion != "tls13" {
		t.Errorf("first result TLSVersion = %q, want tls13", results[0].TLS.TLSVersion)
	}
	if results[1].StatusCode != 301 || results[1].TLS != nil {
		t.Errorf("second result wrong: %+v", results[1])
	}
	if results[2].Host != "api.example.com" || results[2].IP != "93.184.216.35" {
		t.Errorf("third result wrong: %+v", results[2])
	}
	// Skipped: empty-URL line + malformed line = 2.
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2", skipped)
	}
}

func TestParseKatana_Fixture(t *testing.T) {
	// SYNTHETIC fixture (see testdata/README.md).
	urls, skipped, err := ParseKatana(readFixture(t, "katana.jsonl"))
	if err != nil {
		t.Fatalf("ParseKatana: %v", err)
	}
	if len(urls) != 4 {
		t.Fatalf("urls = %d, want 4", len(urls))
	}
	// request.url is preferred; the style.css line has empty url and must
	// fall back to request.endpoint.
	if urls[2].URL != "https://example.com/style.css" {
		t.Errorf("endpoint fallback wrong: %+v", urls[2])
	}
	if urls[3].Method != "POST" || urls[3].URL != "https://example.com/api/login" {
		t.Errorf("form URL wrong: %+v", urls[3])
	}
	// Skipped: malformed line only = 1.
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	js := JSFiles(urls)
	wantJS := []string{"https://example.com/app.js?v=2"}
	if !reflect.DeepEqual(js, wantJS) {
		t.Errorf("JSFiles = %v, want %v", js, wantJS)
	}
}

func TestJSFiles_QueryAndCase(t *testing.T) {
	urls := []CrawledURL{
		{URL: "https://example.com/A.JS"},
		{URL: "https://example.com/b.js?x=1#frag"},
		{URL: "https://example.com/c.css"},
		{URL: "https://example.com/notjs.txt"},
	}
	js := JSFiles(urls)
	want := []string{"https://example.com/A.JS", "https://example.com/b.js?x=1#frag"}
	if !reflect.DeepEqual(js, want) {
		t.Errorf("JSFiles = %v, want %v", js, want)
	}
}
