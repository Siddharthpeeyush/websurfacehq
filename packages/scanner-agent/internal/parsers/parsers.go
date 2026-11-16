// Package parsers decodes the JSON/JSONL output of the ProjectDiscovery
// tools wrapped by the scanner-agent: subfinder, crt.sh, naabu, httpx and
// katana.
//
// Contract per parser: Parse([]byte) returns typed structs plus a count of
// skipped lines. Parsers are tolerant of missing/extra fields (encoding/json
// ignores unknown fields; every field is optional) and strict about
// malformed JSON lines: a bad line is skipped and counted, never a crash.
// If EVERY line is malformed, that is an error — it means the wrong tool or
// wrong flags produced the output, and silently returning "nothing found"
// would hide the mistake. Empty input is valid: zero results, zero skipped.
package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// parseJSONLines decodes newline-delimited JSON into a slice of T. Blank
// lines are ignored (not counted as skipped). It also accepts a single JSON
// array as input (some tools emit that when given one target).
func parseJSONLines[T any](data []byte) ([]T, int, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, 0, nil
	}
	if trimmed[0] == '[' {
		var arr []T
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, 0, fmt.Errorf("invalid JSON array: %w", err)
		}
		return arr, 0, nil
	}
	var out []T
	skipped := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			skipped++
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 && skipped > 0 {
		return nil, skipped, fmt.Errorf("no valid JSON lines parsed (%d line(s) skipped as malformed)", skipped)
	}
	return out, skipped, nil
}

// dedupeSorted lowercases, dedupes and sorts a string list.
func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ---- subfinder ----

// SubfinderEntry is one subfinder -json line. Only host/source are used;
// any other fields the tool emits are ignored.
type SubfinderEntry struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	IP     string `json:"ip"`
}

// Subdomain is the normalized subfinder result.
type Subdomain struct {
	Host   string `json:"host"`
	Source string `json:"source,omitempty"`
}

// ParseSubfinder parses subfinder -json JSONL output into a deduped,
// sorted subdomain list.
func ParseSubfinder(data []byte) ([]Subdomain, int, error) {
	entries, skipped, err := parseJSONLines[SubfinderEntry](data)
	if err != nil {
		return nil, skipped, err
	}
	byHost := map[string]string{}
	for _, e := range entries {
		host := strings.ToLower(strings.TrimSpace(e.Host))
		if host == "" {
			skipped++
			continue
		}
		if _, ok := byHost[host]; !ok {
			byHost[host] = e.Source
		}
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]Subdomain, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, Subdomain{Host: h, Source: byHost[h]})
	}
	return out, skipped, nil
}

// ---- crt.sh ----

// CRTEntry is one row of the crt.sh JSON API (output=json). name_value may
// hold several names separated by newlines (one certificate covering many
// names); common_name is the primary name.
type CRTEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// ParseCRT parses crt.sh JSON output and returns the deduped, sorted
// subdomains of domain found in it. Wildcard entries ("*.example.com")
// are unwildcarded to "example.com". Names that are not the domain or a
// subdomain of it are dropped (crt.sh can return unrelated names when a
// certificate covers many domains).
func ParseCRT(data []byte, domain string) ([]string, error) {
	var entries []CRTEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("invalid crt.sh JSON: %w", err)
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	names := []string{}
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(raw))
			name = strings.TrimPrefix(name, "*.")
			if name == "" {
				continue
			}
			if name == domain || strings.HasSuffix(name, "."+domain) {
				names = append(names, name)
			}
		}
		// common_name is usually already inside name_value, but include it
		// for certs where it is not.
		cn := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(e.CommonName, "*.")))
		if cn != "" && (cn == domain || strings.HasSuffix(cn, "."+domain)) {
			names = append(names, cn)
		}
	}
	return dedupeSorted(names), nil
}

// ---- naabu ----

// NaabuEntry is one naabu -json line.
type NaabuEntry struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// OpenPort is the normalized naabu result.
type OpenPort struct {
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// ParseNaabu parses naabu -json JSONL output into open ports, sorted by
// host then port. Entries with no usable port are skipped and counted.
func ParseNaabu(data []byte) ([]OpenPort, int, error) {
	entries, skipped, err := parseJSONLines[NaabuEntry](data)
	if err != nil {
		return nil, skipped, err
	}
	out := []OpenPort{}
	for _, e := range entries {
		host := strings.ToLower(strings.TrimSpace(e.Host))
		if host == "" {
			host = strings.TrimSpace(e.IP)
		}
		if host == "" || e.Port <= 0 || e.Port > 65535 {
			skipped++
			continue
		}
		out = append(out, OpenPort{Host: host, IP: e.IP, Port: e.Port, Protocol: e.Protocol})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out, skipped, nil
}

// ---- httpx ----

// HttpxTLS is the subset of httpx's -tls-probe output we store. Every
// field is optional; httpx omits most of them for non-TLS hosts. Real
// httpx spells the version "tls_version" (not "version"); both are
// accepted.
type HttpxTLS struct {
	SubjectCN  string   `json:"subject_cn,omitempty"`
	SubjectAN  []string `json:"subject_an,omitempty"`
	IssuerCN   string   `json:"issuer_cn,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	Version    string   `json:"version,omitempty"`
	TLSVersion string   `json:"tls_version,omitempty"`
}

// HttpxEntry is one httpx -json line. Real httpx reports resolved IPs in
// "a" (an array, e.g. "a":["93.184.216.34"]), not in a top-level "ip"
// field — "ip" is kept as a fallback for other httpx versions/configs.
type HttpxEntry struct {
	URL         string    `json:"url"`
	Input       string    `json:"input"`
	Scheme      string    `json:"scheme"`
	Host        string    `json:"host"`
	Port        string    `json:"port"`
	StatusCode  int       `json:"status_code"`
	Title       string    `json:"title"`
	Tech        []string  `json:"tech"`
	IP          string    `json:"ip"`
	A           []string  `json:"a"`
	Webserver   string    `json:"webserver"`
	ContentType string    `json:"content_type"`
	TLS         *HttpxTLS `json:"tls"`
}

// ProbeResult is the normalized httpx result.
type ProbeResult struct {
	URL          string    `json:"url"`
	Host         string    `json:"host"`
	StatusCode   int       `json:"status_code"`
	Title        string    `json:"title,omitempty"`
	Technologies []string  `json:"technologies,omitempty"`
	IP           string    `json:"ip,omitempty"`
	Webserver    string    `json:"webserver,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	TLS          *HttpxTLS `json:"tls,omitempty"`
}

// ParseHttpx parses httpx -json JSONL output. Entries with no URL are
// skipped and counted.
func ParseHttpx(data []byte) ([]ProbeResult, int, error) {
	entries, skipped, err := parseJSONLines[HttpxEntry](data)
	if err != nil {
		return nil, skipped, err
	}
	out := []ProbeResult{}
	for _, e := range entries {
		if strings.TrimSpace(e.URL) == "" {
			skipped++
			continue
		}
		host := e.Host
		if host == "" {
			host = e.Input
		}
		ip := e.IP
		if ip == "" && len(e.A) > 0 {
			ip = e.A[0] // real httpx reports IPs in "a", not "ip"
		}
		out = append(out, ProbeResult{
			URL:          e.URL,
			Host:         host,
			StatusCode:   e.StatusCode,
			Title:        e.Title,
			Technologies: e.Tech,
			IP:           ip,
			Webserver:    e.Webserver,
			ContentType:  e.ContentType,
			TLS:          e.TLS,
		})
	}
	return out, skipped, nil
}

// ---- katana ----

// KatanaRequest is the request half of a katana -jsonl line.
type KatanaRequest struct {
	Method   string `json:"method"`
	URL      string `json:"url"`
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"`
}

// KatanaResponse is the response half of a katana -jsonl line.
type KatanaResponse struct {
	StatusCode   int      `json:"status_code"`
	Technologies []string `json:"technologies"`
}

// KatanaEntry is one katana -jsonl line. Katana emits error lines for
// failed fetches ({"request":{...},"error":"..."}) — those carry no
// response and must not be counted as crawled URLs.
type KatanaEntry struct {
	Request  KatanaRequest  `json:"request"`
	Response KatanaResponse `json:"response"`
	Error    string         `json:"error"`
}

// CrawledURL is the normalized katana result.
type CrawledURL struct {
	URL          string   `json:"url"`
	Method       string   `json:"method,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Source       string   `json:"source,omitempty"`
}

// ParseKatana parses katana -jsonl output. Entries with no URL (katana
// sometimes emits lines without a request URL) are skipped and counted.
// request.url is preferred; request.endpoint is the fallback.
func ParseKatana(data []byte) ([]CrawledURL, int, error) {
	entries, skipped, err := parseJSONLines[KatanaEntry](data)
	if err != nil {
		return nil, skipped, err
	}
	out := []CrawledURL{}
	for _, e := range entries {
		if strings.TrimSpace(e.Error) != "" {
			// Failed fetch (e.g. TLS handshake error): not a crawled
			// URL. Skip and count it.
			skipped++
			continue
		}
		u := strings.TrimSpace(e.Request.URL)
		if u == "" {
			u = strings.TrimSpace(e.Request.Endpoint)
		}
		if u == "" {
			skipped++
			continue
		}
		out = append(out, CrawledURL{
			URL:          u,
			Method:       e.Request.Method,
			StatusCode:   e.Response.StatusCode,
			Technologies: e.Response.Technologies,
			Source:       e.Request.Source,
		})
	}
	return out, skipped, nil
}

// JSFiles returns the crawled URLs that point at JavaScript files — the
// input list for the Week 2 JS secret scraper (workstream B / Python).
// A URL counts if its path (before any ? or #) ends in .js. Unlike
// dedupeSorted, this preserves URL case: paths are case-sensitive, so
// lowercasing would corrupt the URL.
func JSFiles(urls []CrawledURL) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, u := range urls {
		path := u.URL
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
		if strings.HasSuffix(strings.ToLower(path), ".js") {
			if !seen[u.URL] {
				seen[u.URL] = true
				out = append(out, u.URL)
			}
		}
	}
	sort.Strings(out)
	return out
}
