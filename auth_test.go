package nucleisdk

import (
	"reflect"
	"testing"
)

func TestMatchesDomain(t *testing.T) {
	if !matchesDomain("api.example.com", []string{"example.com"}) {
		t.Fatalf("expected subdomain match")
	}
	if !matchesDomain("EXAMPLE.com", []string{"example.com"}) {
		t.Fatalf("expected case-insensitive match")
	}
	if matchesDomain("example.net", []string{"example.com"}) {
		t.Fatalf("expected non-matching domain to fail")
	}
	if !matchesDomain("any.host", nil) {
		t.Fatalf("expected empty domain list to match all")
	}
}

func TestExtractDomainsFromTargets(t *testing.T) {
	targets := []string{
		"https://a.example.com/path",
		"http://b.example.com:8080",
		"example.com",
		"1.2.3.4",
		"https://a.example.com/other",
	}

	domains := extractDomainsFromTargets(targets)
	got := make(map[string]bool, len(domains))
	for _, d := range domains {
		got[d] = true
	}

	want := map[string]bool{
		"a.example.com": true,
		"b.example.com": true,
		"example.com":   true,
		"1.2.3.4":       true,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected domains: %#v", domains)
	}
}
