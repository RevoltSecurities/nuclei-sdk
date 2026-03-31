package nucleisdk

import "testing"

func TestMatchesSeverityFilter(t *testing.T) {
	result := &ScanResult{Severity: "High"}

	if !matchesSeverityFilter(result, nil) {
		t.Fatalf("expected empty filter to match")
	}
	if !matchesSeverityFilter(result, []string{"low", "HIGH"}) {
		t.Fatalf("expected case-insensitive match to succeed")
	}
	if matchesSeverityFilter(result, []string{"low", "medium"}) {
		t.Fatalf("expected non-matching filter to fail")
	}
}
