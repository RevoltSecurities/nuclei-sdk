package nucleisdk

import "testing"

func TestScanOptionsHasDirectTemplates(t *testing.T) {
	opts := &ScanOptions{}
	if opts.hasDirectTemplates() {
		t.Fatalf("expected no direct templates by default")
	}

	opts.TemplateFiles = []string{"one.yaml"}
	if !opts.hasDirectTemplates() {
		t.Fatalf("expected template files to trigger direct mode")
	}

	opts.TemplateFiles = nil
	opts.TemplateDirs = []string{"./templates"}
	if !opts.hasDirectTemplates() {
		t.Fatalf("expected template dirs to trigger direct mode")
	}

	opts.TemplateDirs = nil
	opts.TemplateBytes = []TemplateBytesEntry{{Name: "test", Data: []byte("x")}}
	if !opts.hasDirectTemplates() {
		t.Fatalf("expected template bytes to trigger direct mode")
	}
}

func TestRequestResponseTargetDefaults(t *testing.T) {
	rrt := RequestResponseTarget{
		URL:    "https://example.com/api/users",
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: `{"name":"test"}`,
	}

	if rrt.URL != "https://example.com/api/users" {
		t.Fatalf("unexpected URL: %s", rrt.URL)
	}
	if rrt.Method != "POST" {
		t.Fatalf("unexpected method: %s", rrt.Method)
	}
	if rrt.Headers["Content-Type"] != "application/json" {
		t.Fatalf("unexpected Content-Type header: %v", rrt.Headers)
	}
	if rrt.Body != `{"name":"test"}` {
		t.Fatalf("unexpected body: %s", rrt.Body)
	}
}

func TestScanOptionsWithRequestResponseTargets(t *testing.T) {
	opts := &ScanOptions{
		RequestResponseTargets: []RequestResponseTarget{
			{
				URL:    "https://example.com/api/users",
				Method: "POST",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: `{"name":"test"}`,
			},
		},
	}

	if len(opts.RequestResponseTargets) != 1 {
		t.Fatalf("expected 1 RequestResponseTarget, got %d", len(opts.RequestResponseTargets))
	}
	if opts.RequestResponseTargets[0].Method != "POST" {
		t.Fatalf("expected POST method, got %s", opts.RequestResponseTargets[0].Method)
	}
}
