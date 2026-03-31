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
