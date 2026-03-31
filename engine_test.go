package nucleisdk

import (
	"bytes"
	"testing"
)

func TestParseConcurrentScan(t *testing.T) {
	se := &ScanEngine{}

	scan := ConcurrentScan{
		Label: "job-1",
		Options: []Option{
			WithTargets("https://example.com"),
			WithTags("cve", "exposure"),
			WithTemplateBytes("cve-123", []byte("id: test")),
			WithResultSeverityFilter("high"),
		},
	}

	opts, err := se.parseConcurrentScan(scan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(opts.Targets) != 1 || opts.Targets[0] != "https://example.com" {
		t.Fatalf("unexpected targets: %#v", opts.Targets)
	}
	if len(opts.Tags) != 2 {
		t.Fatalf("unexpected tags: %#v", opts.Tags)
	}
	if len(opts.TemplateBytes) != 1 || opts.TemplateBytes[0].Name != "cve-123" {
		t.Fatalf("unexpected template bytes: %#v", opts.TemplateBytes)
	}
	if !bytes.Equal(opts.TemplateBytes[0].Data, []byte("id: test")) {
		t.Fatalf("template bytes data mismatch")
	}
	if len(opts.ResultSeverityFilter) != 1 || opts.ResultSeverityFilter[0] != "high" {
		t.Fatalf("unexpected result severity filter: %#v", opts.ResultSeverityFilter)
	}
}
