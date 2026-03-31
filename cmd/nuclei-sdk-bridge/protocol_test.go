package main

import (
	"encoding/base64"
	"testing"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

func TestBridgeScanOptionsToScanOptions(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("id: test"))

	in := &BridgeScanOptions{
		Targets: []string{"https://example.com"},
		TemplateBytes: []BridgeTemplateBytesEntry{
			{Name: "tmpl", Data: encoded},
			{Name: "bad", Data: "!!notbase64!!"},
		},
		ResultSeverityFilter: []string{"high"},
	}

	out := in.toScanOptions()

	if len(out.Targets) != 1 || out.Targets[0] != "https://example.com" {
		t.Fatalf("unexpected targets: %#v", out.Targets)
	}
	if len(out.TemplateBytes) != 1 {
		t.Fatalf("expected 1 decoded template, got %d", len(out.TemplateBytes))
	}
	if out.TemplateBytes[0].Name != "tmpl" {
		t.Fatalf("unexpected template name: %s", out.TemplateBytes[0].Name)
	}
	if string(out.TemplateBytes[0].Data) != "id: test" {
		t.Fatalf("unexpected template data: %q", string(out.TemplateBytes[0].Data))
	}
	if len(out.ResultSeverityFilter) != 1 || out.ResultSeverityFilter[0] != "high" {
		t.Fatalf("unexpected severity filter: %#v", out.ResultSeverityFilter)
	}
}

func TestScanResultToData(t *testing.T) {
	in := &nucleisdk.ScanResult{
		TemplateID:   "tpl-1",
		TemplateName: "Test",
		Severity:     "high",
		Host:         "example.com",
		MatchedURL:   "https://example.com",
		MatcherStatus: true,
	}

	out := scanResultToData(in)

	if out.TemplateID != "tpl-1" || out.TemplateName != "Test" {
		t.Fatalf("unexpected template fields: %#v", out)
	}
	if out.Severity != "high" || out.Host != "example.com" {
		t.Fatalf("unexpected core fields: %#v", out)
	}
	if out.MatcherStatus != true {
		t.Fatalf("expected matcher_status to be true")
	}
}
