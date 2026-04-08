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

func TestBridgeScanOptionsWithRequestResponseTargets(t *testing.T) {
	in := &BridgeScanOptions{
		RequestResponseTargets: []BridgeRequestResponseTarget{
			{
				URL:    "https://example.com/api/users",
				Method: "POST",
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer token123",
				},
				Body: `{"name":"test"}`,
			},
			{
				URL:    "https://example.com/api/health",
				Method: "GET",
			},
		},
	}

	out := in.toScanOptions()

	if len(out.RequestResponseTargets) != 2 {
		t.Fatalf("expected 2 RequestResponseTargets, got %d", len(out.RequestResponseTargets))
	}

	rrt := out.RequestResponseTargets[0]
	if rrt.URL != "https://example.com/api/users" {
		t.Fatalf("unexpected URL: %s", rrt.URL)
	}
	if rrt.Method != "POST" {
		t.Fatalf("unexpected method: %s", rrt.Method)
	}
	if rrt.Headers["Content-Type"] != "application/json" {
		t.Fatalf("unexpected Content-Type: %v", rrt.Headers)
	}
	if rrt.Body != `{"name":"test"}` {
		t.Fatalf("unexpected body: %s", rrt.Body)
	}

	rrt2 := out.RequestResponseTargets[1]
	if rrt2.Method != "GET" {
		t.Fatalf("expected GET for second target, got %s", rrt2.Method)
	}
	if len(rrt2.Headers) != 0 {
		t.Fatalf("expected no headers for second target, got %v", rrt2.Headers)
	}
}

func TestScanResultToData(t *testing.T) {
	in := &nucleisdk.ScanResult{
		TemplateID:    "tpl-1",
		TemplateName:  "Test",
		Severity:      "high",
		Host:          "example.com",
		MatchedURL:    "https://example.com",
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
