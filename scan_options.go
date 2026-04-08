package nucleisdk

// RequestResponseTarget provides full HTTP request metadata for DAST fuzzing.
//
// When nuclei's fuzzing engine receives a target with only a URL, it defaults to
// GET with no body (the "URL-only" code path in request_fuzz.go). By providing
// a RequestResponseTarget, the SDK constructs a full RequestResponse object that
// triggers nuclei's "ReqResp" code path, which preserves the HTTP method, headers,
// and body during fuzzing.
//
// This is essential for testing POST/PUT/PATCH endpoints where the fuzzing engine
// needs to know the original method and body to inject payloads correctly.
type RequestResponseTarget struct {
	URL     string            // Full URL (e.g., "https://example.com/api/users")
	Method  string            // HTTP method (e.g., "POST", "PUT")
	Headers map[string]string // Request headers (e.g., Content-Type, Authorization)
	Body    string            // Request body (e.g., JSON payload)
}

// ScanOptions defines per-scan parameters for ScanEngine.Scan().
// These are lightweight, per-invocation settings — targets, template filters, etc.
// Global resources (interactsh, parser, catalog, browser) are shared from the engine.
//
// Template selection works in two modes:
//
//  1. Filter mode (default): When only Tags/Severities/ProtocolTypes/TemplateIDs are set,
//     templates are filtered at runtime from the engine's pre-loaded global template store.
//
//  2. Direct mode: When TemplateFiles, TemplateDirs, or TemplateBytes are set,
//     ONLY those templates are loaded and used for this scan. The global store is not used.
//     This is ideal for targeted scans where you know exactly which template to run.
type ScanOptions struct {
	// Targets to scan (URLs, domains, IPs, host:port)
	Targets    []string
	TargetFile string

	// RequestResponseTargets provides full HTTP request metadata for DAST fuzzing.
	// When set, these targets are loaded with their method, headers, and body preserved,
	// triggering nuclei's ReqResp code path instead of the URL-only path that defaults to GET.
	// Plain URL Targets are still supported alongside these.
	RequestResponseTargets []RequestResponseTarget

	// Template filtering (applied at runtime against the pre-loaded template store)
	// These are ignored when TemplateFiles/TemplateDirs/TemplateBytes are set.
	Tags          []string
	ExcludeTags   []string
	Severities    []string
	ProtocolTypes string // "http", "dns", "ssl", "network" — comma-separated
	TemplateIDs   []string
	ExcludeIDs    []string
	Authors       []string

	// Per-scan template sources (direct mode — bypasses global store)
	TemplateFiles []string             // Specific template file paths for this scan
	TemplateDirs  []string             // Template directories for this scan
	TemplateBytes []TemplateBytesEntry // Raw YAML templates (e.g., from API response)

	// Result severity filter (post-scan filtering)
	ResultSeverityFilter []string
}

// hasDirectTemplates returns true if the scan specifies its own templates
// (files, dirs, or bytes) rather than filtering from the global store.
func (o *ScanOptions) hasDirectTemplates() bool {
	return len(o.TemplateFiles) > 0 || len(o.TemplateDirs) > 0 || len(o.TemplateBytes) > 0
}
