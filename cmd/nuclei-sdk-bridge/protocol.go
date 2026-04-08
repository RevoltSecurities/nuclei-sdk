package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
)

// --- Request types (Python → Go, stdin) ---

// Request is the top-level JSON command from the Python client.
type Request struct {
	Cmd     string             `json:"cmd"`
	ID      string             `json:"id,omitempty"`
	Config  *BridgeConfig      `json:"config,omitempty"`
	Options *BridgeScanOptions `json:"options,omitempty"`
	Label   string             `json:"label,omitempty"`
	Workers int                `json:"workers,omitempty"`
}

// BridgeConfig maps to ScanEngine configuration (used in "setup" command).
type BridgeConfig struct {
	// Template sources
	TemplateDirs  []string `json:"template_dirs,omitempty"`
	TemplateFiles []string `json:"template_files,omitempty"`
	Workflows     []string `json:"workflows,omitempty"`

	// Template filters
	Tags            []string `json:"tags,omitempty"`
	ExcludeTags     []string `json:"exclude_tags,omitempty"`
	Severities      []string `json:"severities,omitempty"`
	ExcludeSeverity []string `json:"exclude_severities,omitempty"`
	ProtocolTypes   string   `json:"protocol_types,omitempty"`
	TemplateIDs     []string `json:"template_ids,omitempty"`
	ExcludeIDs      []string `json:"exclude_ids,omitempty"`
	Authors         []string `json:"authors,omitempty"`

	// Network
	Timeout int      `json:"timeout,omitempty"`
	Retries int      `json:"retries,omitempty"`
	Proxy   []string `json:"proxy,omitempty"`

	// Concurrency
	Threads         int `json:"threads,omitempty"`
	HostConcurrency int `json:"host_concurrency,omitempty"`
	RateLimit       int `json:"rate_limit,omitempty"`

	// Features
	Headless     bool `json:"headless,omitempty"`
	DASTMode     bool `json:"dast_mode,omitempty"`
	NoInteractsh bool `json:"no_interactsh,omitempty"`

	// Verbosity
	Verbose bool `json:"verbose,omitempty"`
	Debug   bool `json:"debug,omitempty"`
	Silent  bool `json:"silent,omitempty"`

	// Auth
	Auth         []BridgeAuthConfig `json:"auth,omitempty"`
	SecretsFiles []string           `json:"secrets_files,omitempty"`

	// Headers & Variables
	CustomHeaders []string `json:"custom_headers,omitempty"`
	CustomVars    []string `json:"custom_vars,omitempty"`

	// Template loading (additional)
	TemplateBytes  []BridgeTemplateBytesEntry `json:"template_bytes,omitempty"`
	TemplateURLs   []string                   `json:"template_urls,omitempty"`
	TrustedDomains []string                   `json:"trusted_domains,omitempty"`

	// Network (additional)
	ProxyInternal bool `json:"proxy_internal,omitempty"`

	// Concurrency (additional)
	RateLimitDuration  string `json:"rate_limit_duration,omitempty"`
	PayloadConcurrency int    `json:"payload_concurrency,omitempty"`

	// Features (additional)
	ScanStrategy  string `json:"scan_strategy,omitempty"`
	CodeTemplates bool   `json:"code_templates,omitempty"`
	MatcherStatus bool   `json:"matcher_status,omitempty"`
	UpdateCheck   bool   `json:"update_check,omitempty"`

	// Template execution modes
	SelfContainedTemplates  bool `json:"self_contained_templates,omitempty"`
	GlobalMatchersTemplates bool `json:"global_matchers_templates,omitempty"`
	DisableTemplateCache    bool `json:"disable_template_cache,omitempty"`
	FileTemplates           bool `json:"file_templates,omitempty"`
	PassiveMode             bool `json:"passive_mode,omitempty"`
	SignedTemplatesOnly     bool `json:"signed_templates_only,omitempty"`

	// Response
	ResponseReadSize int `json:"response_read_size,omitempty"`

	// Sandbox
	SandboxAllowLocalFile  bool `json:"sandbox_allow_local_file,omitempty"`
	SandboxRestrictNetwork bool `json:"sandbox_restrict_network,omitempty"`

	// Advanced network
	LeaveDefaultPorts bool     `json:"leave_default_ports,omitempty"`
	NetworkInterface  string   `json:"network_interface,omitempty"`
	SourceIP          string   `json:"source_ip,omitempty"`
	SystemResolvers   bool     `json:"system_resolvers,omitempty"`
	Resolvers         []string `json:"resolvers,omitempty"`
	DisableMaxHostErr bool     `json:"disable_max_host_err,omitempty"`

	// Execution control
	StopAtFirstMatch bool `json:"stop_at_first_match,omitempty"`

	// Result filtering
	ResultSeverityFilter []string `json:"result_severity_filter,omitempty"`

	// Target options
	OpenAPISpec    string   `json:"openapi_spec,omitempty"`
	SwaggerSpec    string   `json:"swagger_spec,omitempty"`
	ExcludeTargets []string `json:"exclude_targets,omitempty"`

	// HTTP probing
	HTTPProbe        bool     `json:"http_probe,omitempty"`
	ProbeConcurrency int      `json:"probe_concurrency,omitempty"`
	ScanAllIPs       bool     `json:"scan_all_ips,omitempty"`
	IPVersion        []string `json:"ip_version,omitempty"`
}

// BridgeAuthConfig maps to nucleisdk.AuthConfig.
type BridgeAuthConfig struct {
	Type        string            `json:"type"`
	Domains     []string          `json:"domains,omitempty"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Token       string            `json:"token,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Cookies     map[string]string `json:"cookies,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
}

// BridgeScanOptions maps to nucleisdk.ScanOptions (used in "scan" / "pool_submit").
type BridgeScanOptions struct {
	Targets              []string                   `json:"targets,omitempty"`
	TargetFile           string                     `json:"target_file,omitempty"`
	Tags                 []string                   `json:"tags,omitempty"`
	ExcludeTags          []string                   `json:"exclude_tags,omitempty"`
	Severities           []string                   `json:"severities,omitempty"`
	ProtocolTypes        string                     `json:"protocol_types,omitempty"`
	TemplateIDs          []string                   `json:"template_ids,omitempty"`
	ExcludeIDs           []string                   `json:"exclude_ids,omitempty"`
	Authors              []string                   `json:"authors,omitempty"`
	TemplateFiles        []string                   `json:"template_files,omitempty"`
	TemplateDirs         []string                   `json:"template_dirs,omitempty"`
	TemplateBytes        []BridgeTemplateBytesEntry `json:"template_bytes,omitempty"`
	ResultSeverityFilter []string                   `json:"result_severity_filter,omitempty"`

	// RequestResponseTargets provides full HTTP request metadata for DAST fuzzing.
	// When set, nuclei preserves the method, headers, and body instead of defaulting to GET.
	RequestResponseTargets []BridgeRequestResponseTarget `json:"request_response_targets,omitempty"`
}

// BridgeRequestResponseTarget holds full HTTP request metadata for a DAST target.
type BridgeRequestResponseTarget struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// BridgeTemplateBytesEntry holds a named template with base64-encoded data.
type BridgeTemplateBytesEntry struct {
	Name string `json:"name"`
	Data string `json:"data"` // base64 encoded
}

// --- Response types (Go → Python, stdout) ---

// Response is the top-level JSON response sent to the Python client.
type Response struct {
	ID    string           `json:"id,omitempty"`
	Type  string           `json:"type"`
	Data  *json.RawMessage `json:"data,omitempty"`
	Label string           `json:"label,omitempty"`
	Error string           `json:"error,omitempty"`
}

// ResultData is the scan result payload in "result" / "pool_result" responses.
type ResultData struct {
	TemplateID       string                 `json:"template_id"`
	TemplateName     string                 `json:"template_name"`
	TemplatePath     string                 `json:"template_path,omitempty"`
	Severity         string                 `json:"severity"`
	Type             string                 `json:"type"`
	Host             string                 `json:"host"`
	MatchedURL       string                 `json:"matched_url"`
	MatcherName      string                 `json:"matcher_name,omitempty"`
	ExtractorName    string                 `json:"extractor_name,omitempty"`
	ExtractedResults []string               `json:"extracted_results,omitempty"`
	IP               string                 `json:"ip,omitempty"`
	Port             string                 `json:"port,omitempty"`
	Scheme           string                 `json:"scheme,omitempty"`
	URL              string                 `json:"url,omitempty"`
	Path             string                 `json:"path,omitempty"`
	Request          string                 `json:"request,omitempty"`
	Response         string                 `json:"response,omitempty"`
	CURLCommand      string                 `json:"curl_command,omitempty"`
	Tags             []string               `json:"tags,omitempty"`
	Authors          []string               `json:"authors,omitempty"`
	Description      string                 `json:"description,omitempty"`
	Impact           string                 `json:"impact,omitempty"`
	Remediation      string                 `json:"remediation,omitempty"`
	Reference        []string               `json:"reference,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CVEID            []string               `json:"cve_id,omitempty"`
	CWEID            []string               `json:"cwe_id,omitempty"`
	CVSSMetrics      string                 `json:"cvss_metrics,omitempty"`
	CVSSScore        float64                `json:"cvss_score,omitempty"`
	EPSSScore        float64                `json:"epss_score,omitempty"`
	CPE              string                 `json:"cpe,omitempty"`
	IsFuzzingResult  bool                   `json:"is_fuzzing_result,omitempty"`
	FuzzingMethod    string                 `json:"fuzzing_method,omitempty"`
	FuzzingParameter string                 `json:"fuzzing_parameter,omitempty"`
	FuzzingPosition  string                 `json:"fuzzing_position,omitempty"`
	MatcherStatus    bool                   `json:"matcher_status"`
	Timestamp        time.Time              `json:"timestamp"`
	ResultError      string                 `json:"error,omitempty"`
}

// --- Conversion helpers ---

// toEngineOptions converts BridgeConfig to nucleisdk.Option slice.
func (c *BridgeConfig) toEngineOptions() []nucleisdk.Option {
	var opts []nucleisdk.Option

	// Template sources
	for _, d := range c.TemplateDirs {
		opts = append(opts, nucleisdk.WithTemplateDir(d))
	}
	if len(c.TemplateFiles) > 0 {
		opts = append(opts, nucleisdk.WithTemplateFiles(c.TemplateFiles...))
	}
	if len(c.Workflows) > 0 {
		opts = append(opts, nucleisdk.WithWorkflows(c.Workflows...))
	}

	// Template filters
	if len(c.Tags) > 0 {
		opts = append(opts, nucleisdk.WithTags(c.Tags...))
	}
	if len(c.ExcludeTags) > 0 {
		opts = append(opts, nucleisdk.WithExcludeTags(c.ExcludeTags...))
	}
	if len(c.Severities) > 0 {
		opts = append(opts, nucleisdk.WithSeverityFilter(c.Severities...))
	}
	if len(c.ExcludeSeverity) > 0 {
		opts = append(opts, nucleisdk.WithExcludeSeverities(c.ExcludeSeverity...))
	}
	if c.ProtocolTypes != "" {
		opts = append(opts, nucleisdk.WithProtocolTypes(c.ProtocolTypes))
	}
	if len(c.TemplateIDs) > 0 {
		opts = append(opts, nucleisdk.WithTemplateIDs(c.TemplateIDs...))
	}
	if len(c.ExcludeIDs) > 0 {
		opts = append(opts, nucleisdk.WithExcludeTemplateIDs(c.ExcludeIDs...))
	}
	if len(c.Authors) > 0 {
		opts = append(opts, nucleisdk.WithAuthors(c.Authors...))
	}

	// Network
	if c.Timeout > 0 {
		opts = append(opts, nucleisdk.WithTimeout(c.Timeout))
	}
	if c.Retries > 0 {
		opts = append(opts, nucleisdk.WithRetries(c.Retries))
	}
	for _, p := range c.Proxy {
		opts = append(opts, nucleisdk.WithProxy(p))
	}

	// Concurrency
	if c.Threads > 0 {
		opts = append(opts, nucleisdk.WithThreads(c.Threads))
	}
	if c.HostConcurrency > 0 {
		opts = append(opts, nucleisdk.WithHostConcurrency(c.HostConcurrency))
	}
	if c.RateLimit > 0 {
		opts = append(opts, nucleisdk.WithRateLimit(c.RateLimit))
	}

	// Features
	if c.Headless {
		opts = append(opts, nucleisdk.WithHeadless(nil))
	}
	if c.NoInteractsh {
		opts = append(opts, nucleisdk.WithNoInteractsh())
	}
	if c.DASTMode {
		opts = append(opts, nucleisdk.WithDASTMode())
	}

	// Verbosity
	if c.Verbose {
		opts = append(opts, nucleisdk.WithVerbose())
	}
	if c.Debug {
		opts = append(opts, nucleisdk.WithDebug())
	}
	if c.Silent {
		opts = append(opts, nucleisdk.WithSilent())
	}

	// Auth
	for _, a := range c.Auth {
		opts = append(opts, nucleisdk.WithAuth(a.toAuthConfig()))
	}
	if len(c.SecretsFiles) > 0 {
		opts = append(opts, nucleisdk.WithSecretsFiles(c.SecretsFiles...))
	}

	// Headers & Variables
	if len(c.CustomHeaders) > 0 {
		opts = append(opts, nucleisdk.WithHeaders(c.CustomHeaders...))
	}
	if len(c.CustomVars) > 0 {
		opts = append(opts, nucleisdk.WithVars(c.CustomVars...))
	}

	// Template loading (additional)
	for _, tb := range c.TemplateBytes {
		data, err := base64.StdEncoding.DecodeString(tb.Data)
		if err != nil {
			continue
		}
		opts = append(opts, nucleisdk.WithTemplateBytes(tb.Name, data))
	}
	if len(c.TemplateURLs) > 0 {
		opts = append(opts, nucleisdk.WithTemplateURLs(c.TemplateURLs...))
	}
	if len(c.TrustedDomains) > 0 {
		opts = append(opts, nucleisdk.WithTrustedDomains(c.TrustedDomains...))
	}

	// Network (additional)
	if c.ProxyInternal {
		opts = append(opts, nucleisdk.WithProxyInternal(true))
	}

	// Concurrency (additional)
	if c.RateLimitDuration != "" && c.RateLimit > 0 {
		if dur, err := time.ParseDuration(c.RateLimitDuration); err == nil {
			opts = append(opts, nucleisdk.WithRateLimitCustom(c.RateLimit, dur))
		}
	}
	if c.PayloadConcurrency > 0 {
		opts = append(opts, nucleisdk.WithPayloadConcurrency(c.PayloadConcurrency))
	}

	// Features (additional)
	if c.ScanStrategy != "" {
		opts = append(opts, nucleisdk.WithScanStrategy(c.ScanStrategy))
	}
	if c.CodeTemplates {
		opts = append(opts, nucleisdk.WithCodeTemplates())
	}
	if c.MatcherStatus {
		opts = append(opts, nucleisdk.WithMatcherStatus())
	}
	if c.UpdateCheck {
		opts = append(opts, nucleisdk.WithUpdateCheck())
	}

	// Template execution modes
	if c.SelfContainedTemplates {
		opts = append(opts, nucleisdk.WithSelfContainedTemplates())
	}
	if c.GlobalMatchersTemplates {
		opts = append(opts, nucleisdk.WithGlobalMatchersTemplates())
	}
	if c.DisableTemplateCache {
		opts = append(opts, nucleisdk.WithDisableTemplateCache())
	}
	if c.FileTemplates {
		opts = append(opts, nucleisdk.WithFileTemplates())
	}
	if c.PassiveMode {
		opts = append(opts, nucleisdk.WithPassiveMode())
	}
	if c.SignedTemplatesOnly {
		opts = append(opts, nucleisdk.WithSignedTemplatesOnly())
	}

	// Response
	if c.ResponseReadSize > 0 {
		opts = append(opts, nucleisdk.WithResponseReadSize(c.ResponseReadSize))
	}

	// Sandbox
	if c.SandboxAllowLocalFile || c.SandboxRestrictNetwork {
		opts = append(opts, nucleisdk.WithSandboxOptions(c.SandboxAllowLocalFile, c.SandboxRestrictNetwork))
	}

	// Advanced network
	if c.LeaveDefaultPorts {
		opts = append(opts, nucleisdk.WithLeaveDefaultPorts())
	}
	if c.NetworkInterface != "" {
		opts = append(opts, nucleisdk.WithNetworkInterface(c.NetworkInterface))
	}
	if c.SourceIP != "" {
		opts = append(opts, nucleisdk.WithSourceIP(c.SourceIP))
	}
	if c.SystemResolvers {
		opts = append(opts, nucleisdk.WithSystemResolvers())
	}
	if len(c.Resolvers) > 0 {
		opts = append(opts, nucleisdk.WithResolvers(c.Resolvers...))
	}
	if c.DisableMaxHostErr {
		opts = append(opts, nucleisdk.WithDisableMaxHostErr())
	}

	// Execution control
	if c.StopAtFirstMatch {
		opts = append(opts, nucleisdk.WithStopAtFirstMatch())
	}

	// Result filtering
	if len(c.ResultSeverityFilter) > 0 {
		opts = append(opts, nucleisdk.WithResultSeverityFilter(c.ResultSeverityFilter...))
	}

	// Target options
	if c.OpenAPISpec != "" {
		opts = append(opts, nucleisdk.WithOpenAPISpec(c.OpenAPISpec))
	}
	if c.SwaggerSpec != "" {
		opts = append(opts, nucleisdk.WithSwaggerSpec(c.SwaggerSpec))
	}
	if len(c.ExcludeTargets) > 0 {
		opts = append(opts, nucleisdk.WithExcludeTargets(c.ExcludeTargets...))
	}

	// HTTP probing
	if c.HTTPProbe {
		opts = append(opts, nucleisdk.WithHTTPProbe())
	}
	if c.ProbeConcurrency > 0 {
		opts = append(opts, nucleisdk.WithProbeConcurrency(c.ProbeConcurrency))
	}
	if c.ScanAllIPs {
		opts = append(opts, nucleisdk.WithScanAllIPs())
	}
	if len(c.IPVersion) > 0 {
		opts = append(opts, nucleisdk.WithIPVersion(c.IPVersion...))
	}

	return opts
}

// toAuthConfig converts BridgeAuthConfig to nucleisdk.AuthConfig.
func (a *BridgeAuthConfig) toAuthConfig() nucleisdk.AuthConfig {
	switch strings.ToLower(a.Type) {
	case "basic":
		return nucleisdk.BasicAuth(a.Username, a.Password, a.Domains...)
	case "bearer":
		return nucleisdk.BearerToken(a.Token, a.Domains...)
	case "header":
		return nucleisdk.HeaderAuth(a.Headers, a.Domains...)
	case "cookie":
		return nucleisdk.CookieAuth(a.Cookies, a.Domains...)
	case "query":
		return nucleisdk.QueryAuth(a.QueryParams, a.Domains...)
	case "apikey":
		for k, v := range a.Headers {
			return nucleisdk.APIKeyHeader(k, v, a.Domains...)
		}
	}
	return nucleisdk.AuthConfig{}
}

// toScanOptions converts BridgeScanOptions to nucleisdk.ScanOptions.
func (o *BridgeScanOptions) toScanOptions() *nucleisdk.ScanOptions {
	opts := &nucleisdk.ScanOptions{
		Targets:       o.Targets,
		TargetFile:    o.TargetFile,
		Tags:          o.Tags,
		ExcludeTags:   o.ExcludeTags,
		Severities:    o.Severities,
		ProtocolTypes: o.ProtocolTypes,
		TemplateIDs:   o.TemplateIDs,
		ExcludeIDs:    o.ExcludeIDs,
		Authors:       o.Authors,
		TemplateFiles: o.TemplateFiles,
		TemplateDirs:  o.TemplateDirs,
	}

	for _, tb := range o.TemplateBytes {
		data, err := base64.StdEncoding.DecodeString(tb.Data)
		if err != nil {
			continue
		}
		opts.TemplateBytes = append(opts.TemplateBytes,
			nucleisdk.TemplateBytesEntry{Name: tb.Name, Data: data})
	}

	opts.ResultSeverityFilter = o.ResultSeverityFilter

	// Convert RequestResponseTargets for DAST fuzzing
	for _, rrt := range o.RequestResponseTargets {
		opts.RequestResponseTargets = append(opts.RequestResponseTargets,
			nucleisdk.RequestResponseTarget{
				URL:     rrt.URL,
				Method:  rrt.Method,
				Headers: rrt.Headers,
				Body:    rrt.Body,
			})
	}

	return opts
}

// scanResultToData converts a nucleisdk.ScanResult to ResultData for JSON output.
func scanResultToData(r *nucleisdk.ScanResult) *ResultData {
	return &ResultData{
		TemplateID:       r.TemplateID,
		TemplateName:     r.TemplateName,
		TemplatePath:     r.TemplatePath,
		Severity:         r.Severity,
		Type:             r.Type,
		Host:             r.Host,
		MatchedURL:       r.MatchedURL,
		MatcherName:      r.MatcherName,
		ExtractorName:    r.ExtractorName,
		ExtractedResults: r.ExtractedResults,
		IP:               r.IP,
		Port:             r.Port,
		Scheme:           r.Scheme,
		URL:              r.URL,
		Path:             r.Path,
		Request:          r.Request,
		Response:         r.Response,
		CURLCommand:      r.CURLCommand,
		Tags:             r.Tags,
		Authors:          r.Authors,
		Description:      r.Description,
		Impact:           r.Impact,
		Remediation:      r.Remediation,
		Reference:        r.Reference,
		Metadata:         r.Metadata,
		CVEID:            r.CVEID,
		CWEID:            r.CWEID,
		CVSSMetrics:      r.CVSSMetrics,
		CVSSScore:        r.CVSSScore,
		EPSSScore:        r.EPSSScore,
		CPE:              r.CPE,
		IsFuzzingResult:  r.IsFuzzingResult,
		FuzzingMethod:    r.FuzzingMethod,
		FuzzingParameter: r.FuzzingParameter,
		FuzzingPosition:  r.FuzzingPosition,
		MatcherStatus:    r.MatcherStatus,
		Timestamp:        r.Timestamp,
		ResultError:      r.Error,
	}
}
