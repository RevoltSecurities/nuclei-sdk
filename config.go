package nucleisdk

import (
	"io"
	"time"
)

// ScanConfig holds all scanner configuration, populated by Option functions.
type ScanConfig struct {
	// Template sources
	templateDirs   []string
	templateFiles  []string
	templateBytes  []templateBytesEntry
	templateURLs   []string
	workflows      []string
	trustedDomains []string

	// Template filters
	tags            []string
	excludeTags     []string
	severity        []string
	excludeSeverity []string
	templateIDs     []string
	excludeIDs      []string
	protocolTypes   string
	authors         []string

	// Targets
	targets        []string
	targetFile     string
	targetReader   io.Reader
	excludeTargets []string
	openAPISpec    string
	openAPIMode    string

	// HTTP probing
	httpProbe        bool
	probeConcurrency int
	scanAllIPs       bool
	ipVersion        []string

	// Network & proxy
	proxy         []string
	proxyInternal bool
	timeout       int
	retries       int

	// Concurrency
	templateThreads    int
	hostConcurrency    int
	rateLimitCount     int
	rateLimitDuration  time.Duration
	payloadConcurrency int

	// Auth
	authConfigs  []AuthConfig
	secretsFiles []string

	// Headers & variables
	customHeaders []string
	customVars    []string

	// Features
	headless      bool
	headlessOpts  *HeadlessConfig
	scanStrategy  string
	dastMode      bool
	enableCode    bool
	matcherStatus bool

	// Interactsh
	noInteractsh bool

	// Template execution modes
	selfContainedTemplates  bool
	globalMatchersTemplates bool
	disableTemplateCache    bool
	enableFileTemplates     bool
	passiveMode             bool
	signedTemplatesOnly     bool

	// Response handling
	responseReadSize int

	// Sandbox
	sandboxAllowLocalFile  bool
	sandboxRestrictNetwork bool

	// Execution control
	stopAtFirstMatch  bool
	disableMaxHostErr bool

	// Advanced network
	leaveDefaultPorts bool
	networkInterface  string
	sourceIP          string
	systemResolvers   bool
	resolversList     []string

	// Verbosity
	verbose bool
	debug   bool
	silent  bool

	// Result handling
	resultSeverityFilter []string

	// Disable update check (default true for SDK usage)
	disableUpdateCheck bool
}

// TemplateBytesEntry holds a named raw YAML template.
type TemplateBytesEntry struct {
	Name string
	Data []byte
}

// templateBytesEntry is an alias for internal use.
type templateBytesEntry = TemplateBytesEntry

// TemplateBytes creates a TemplateBytesEntry from a name and YAML data.
func TemplateBytes(name string, data []byte) TemplateBytesEntry {
	return TemplateBytesEntry{Name: name, Data: data}
}

// HeadlessConfig wraps headless browser options.
type HeadlessConfig struct {
	PageTimeout int
	ShowBrowser bool
	UseChrome   bool
	ExtraArgs   []string
}

// Scan strategy constants.
const (
	StrategyTemplateSpray = "template-spray"
	StrategyHostSpray     = "host-spray"
)

// newScanConfig returns a ScanConfig with sensible defaults.
func newScanConfig() *ScanConfig {
	return &ScanConfig{
		timeout:            10,
		retries:            1,
		templateThreads:    25,
		hostConcurrency:    25,
		rateLimitCount:     150,
		rateLimitDuration:  time.Second,
		scanStrategy:       StrategyTemplateSpray,
		disableUpdateCheck: true,
	}
}
