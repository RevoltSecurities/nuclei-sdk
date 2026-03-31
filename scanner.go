package nucleisdk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Scanner is the main entry point for running nuclei scans.
type Scanner struct {
	config *ScanConfig
	engine *nuclei.NucleiEngine
	tmpDir string
	mu     sync.Mutex
}

// NewScanner creates a new Scanner with the given options.
func NewScanner(opts ...Option) (*Scanner, error) {
	cfg := newScanConfig()
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}
	return &Scanner{config: cfg}, nil
}

// Run executes the scan and returns results via a channel.
// The channel is closed when scanning completes or the context is cancelled.
// Any scan execution errors are sent as a ScanResult with the Error field set.
func (s *Scanner) Run(ctx context.Context) (<-chan *ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.initialize(ctx); err != nil {
		return nil, err
	}

	resultCh := make(chan *ScanResult, 100)

	// Capture engine reference before goroutine to avoid race with Close()
	engine := s.engine
	severityFilter := s.config.resultSeverityFilter

	go func() {
		defer close(resultCh)
		defer s.cleanup()

		callback := func(event *output.ResultEvent) {
			result := fromResultEvent(event)
			if result == nil {
				return
			}
			if !matchesSeverityFilter(result, severityFilter) {
				return
			}
			select {
			case resultCh <- result:
			case <-ctx.Done():
				return
			}
		}

		if err := engine.ExecuteCallbackWithCtx(ctx, callback); err != nil {
			// Send error as a result so the caller can distinguish failure from zero findings
			select {
			case resultCh <- &ScanResult{Error: err.Error()}:
			case <-ctx.Done():
			}
		}
	}()

	return resultCh, nil
}

// RunWithCallback executes the scan and invokes the callback for each result.
// Blocks until scanning is complete or the context is cancelled.
func (s *Scanner) RunWithCallback(ctx context.Context, callback func(*ScanResult)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.initialize(ctx); err != nil {
		return err
	}
	defer s.cleanup()

	nucleiCallback := func(event *output.ResultEvent) {
		result := fromResultEvent(event)
		if result == nil {
			return
		}
		if !matchesSeverityFilter(result, s.config.resultSeverityFilter) {
			return
		}
		callback(result)
	}

	return s.engine.ExecuteCallbackWithCtx(ctx, nucleiCallback)
}

// Close releases resources held by the scanner.
func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup()
	return nil
}

// initialize sets up the nuclei engine and loads templates/targets.
func (s *Scanner) initialize(ctx context.Context) error {
	// Build nuclei options
	nucleiOpts, tmpDir, err := s.buildNucleiOptions(ctx)
	if err != nil {
		return fmt.Errorf("building options: %w", err)
	}
	s.tmpDir = tmpDir

	// Create engine
	engine, err := nuclei.NewNucleiEngineCtx(ctx, nucleiOpts...)
	if err != nil {
		s.removeTmpDir()
		return fmt.Errorf("creating engine: %w", err)
	}
	s.engine = engine

	// Load targets
	if err := s.loadTargets(); err != nil {
		s.cleanup()
		return fmt.Errorf("loading targets: %w", err)
	}

	return nil
}

// loadTargets loads targets into the engine based on config.
func (s *Scanner) loadTargets() error {
	cfg := s.config
	probe := cfg.httpProbe

	// OpenAPI/Swagger spec takes priority (mutually exclusive)
	if cfg.openAPISpec != "" {
		return s.engine.LoadTargetsWithHttpData(cfg.openAPISpec, cfg.openAPIMode)
	}

	// Load from targets slice
	if len(cfg.targets) > 0 {
		s.engine.LoadTargets(cfg.targets, probe)
	}

	// Load from file
	if cfg.targetFile != "" {
		targets, err := TargetsFromFile(cfg.targetFile)
		if err != nil {
			return err
		}
		if len(targets) > 0 {
			s.engine.LoadTargets(targets, probe)
		}
	}

	// Load from reader
	if cfg.targetReader != nil {
		s.engine.LoadTargetsFromReader(cfg.targetReader, probe)
	}

	return nil
}

// cleanup releases engine resources and removes temp files.
func (s *Scanner) cleanup() {
	if s.engine != nil {
		s.engine.Close()
		s.engine = nil
	}
	s.removeTmpDir()
}

// removeTmpDir removes the temporary directory if it exists.
func (s *Scanner) removeTmpDir() {
	if s.tmpDir != "" {
		os.RemoveAll(s.tmpDir)
		s.tmpDir = ""
	}
}

// buildNucleiOptions translates ScanConfig into nuclei SDK options.
// Returns the options slice, temp directory path (if created), and any error.
func (s *Scanner) buildNucleiOptions(ctx context.Context) ([]nuclei.NucleiSDKOptions, string, error) {
	cfg := s.config
	var opts []nuclei.NucleiSDKOptions
	var tmpDir string

	// Handle raw YAML bytes and URL templates by writing to temp dir
	var extraTemplatePaths []string
	if len(cfg.templateBytes) > 0 || len(cfg.templateURLs) > 0 {
		var err error
		tmpDir, err = os.MkdirTemp("", "nuclei-sdk-templates-*")
		if err != nil {
			return nil, "", fmt.Errorf("creating temp dir: %w", err)
		}

		// Write raw YAML bytes to temp files
		for _, entry := range cfg.templateBytes {
			name := entry.Name
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				name += ".yaml"
			}
			path := filepath.Join(tmpDir, name)
			if err := os.WriteFile(path, entry.Data, 0644); err != nil {
				os.RemoveAll(tmpDir)
				return nil, "", fmt.Errorf("writing template %s: %w", name, err)
			}
			extraTemplatePaths = append(extraTemplatePaths, path)
		}

		// Fetch URL templates and write to temp files
		for i, templateURL := range cfg.templateURLs {
			data, err := FetchTemplateFromURL(ctx, templateURL)
			if err != nil {
				os.RemoveAll(tmpDir)
				return nil, "", fmt.Errorf("fetching template from %s: %w", templateURL, err)
			}
			name := fmt.Sprintf("url-template-%d.yaml", i)
			// Try to extract a better name from the URL
			if parts := strings.Split(templateURL, "/"); len(parts) > 0 {
				last := parts[len(parts)-1]
				if strings.HasSuffix(last, ".yaml") || strings.HasSuffix(last, ".yml") {
					name = last
				}
			}
			path := filepath.Join(tmpDir, name)
			if err := os.WriteFile(path, data, 0644); err != nil {
				os.RemoveAll(tmpDir)
				return nil, "", fmt.Errorf("writing URL template: %w", err)
			}
			extraTemplatePaths = append(extraTemplatePaths, path)
		}
	}

	// Template sources
	var allTemplates []string
	allTemplates = append(allTemplates, cfg.templateDirs...)
	allTemplates = append(allTemplates, cfg.templateFiles...)
	allTemplates = append(allTemplates, extraTemplatePaths...)

	if len(allTemplates) > 0 || len(cfg.workflows) > 0 {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates:      allTemplates,
			Workflows:      cfg.workflows,
			TrustedDomains: cfg.trustedDomains,
		}))
	}

	// Template filters
	filters := nuclei.TemplateFilters{}
	if len(cfg.severity) > 0 {
		filters.Severity = strings.Join(cfg.severity, ",")
	}
	if len(cfg.excludeSeverity) > 0 {
		filters.ExcludeSeverities = strings.Join(cfg.excludeSeverity, ",")
	}
	if cfg.protocolTypes != "" {
		filters.ProtocolTypes = cfg.protocolTypes
	}
	if len(cfg.tags) > 0 {
		filters.Tags = cfg.tags
	}
	if len(cfg.excludeTags) > 0 {
		filters.ExcludeTags = cfg.excludeTags
	}
	if len(cfg.templateIDs) > 0 {
		filters.IDs = cfg.templateIDs
	}
	if len(cfg.excludeIDs) > 0 {
		filters.ExcludeIDs = cfg.excludeIDs
	}
	if len(cfg.authors) > 0 {
		filters.Authors = cfg.authors
	}
	opts = append(opts, nuclei.WithTemplateFilters(filters))

	// Network config
	netCfg := nuclei.NetworkConfig{
		Timeout:               cfg.timeout,
		Retries:               cfg.retries,
		LeaveDefaultPorts:     cfg.leaveDefaultPorts,
		Interface:             cfg.networkInterface,
		SourceIP:              cfg.sourceIP,
		SystemResolvers:       cfg.systemResolvers,
		InternalResolversList: cfg.resolversList,
	}
	if cfg.disableMaxHostErr {
		netCfg.DisableMaxHostErr = true
	}
	opts = append(opts, nuclei.WithNetworkConfig(netCfg))

	// Proxy
	if len(cfg.proxy) > 0 {
		opts = append(opts, nuclei.WithProxy(cfg.proxy, cfg.proxyInternal))
	}

	// Concurrency (all fields must be >= 1)
	payloadConc := cfg.payloadConcurrency
	if payloadConc <= 0 {
		payloadConc = 25
	}
	concurrency := nuclei.Concurrency{
		TemplateConcurrency:           cfg.templateThreads,
		HostConcurrency:               cfg.hostConcurrency,
		HeadlessHostConcurrency:       2,
		HeadlessTemplateConcurrency:   2,
		JavascriptTemplateConcurrency: 2,
		TemplatePayloadConcurrency:    payloadConc,
		ProbeConcurrency:              50,
	}
	opts = append(opts, nuclei.WithConcurrency(concurrency))

	// Rate limiting
	if cfg.rateLimitCount > 0 {
		opts = append(opts, nuclei.WithGlobalRateLimitCtx(ctx, cfg.rateLimitCount, cfg.rateLimitDuration))
	}

	// Headers
	if len(cfg.customHeaders) > 0 {
		opts = append(opts, nuclei.WithHeaders(cfg.customHeaders))
	}

	// Variables
	if len(cfg.customVars) > 0 {
		opts = append(opts, nuclei.WithVars(cfg.customVars))
	}

	// Auth
	if len(cfg.authConfigs) > 0 {
		targetDomains := extractDomainsFromTargets(cfg.targets)
		provider := newSDKAuthProvider(cfg.authConfigs, targetDomains)
		opts = append(opts, nuclei.WithAuthProvider(provider))
	}
	if len(cfg.secretsFiles) > 0 {
		opts = append(opts, nuclei.LoadSecretsFromFile(cfg.secretsFiles, true))
	}

	// Interactsh (no-interactsh disables OOB testing)
	if cfg.noInteractsh {
		opts = append(opts, nuclei.WithInteractshOptions(nuclei.InteractshOpts{
			NoInteractsh: true,
		}))
	}

	// Self-contained templates
	if cfg.selfContainedTemplates {
		opts = append(opts, nuclei.EnableSelfContainedTemplates())
	}

	// Global matchers templates
	if cfg.globalMatchersTemplates {
		opts = append(opts, nuclei.EnableGlobalMatchersTemplates())
	}

	// Disable template cache
	if cfg.disableTemplateCache {
		opts = append(opts, nuclei.DisableTemplateCache())
	}

	// File templates
	if cfg.enableFileTemplates {
		opts = append(opts, nuclei.EnableFileTemplates())
	}

	// Passive mode
	if cfg.passiveMode {
		opts = append(opts, nuclei.EnablePassiveMode())
	}

	// Response read size
	if cfg.responseReadSize > 0 {
		opts = append(opts, nuclei.WithResponseReadSize(cfg.responseReadSize))
	}

	// Sandbox
	if cfg.sandboxAllowLocalFile || cfg.sandboxRestrictNetwork {
		opts = append(opts, nuclei.WithSandboxOptions(cfg.sandboxAllowLocalFile, cfg.sandboxRestrictNetwork))
	}

	// Signed templates only
	if cfg.signedTemplatesOnly {
		opts = append(opts, nuclei.SignedTemplatesOnly())
	}

	// Headless
	if cfg.headless {
		hopts := &nuclei.HeadlessOpts{}
		if cfg.headlessOpts != nil {
			hopts.PageTimeout = cfg.headlessOpts.PageTimeout
			hopts.ShowBrowser = cfg.headlessOpts.ShowBrowser
			hopts.UseChrome = cfg.headlessOpts.UseChrome
			hopts.HeadlessOptions = cfg.headlessOpts.ExtraArgs
		}
		opts = append(opts, nuclei.EnableHeadlessWithOpts(hopts))
	}

	// Scan strategy
	if cfg.scanStrategy != "" {
		opts = append(opts, nuclei.WithScanStrategy(cfg.scanStrategy))
	}

	// DAST mode
	if cfg.dastMode {
		opts = append(opts, nuclei.DASTMode())
	}

	// Code templates
	if cfg.enableCode {
		opts = append(opts, nuclei.EnableCodeTemplates())
	}

	// Matcher status
	if cfg.matcherStatus {
		opts = append(opts, nuclei.EnableMatcherStatus())
	}

	// Verbosity
	opts = append(opts, nuclei.WithVerbosity(nuclei.VerbosityOptions{
		Verbose:       cfg.verbose,
		Silent:        cfg.silent,
		Debug:         cfg.debug,
		DebugRequest:  cfg.debug,
		DebugResponse: cfg.debug,
	}))

	// Stop at first match
	if cfg.stopAtFirstMatch {
		opts = append(opts, func(e *nuclei.NucleiEngine) error {
			e.Options().StopAtFirstMatch = true
			return nil
		})
	}

	// Disable update check (default for SDK)
	if cfg.disableUpdateCheck {
		opts = append(opts, nuclei.DisableUpdateCheck())
	}

	return opts, tmpDir, nil
}
