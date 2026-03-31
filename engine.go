package nucleisdk

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	nucleiUtils "github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/ratelimit"
)

// ScanEngine provides a high-performance, concurrent scanning API.
//
// Architecture: shared-global / ephemeral-per-scan
//
// Global resources (initialized once in Setup, shared read-only across scans):
//   - Template catalog, parser, and loaded template store
//   - Output writer, progress tracker, interactsh client
//   - Rate limiter, browser instance, host error cache
//
// Per-scan resources (created in each Scan call, lightweight):
//   - core.Engine (~5 fields), ExecutorOptions (shallow copy sharing global refs)
//   - SimpleInputProvider (just a []MetaInput slice)
//   - Filtered template list (runtime match from global store)
//
// This design allows 1000+ concurrent Scan() calls with minimal per-scan overhead.
//
// Usage:
//
//	engine, _ := nucleisdk.NewScanEngine(
//	    nucleisdk.WithRateLimit(100),
//	    nucleisdk.WithTimeout(10),
//	    nucleisdk.WithNoInteractsh(),
//	)
//	if err := engine.Setup(); err != nil { log.Fatal(err) }
//	defer engine.Close()
//
//	// Lightweight concurrent scans
//	go func() {
//	    results, _ := engine.Scan(ctx, &nucleisdk.ScanOptions{
//	        Targets:       []string{"https://example.com"},
//	        Tags:          []string{"cve", "exposure"},
//	        Severities:    []string{"high", "critical"},
//	        ProtocolTypes: "http",
//	    })
//	    for r := range results { ... }
//	}()
type ScanEngine struct {
	// Configuration (set by user via Option functions)
	config *ScanConfig

	// Global resources (initialized in Setup, shared across scans)
	nucOpts          *types.Options
	catalog          catalog.Catalog
	parser           *templates.Parser
	store            *loader.Store
	allTemplates     []*templates.Template
	outputWriter     output.Writer
	interactshClient *interactsh.Client
	rateLimiter      *ratelimit.Limiter
	progressClient   progress.Progress
	browserInstance  *engine.Browser
	hostErrCache     *hosterrorscache.Cache
	reportClient     reporting.Client
	colorizer        aurora.Aurora
	baseExecOpts     *protocols.ExecutorOptions
	logger           *gologger.Logger

	mu      sync.RWMutex
	isSetup bool
	closed  bool
	tmpDir  string
}

// NewScanEngine creates a new engine with the given configuration.
// This only stores config — call Setup() to initialize heavy resources.
func NewScanEngine(opts ...Option) (*ScanEngine, error) {
	cfg := newScanConfig()
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	return &ScanEngine{
		config: cfg,
		logger: gologger.DefaultLogger,
	}, nil
}

// Setup performs the one-time heavy initialization of global resources:
// protocol state, catalog, parser, template loading, output writer,
// interactsh client, rate limiter, browser, etc.
//
// This must be called before Scan(). It is safe to call only once.
func (se *ScanEngine) Setup() error {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.isSetup {
		return fmt.Errorf("engine already set up")
	}
	if se.closed {
		return fmt.Errorf("engine is closed")
	}

	ctx := context.Background()

	// 1. Build nuclei options from SDK config
	se.nucOpts = buildNucleiOptions(se.config)

	// 2. Configure logger
	if se.nucOpts.Verbose {
		se.logger.SetMaxLevel(levels.LevelVerbose)
	} else if se.nucOpts.Debug {
		se.logger.SetMaxLevel(levels.LevelDebug)
	} else if se.nucOpts.Silent {
		se.logger.SetMaxLevel(levels.LevelSilent)
	}
	se.nucOpts.Logger = se.logger

	// 3. Basic validation
	if se.nucOpts.Verbose && se.nucOpts.Silent {
		return fmt.Errorf("both verbose and silent mode specified")
	}

	// 4. Initialize protocol state (dialers, DNS, network pools)
	if protocolstate.ShouldInit(se.nucOpts.ExecutionId) {
		if err := protocolinit.Init(se.nucOpts); err != nil {
			return fmt.Errorf("initializing protocols: %w", err)
		}
	}

	// 5. Output writer (mock writer with callback support)
	se.outputWriter = se.createOutputWriter()

	// 6. Progress tracker
	se.progressClient = &testutils.MockProgressClient{}

	// 7. Host error cache
	if se.nucOpts.ShouldUseHostError() {
		se.hostErrCache = hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	}

	// 8. Reporting client
	if err := reporting.CreateConfigIfNotExists(); err != nil {
		return fmt.Errorf("creating reporting config: %w", err)
	}
	rc, err := reporting.New(&reporting.Options{}, "", false)
	if err != nil {
		return fmt.Errorf("creating reporting client: %w", err)
	}
	se.reportClient = rc

	// 9. Interactsh client — always create it (even with NoInteractsh).
	//    The Client struct must exist to avoid nil dereferences in templates
	//    that reference {{interactsh-url}}. When NoInteractsh is true, the client
	//    skips connecting to the server but still handles marker replacement safely.
	interactshOpts := interactsh.DefaultOptions(se.outputWriter, se.reportClient, se.progressClient)
	if se.config.noInteractsh {
		interactshOpts.NoInteractsh = true
	}
	interactshClient, err := interactsh.New(interactshOpts)
	if err != nil {
		return fmt.Errorf("creating interactsh client: %w", err)
	}
	se.interactshClient = interactshClient

	// 10. Rate limiter (global, shared across scans)
	se.rateLimiter = nucleiUtils.GetRateLimiter(ctx, se.nucOpts.RateLimit, se.nucOpts.RateLimitDuration)

	// 11. Browser (if headless enabled)
	if se.nucOpts.Headless {
		browser, err := engine.New(se.nucOpts)
		if err != nil {
			return fmt.Errorf("creating headless browser: %w", err)
		}
		se.browserInstance = browser
	}

	// 12. Colorizer
	se.colorizer = aurora.NewAurora(true)

	// 13. Catalog (template discovery from disk)
	se.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)

	// 14. Temporary directory for SDK-managed files
	tmpDir, err := os.MkdirTemp("", "nuclei-sdk-engine-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	se.tmpDir = tmpDir

	// Write any raw template bytes to temp dir
	if err := se.writeTemplateBytesToDisk(); err != nil {
		return fmt.Errorf("writing template bytes: %w", err)
	}

	// 15. Parser (template parsing with caching)
	se.parser = templates.NewParser()

	// 16. Base ExecutorOptions (shared references, copied per-scan)
	se.baseExecOpts = &protocols.ExecutorOptions{
		Output:             se.outputWriter,
		Options:            se.nucOpts,
		Progress:           se.progressClient,
		Catalog:            se.catalog,
		IssuesClient:       se.reportClient,
		RateLimiter:        se.rateLimiter,
		Interactsh:         se.interactshClient,
		Colorizer:          se.colorizer,
		ResumeCfg:          types.NewResumeCfg(),
		Browser:            se.browserInstance,
		Parser:             se.parser,
		InputHelper:        input.NewHelper(),
		TemporaryDirectory: se.tmpDir,
		Logger:             se.logger,
	}
	if se.hostErrCache != nil {
		se.baseExecOpts.HostErrorsCache = se.hostErrCache
	}

	// 17. Auth provider
	if len(se.config.authConfigs) > 0 {
		targetDomains := extractDomainsFromTargets(se.config.targets)
		se.baseExecOpts.AuthProvider = newSDKAuthProvider(se.config.authConfigs, targetDomains)
		if err := se.baseExecOpts.AuthProvider.PreFetchSecrets(); err != nil {
			return fmt.Errorf("prefetching auth secrets: %w", err)
		}
	}

	// 18. Load ALL templates once (expensive, cached globally)
	if err := se.loadTemplates(); err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}

	// 19. SDK version check (once globally)
	installer.NucleiSDKVersionCheck()

	se.isSetup = true
	return nil
}

// Scan executes a lightweight scan with the given per-scan options.
// Creates only a core.Engine, ExecutorOptions copy, and SimpleInputProvider per call.
// Safe to call concurrently from multiple goroutines.
//
// Template selection has two modes:
//
//  1. Filter mode: If no direct templates are specified (TemplateFiles/TemplateDirs/TemplateBytes),
//     templates are filtered from the global store using Tags/Severities/ProtocolTypes/TemplateIDs.
//
//  2. Direct mode: If TemplateFiles, TemplateDirs, or TemplateBytes are set, ONLY those
//     templates are loaded and used. The global store filters are ignored. This is ideal
//     for targeted scans (e.g., "scan target X with this specific CVE template").
func (se *ScanEngine) Scan(ctx context.Context, scanOpts *ScanOptions) (<-chan *ScanResult, error) {
	se.mu.RLock()
	if !se.isSetup {
		se.mu.RUnlock()
		return nil, fmt.Errorf("engine not set up — call Setup() first")
	}
	if se.closed {
		se.mu.RUnlock()
		return nil, fmt.Errorf("engine is closed")
	}
	se.mu.RUnlock()

	// Build targets
	targets, err := se.resolveTargets(scanOpts)
	if err != nil {
		return nil, fmt.Errorf("resolving targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	// Resolve templates: direct mode vs filter mode
	var filtered []*templates.Template
	var perScanTmpDir string

	if scanOpts.hasDirectTemplates() {
		// Direct mode: load only the specified templates
		perScanTmpDir, filtered, err = se.loadDirectTemplates(scanOpts)
		if err != nil {
			return nil, fmt.Errorf("loading per-scan templates: %w", err)
		}
	} else {
		// Filter mode: filter from the global template store
		filtered = se.filterTemplates(scanOpts)
	}

	if len(filtered) == 0 {
		if perScanTmpDir != "" {
			os.RemoveAll(perScanTmpDir)
		}
		return nil, fmt.Errorf("no templates match the given filters")
	}

	resultCh := make(chan *ScanResult, 100)

	go func() {
		defer close(resultCh)
		if perScanTmpDir != "" {
			defer os.RemoveAll(perScanTmpDir)
		}

		se.executeScan(ctx, filtered, targets, scanOpts, resultCh)
	}()

	return resultCh, nil
}

// ScanWithCallback executes a scan and invokes the callback for each result.
// Blocks until scanning completes or the context is cancelled.
func (se *ScanEngine) ScanWithCallback(ctx context.Context, scanOpts *ScanOptions, cb func(*ScanResult)) error {
	results, err := se.Scan(ctx, scanOpts)
	if err != nil {
		return err
	}
	for r := range results {
		cb(r)
	}
	return nil
}

// NucleiOptions returns the underlying nuclei types.Options for advanced customization.
// Available only after Setup() has been called. Returns nil before Setup().
//
// This gives Go users full access to every nuclei option beyond what the SDK's
// With* functions expose. Modify before calling Scan() — changes during a scan
// are not safe.
//
//	engine, _ := nucleisdk.NewScanEngine(nucleisdk.WithRateLimit(100))
//	engine.Setup()
//	opts := engine.NucleiOptions()
//	opts.FollowRedirects = true
//	opts.MaxHostError = 5
func (se *ScanEngine) NucleiOptions() *types.Options {
	se.mu.RLock()
	defer se.mu.RUnlock()
	return se.nucOpts
}

// GetLoadedTemplates returns all templates loaded during Setup.
func (se *ScanEngine) GetLoadedTemplates() []*templates.Template {
	se.mu.RLock()
	defer se.mu.RUnlock()
	return se.allTemplates
}

// Close releases all global resources held by the engine.
func (se *ScanEngine) Close() error {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.closed {
		return nil
	}
	se.closed = true

	if se.interactshClient != nil {
		se.interactshClient.Close()
	}
	if se.reportClient != nil {
		se.reportClient.Close()
	}
	if se.outputWriter != nil {
		se.outputWriter.Close()
	}
	if se.progressClient != nil {
		se.progressClient.Stop()
	}
	if se.hostErrCache != nil {
		se.hostErrCache.Close()
	}
	if se.rateLimiter != nil {
		se.rateLimiter.Stop()
	}
	if se.browserInstance != nil {
		se.browserInstance.Close()
	}
	if se.tmpDir != "" {
		os.RemoveAll(se.tmpDir)
	}
	if se.nucOpts != nil {
		protocolinit.Close(se.nucOpts.ExecutionId)
	}

	return nil
}

// --- Internal methods ---

// executeScan creates ephemeral per-scan objects, runs the scan, and cleans up.
func (se *ScanEngine) executeScan(ctx context.Context, tmplList []*templates.Template, targets []string, scanOpts *ScanOptions, resultCh chan<- *ScanResult) {
	// Create per-scan options copy
	perScanOpts := applyScanOptionsToNucleiOpts(se.nucOpts, scanOpts)

	// Create ephemeral per-scan rate limiter
	perScanRateLimiter := nucleiUtils.GetRateLimiter(ctx, perScanOpts.RateLimit, perScanOpts.RateLimitDuration)
	defer perScanRateLimiter.Stop()

	// Create ephemeral ExecutorOptions sharing global resources
	execOpts := &protocols.ExecutorOptions{
		Output:             se.outputWriter,
		Options:            perScanOpts,
		Progress:           se.progressClient,
		Catalog:            se.catalog,
		IssuesClient:       se.reportClient,
		RateLimiter:        perScanRateLimiter,
		Interactsh:         se.interactshClient,
		Colorizer:          aurora.NewAurora(true),
		ResumeCfg:          types.NewResumeCfg(),
		Browser:            se.browserInstance,
		Parser:             se.parser,
		InputHelper:        input.NewHelper(),
		TemporaryDirectory: se.tmpDir,
		Logger:             se.logger,
	}
	if se.hostErrCache != nil {
		execOpts.HostErrorsCache = se.hostErrCache
	}
	if se.baseExecOpts.AuthProvider != nil {
		execOpts.AuthProvider = se.baseExecOpts.AuthProvider
	}
	defer se.dereferenceEphemeral(execOpts)

	// Create per-scan input provider
	inputProvider := provider.NewSimpleInputProviderWithUrls(perScanOpts.ExecutionId, targets...)

	// Create per-scan workflow loader
	workflowLoader, err := workflow.NewLoader(execOpts)
	if err != nil {
		se.sendError(ctx, resultCh, fmt.Sprintf("creating workflow loader: %v", err))
		return
	}
	execOpts.WorkflowLoader = workflowLoader

	// Create per-scan core engine (very lightweight — ~5 fields)
	coreEngine := core.New(perScanOpts)
	coreEngine.SetExecuterOptions(execOpts)

	// Set result callback
	sevFilter := scanOpts.ResultSeverityFilter
	coreEngine.Callback = func(event *output.ResultEvent) {
		result := fromResultEvent(event)
		if result == nil {
			return
		}
		if !matchesSeverityFilter(result, sevFilter) {
			return
		}
		select {
		case resultCh <- result:
		case <-ctx.Done():
		}
	}

	// Execute scan
	_ = coreEngine.ExecuteScanWithOpts(ctx, tmplList, inputProvider, false)
	coreEngine.WorkPool().Wait()
}

// dereferenceEphemeral nils out global references to prevent accidental
// closure of shared resources during per-scan cleanup.
func (se *ScanEngine) dereferenceEphemeral(execOpts *protocols.ExecutorOptions) {
	execOpts.Output = nil
	execOpts.IssuesClient = nil
	execOpts.Interactsh = nil
	execOpts.HostErrorsCache = nil
	execOpts.Progress = nil
	execOpts.Catalog = nil
	execOpts.Parser = nil
}

// createOutputWriter creates a mock output writer that routes results through callbacks.
func (se *ScanEngine) createOutputWriter() output.Writer {
	mockWriter := testutils.NewMockOutputWriter(se.nucOpts.OmitTemplate)
	mockWriter.WriteCallback = func(event *output.ResultEvent) {
		// Results are routed through core.Engine.Callback, not here.
		// This writer exists to satisfy nuclei's internal plumbing.
	}
	return mockWriter
}

// loadTemplates loads all templates once into the global store.
func (se *ScanEngine) loadTemplates() error {
	workflowLoader, err := workflow.NewLoader(se.baseExecOpts)
	if err != nil {
		return fmt.Errorf("creating workflow loader: %w", err)
	}
	se.baseExecOpts.WorkflowLoader = workflowLoader

	storeCfg := loader.NewConfig(se.nucOpts, se.catalog, se.baseExecOpts)
	se.store, err = loader.New(storeCfg)
	if err != nil {
		return fmt.Errorf("creating template store: %w", err)
	}
	if err := se.store.Load(); err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}

	se.allTemplates = append(se.store.Templates(), se.store.Workflows()...)
	return nil
}

// writeTemplateBytesToDisk writes raw template bytes from config to the temp dir
// so they are available for the template loader.
func (se *ScanEngine) writeTemplateBytesToDisk() error {
	for _, entry := range se.config.templateBytes {
		name := entry.Name
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			name += ".yaml"
		}
		path := filepath.Join(se.tmpDir, name)
		if err := os.WriteFile(path, entry.Data, 0644); err != nil {
			return fmt.Errorf("writing template %s: %w", name, err)
		}
		// Add to nuclei template paths so the loader picks them up
		se.nucOpts.Templates = append(se.nucOpts.Templates, path)
	}
	return nil
}

// loadDirectTemplates loads per-scan templates from files, dirs, and/or raw bytes.
// Returns a temp dir (for bytes, must be cleaned up by caller), parsed templates, and error.
func (se *ScanEngine) loadDirectTemplates(scanOpts *ScanOptions) (string, []*templates.Template, error) {
	perScanOpts := se.nucOpts.Copy()

	// Reset template sources — we only want what this scan specifies
	perScanOpts.Templates = nil
	perScanOpts.Workflows = nil

	// Add template files and dirs
	perScanOpts.Templates = append(perScanOpts.Templates, scanOpts.TemplateFiles...)
	perScanOpts.Templates = append(perScanOpts.Templates, scanOpts.TemplateDirs...)

	// Write raw template bytes to a temp dir
	var tmpDir string
	if len(scanOpts.TemplateBytes) > 0 {
		var err error
		tmpDir, err = os.MkdirTemp("", "nuclei-sdk-scan-*")
		if err != nil {
			return "", nil, err
		}

		for _, entry := range scanOpts.TemplateBytes {
			name := entry.Name
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				name += ".yaml"
			}
			path := filepath.Join(tmpDir, name)
			if err := os.WriteFile(path, entry.Data, 0644); err != nil {
				os.RemoveAll(tmpDir)
				return "", nil, err
			}
			perScanOpts.Templates = append(perScanOpts.Templates, path)
		}
	}

	// Clear tag/severity/protocol filters — direct mode loads exactly what's specified
	perScanOpts.Tags = nil
	perScanOpts.ExcludeTags = nil
	perScanOpts.Severities = nil
	perScanOpts.ExcludeSeverities = nil
	perScanOpts.Protocols = nil
	perScanOpts.ExcludeProtocols = nil
	perScanOpts.IncludeIds = nil
	perScanOpts.ExcludeIds = nil
	perScanOpts.Authors = nil

	// Use loader to parse the templates
	storeCfg := loader.NewConfig(perScanOpts, se.catalog, se.baseExecOpts)
	tmpStore, err := loader.New(storeCfg)
	if err != nil {
		if tmpDir != "" {
			os.RemoveAll(tmpDir)
		}
		return "", nil, err
	}
	if err := tmpStore.Load(); err != nil {
		if tmpDir != "" {
			os.RemoveAll(tmpDir)
		}
		return "", nil, err
	}

	loaded := append(tmpStore.Templates(), tmpStore.Workflows()...)
	return tmpDir, loaded, nil
}

// filterTemplates performs runtime template filtering using nuclei's TagFilter.
// This matches templates against per-scan tags, severities, protocols, and IDs.
func (se *ScanEngine) filterTemplates(scanOpts *ScanOptions) []*templates.Template {
	// If no per-scan filters, return all templates
	if len(scanOpts.Tags) == 0 && len(scanOpts.ExcludeTags) == 0 &&
		len(scanOpts.Severities) == 0 && scanOpts.ProtocolTypes == "" &&
		len(scanOpts.TemplateIDs) == 0 && len(scanOpts.ExcludeIDs) == 0 &&
		len(scanOpts.Authors) == 0 {
		return se.allTemplates
	}

	tagFilter, err := templates.NewTagFilter(&templates.TagFilterConfig{
		Tags:        scanOpts.Tags,
		ExcludeTags: scanOpts.ExcludeTags,
		Authors:     scanOpts.Authors,
		Severities:  parseSeverities(scanOpts.Severities),
		Protocols:   parseProtocolTypes(scanOpts.ProtocolTypes),
		ExcludeIds:  scanOpts.ExcludeIDs,
		IncludeIds:  scanOpts.TemplateIDs,
	})
	if err != nil {
		// If filter creation fails, return all templates
		return se.allTemplates
	}

	var filtered []*templates.Template
	for _, tmpl := range se.allTemplates {
		matched, err := tagFilter.Match(tmpl, nil)
		if err == nil && matched {
			filtered = append(filtered, tmpl)
		}
	}
	return filtered
}

// resolveTargets collects all targets from ScanOptions.
func (se *ScanEngine) resolveTargets(scanOpts *ScanOptions) ([]string, error) {
	var targets []string
	targets = append(targets, scanOpts.Targets...)

	if scanOpts.TargetFile != "" {
		fileTargets, err := TargetsFromFile(scanOpts.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("reading target file: %w", err)
		}
		targets = append(targets, fileTargets...)
	}

	return targets, nil
}

// sendError sends an error result to the channel.
func (se *ScanEngine) sendError(ctx context.Context, resultCh chan<- *ScanResult, msg string) {
	select {
	case resultCh <- &ScanResult{Error: msg}:
	case <-ctx.Done():
	}
}

// --- Concurrent scan types (for labeled parallel scanning) ---

// ConcurrentScan defines a labeled scan job for RunParallel.
// Each job specifies its own targets, protocol types, tags, and severity filters.
type ConcurrentScan struct {
	Label   string   // Identifier for routing results (e.g., "http", "dns", "wordpress")
	Options []Option // Per-job options: targets, tags, protocol types, severity, etc.
}

// LabeledResult wraps a ScanResult with the scan job label it was matched to.
type LabeledResult struct {
	Label string `json:"label"`
	*ScanResult
}

// RunParallel launches multiple lightweight scans concurrently using the shared
// global resources. Each scan gets its own core.Engine and filtered templates.
// Results are tagged with the scan label.
//
// This is the most efficient way to run multiple scan types concurrently.
// Unlike creating N separate engines, all scans share a single set of global
// resources (templates, interactsh, rate limiter, etc.).
func (se *ScanEngine) RunParallel(ctx context.Context, scans ...ConcurrentScan) (<-chan *LabeledResult, error) {
	se.mu.RLock()
	if !se.isSetup {
		se.mu.RUnlock()
		return nil, fmt.Errorf("engine not set up — call Setup() first")
	}
	if se.closed {
		se.mu.RUnlock()
		return nil, fmt.Errorf("engine is closed")
	}
	se.mu.RUnlock()

	if len(scans) == 0 {
		return nil, fmt.Errorf("no scan jobs provided")
	}

	resultCh := make(chan *LabeledResult, 100)

	go func() {
		defer close(resultCh)

		var wg sync.WaitGroup
		for _, scan := range scans {
			scanOpts, err := se.parseConcurrentScan(scan)
			if err != nil {
				select {
				case resultCh <- &LabeledResult{Label: scan.Label, ScanResult: &ScanResult{Error: err.Error()}}:
				case <-ctx.Done():
				}
				continue
			}

			wg.Add(1)
			go func(label string, opts *ScanOptions) {
				defer wg.Done()

				results, err := se.Scan(ctx, opts)
				if err != nil {
					select {
					case resultCh <- &LabeledResult{Label: label, ScanResult: &ScanResult{Error: err.Error()}}:
					case <-ctx.Done():
					}
					return
				}

				for r := range results {
					select {
					case resultCh <- &LabeledResult{Label: label, ScanResult: r}:
					case <-ctx.Done():
						return
					}
				}
			}(scan.Label, scanOpts)
		}
		wg.Wait()
	}()

	return resultCh, nil
}

// parseConcurrentScan converts a ConcurrentScan's Option list into ScanOptions.
func (se *ScanEngine) parseConcurrentScan(scan ConcurrentScan) (*ScanOptions, error) {
	cfg := newScanConfig()
	for _, opt := range scan.Options {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("job %q: %w", scan.Label, err)
		}
	}

	return &ScanOptions{
		Targets:              cfg.targets,
		TargetFile:           cfg.targetFile,
		Tags:                 cfg.tags,
		ExcludeTags:          cfg.excludeTags,
		Severities:           cfg.severity,
		ProtocolTypes:        cfg.protocolTypes,
		TemplateIDs:          cfg.templateIDs,
		ExcludeIDs:           cfg.excludeIDs,
		Authors:              cfg.authors,
		TemplateFiles:        cfg.templateFiles,
		TemplateDirs:         cfg.templateDirs,
		TemplateBytes:        cfg.templateBytes,
		ResultSeverityFilter: cfg.resultSeverityFilter,
	}, nil
}

// --- Legacy API support ---

// RunScan provides backward compatibility with the old per-scan engine API.
// Internally, it creates a ScanOptions from the per-scan Option overrides and
// calls Scan(). Requires Setup() to have been called first.
func (se *ScanEngine) RunScan(ctx context.Context, perScanOpts ...Option) (<-chan *ScanResult, error) {
	scanOpts, err := se.parseConcurrentScan(ConcurrentScan{
		Label:   "default",
		Options: perScanOpts,
	})
	if err != nil {
		return nil, err
	}
	return se.Scan(ctx, scanOpts)
}

// RunScanWithCallback provides backward compatibility with the old callback API.
func (se *ScanEngine) RunScanWithCallback(ctx context.Context, callback func(*ScanResult), perScanOpts ...Option) error {
	results, err := se.RunScan(ctx, perScanOpts...)
	if err != nil {
		return err
	}
	for r := range results {
		callback(r)
	}
	return nil
}

// --- Helper functions ---

// normalizeHost extracts a hostname from a URL or host:port string.
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	host := strings.Split(s, ":")[0]
	return strings.ToLower(strings.TrimSpace(host))
}
