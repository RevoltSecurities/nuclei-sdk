package nucleisdk

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// buildNucleiOptions translates a ScanConfig into nuclei's *types.Options.
// Starts from types.DefaultOptions() and overlays SDK config values.
func buildNucleiOptions(cfg *ScanConfig) *types.Options {
	opts := types.DefaultOptions()

	// Timeouts & retries
	opts.Timeout = cfg.timeout
	opts.Retries = cfg.retries

	// Concurrency
	opts.TemplateThreads = cfg.templateThreads
	opts.BulkSize = cfg.hostConcurrency
	opts.RateLimit = cfg.rateLimitCount
	opts.RateLimitDuration = cfg.rateLimitDuration
	if cfg.payloadConcurrency > 0 {
		opts.PayloadConcurrency = cfg.payloadConcurrency
	}

	// Template sources
	opts.Templates = mergeStringSlices(cfg.templateDirs, cfg.templateFiles)
	opts.Workflows = cfg.workflows
	opts.RemoteTemplateDomainList = cfg.trustedDomains

	// Template filters
	opts.Tags = cfg.tags
	opts.ExcludeTags = cfg.excludeTags
	if len(cfg.severity) > 0 {
		opts.Severities = parseSeverities(cfg.severity)
	}
	if len(cfg.excludeSeverity) > 0 {
		opts.ExcludeSeverities = parseSeverities(cfg.excludeSeverity)
	}
	if cfg.protocolTypes != "" {
		opts.Protocols = parseProtocolTypes(cfg.protocolTypes)
	}
	opts.IncludeIds = cfg.templateIDs
	opts.ExcludeIds = cfg.excludeIDs
	opts.Authors = cfg.authors

	// Proxy
	if len(cfg.proxy) > 0 {
		opts.AliveHttpProxy = cfg.proxy[0]
		if len(cfg.proxy) > 1 {
			opts.AliveSocksProxy = cfg.proxy[1]
		}
	}
	opts.ProxyInternal = cfg.proxyInternal

	// Headers & variables
	opts.CustomHeaders = cfg.customHeaders
	for _, v := range cfg.customVars {
		_ = opts.Vars.Set(v)
	}

	// Features
	opts.Headless = cfg.headless
	if cfg.headlessOpts != nil {
		opts.HeadlessOptionalArguments = cfg.headlessOpts.ExtraArgs
		opts.ShowBrowser = cfg.headlessOpts.ShowBrowser
		opts.PageTimeout = cfg.headlessOpts.PageTimeout
		opts.UseInstalledChrome = cfg.headlessOpts.UseChrome
	}
	opts.DAST = cfg.dastMode
	opts.EnableCodeTemplates = cfg.enableCode
	opts.MatcherStatus = cfg.matcherStatus

	// Scan strategy
	if cfg.scanStrategy != "" {
		opts.ScanStrategy = cfg.scanStrategy
	}

	// Interactsh
	if cfg.noInteractsh {
		opts.NoInteractsh = true
	}

	// Template execution modes
	opts.EnableSelfContainedTemplates = cfg.selfContainedTemplates
	opts.EnableGlobalMatchersTemplates = cfg.globalMatchersTemplates
	opts.EnableFileTemplates = cfg.enableFileTemplates
	opts.OfflineHTTP = cfg.passiveMode
	if cfg.signedTemplatesOnly {
		opts.DisableUnsignedTemplates = true
	}

	// Response handling
	if cfg.responseReadSize > 0 {
		opts.ResponseReadSize = cfg.responseReadSize
	}

	// Sandbox
	opts.AllowLocalFileAccess = cfg.sandboxAllowLocalFile
	opts.RestrictLocalNetworkAccess = cfg.sandboxRestrictNetwork

	// Execution control
	opts.StopAtFirstMatch = cfg.stopAtFirstMatch
	if cfg.disableMaxHostErr {
		opts.MaxHostError = -1
	}

	// HTTP Probing
	if !cfg.httpProbe {
		opts.DisableHTTPProbe = true
	}
	if cfg.probeConcurrency > 0 {
		opts.ProbeConcurrency = cfg.probeConcurrency
	}
	opts.ScanAllIPs = cfg.scanAllIPs
	if len(cfg.ipVersion) > 0 {
		_ = opts.IPVersion.Set(strings.Join(cfg.ipVersion, ","))
	}

	// Exclude targets
	if len(cfg.excludeTargets) > 0 {
		opts.ExcludeTargets = cfg.excludeTargets
	}

	// Network
	opts.LeaveDefaultPorts = cfg.leaveDefaultPorts
	opts.Interface = cfg.networkInterface
	opts.SourceIP = cfg.sourceIP
	opts.SystemResolvers = cfg.systemResolvers
	opts.InternalResolversList = cfg.resolversList

	// Verbosity
	opts.Verbose = cfg.verbose
	opts.Debug = cfg.debug
	opts.DebugRequests = cfg.debug
	opts.DebugResponse = cfg.debug
	opts.Silent = cfg.silent

	// SDK defaults: disable update check
	if cfg.disableUpdateCheck {
		config.DefaultConfig.DisableUpdateCheck()
	}
	if opts.ExcludeTags == nil {
		opts.ExcludeTags = []string{}
	}

	return opts
}

// parseSeverities converts string severity names to severity.Severities using Set.
func parseSeverities(strs []string) severity.Severities {
	var result severity.Severities
	_ = result.Set(strings.Join(strs, ","))
	return result
}

// parseProtocolTypes converts a comma-separated protocol string to ProtocolTypes using Set.
func parseProtocolTypes(s string) templateTypes.ProtocolTypes {
	var result templateTypes.ProtocolTypes
	_ = result.Set(s)
	return result
}

// mergeStringSlices combines multiple slices into one.
func mergeStringSlices(slices ...[]string) []string {
	var result []string
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

// applyScanOptionsToNucleiOpts overlays per-scan ScanOptions onto a copy of types.Options.
func applyScanOptionsToNucleiOpts(base *types.Options, scanOpts *ScanOptions) *types.Options {
	opts := base.Copy()

	// Template filters for this scan
	if len(scanOpts.Tags) > 0 {
		opts.Tags = scanOpts.Tags
	}
	if len(scanOpts.ExcludeTags) > 0 {
		opts.ExcludeTags = scanOpts.ExcludeTags
	}
	if len(scanOpts.Severities) > 0 {
		opts.Severities = parseSeverities(scanOpts.Severities)
	}
	if scanOpts.ProtocolTypes != "" {
		opts.Protocols = parseProtocolTypes(scanOpts.ProtocolTypes)
	}
	if len(scanOpts.TemplateIDs) > 0 {
		opts.IncludeIds = scanOpts.TemplateIDs
	}
	if len(scanOpts.ExcludeIDs) > 0 {
		opts.ExcludeIds = scanOpts.ExcludeIDs
	}
	if len(scanOpts.Authors) > 0 {
		opts.Authors = scanOpts.Authors
	}

	return opts
}
