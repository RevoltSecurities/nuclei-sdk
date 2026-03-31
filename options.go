package nucleisdk

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Option is a functional option for configuring the Scanner.
type Option func(*ScanConfig) error

// --- Template Loading Options ---

// WithTemplateDir adds a directory of templates to scan with.
// If not called, nuclei uses the default templates directory (~/.local/nuclei-templates/).
func WithTemplateDir(dir string) Option {
	return func(c *ScanConfig) error {
		if dir == "" {
			return nil // skip empty — nuclei will use default templates dir
		}
		c.templateDirs = append(c.templateDirs, dir)
		return nil
	}
}

// WithTemplateDirs adds multiple template directories.
func WithTemplateDirs(dirs ...string) Option {
	return func(c *ScanConfig) error {
		for _, dir := range dirs {
			if dir != "" {
				c.templateDirs = append(c.templateDirs, dir)
			}
		}
		return nil
	}
}

// WithTemplateFile adds a single template file path.
func WithTemplateFile(file string) Option {
	return func(c *ScanConfig) error {
		c.templateFiles = append(c.templateFiles, file)
		return nil
	}
}

// WithTemplateFiles adds multiple template file paths.
func WithTemplateFiles(files ...string) Option {
	return func(c *ScanConfig) error {
		c.templateFiles = append(c.templateFiles, files...)
		return nil
	}
}

// WithTemplateBytes adds a raw YAML template from bytes.
// The name is used as the filename (without .yaml extension).
func WithTemplateBytes(name string, data []byte) Option {
	return func(c *ScanConfig) error {
		if name == "" {
			return fmt.Errorf("template name cannot be empty")
		}
		if len(data) == 0 {
			return fmt.Errorf("template data cannot be empty")
		}
		c.templateBytes = append(c.templateBytes, templateBytesEntry{
			Name: name,
			Data: data,
		})
		return nil
	}
}

// WithTemplateURL adds a template to fetch from a URL.
func WithTemplateURL(url string) Option {
	return func(c *ScanConfig) error {
		c.templateURLs = append(c.templateURLs, url)
		return nil
	}
}

// WithTemplateURLs adds multiple templates to fetch from URLs.
func WithTemplateURLs(urls ...string) Option {
	return func(c *ScanConfig) error {
		c.templateURLs = append(c.templateURLs, urls...)
		return nil
	}
}

// WithWorkflows adds workflow file/directory paths.
func WithWorkflows(paths ...string) Option {
	return func(c *ScanConfig) error {
		c.workflows = append(c.workflows, paths...)
		return nil
	}
}

// WithTrustedDomains adds trusted domains for remote template loading.
func WithTrustedDomains(domains ...string) Option {
	return func(c *ScanConfig) error {
		c.trustedDomains = append(c.trustedDomains, domains...)
		return nil
	}
}

// --- Template Filter Options ---

// WithTags filters templates by tags (OR logic).
func WithTags(tags ...string) Option {
	return func(c *ScanConfig) error {
		c.tags = append(c.tags, tags...)
		return nil
	}
}

// WithExcludeTags excludes templates with these tags.
func WithExcludeTags(tags ...string) Option {
	return func(c *ScanConfig) error {
		c.excludeTags = append(c.excludeTags, tags...)
		return nil
	}
}

// WithSeverityFilter filters templates by severity (info, low, medium, high, critical).
func WithSeverityFilter(severities ...string) Option {
	return func(c *ScanConfig) error {
		c.severity = append(c.severity, severities...)
		return nil
	}
}

// WithExcludeSeverities excludes templates with these severities.
func WithExcludeSeverities(severities ...string) Option {
	return func(c *ScanConfig) error {
		c.excludeSeverity = append(c.excludeSeverity, severities...)
		return nil
	}
}

// WithTemplateIDs filters templates by ID.
func WithTemplateIDs(ids ...string) Option {
	return func(c *ScanConfig) error {
		c.templateIDs = append(c.templateIDs, ids...)
		return nil
	}
}

// WithExcludeTemplateIDs excludes templates by ID.
func WithExcludeTemplateIDs(ids ...string) Option {
	return func(c *ScanConfig) error {
		c.excludeIDs = append(c.excludeIDs, ids...)
		return nil
	}
}

// WithProtocolTypes filters templates by protocol type (http, dns, network, ssl, etc.).
func WithProtocolTypes(types string) Option {
	return func(c *ScanConfig) error {
		c.protocolTypes = types
		return nil
	}
}

// WithAuthors filters templates by author.
func WithAuthors(authors ...string) Option {
	return func(c *ScanConfig) error {
		c.authors = append(c.authors, authors...)
		return nil
	}
}

// --- Target Options ---

// WithTargets sets the target URLs/hosts to scan.
func WithTargets(targets ...string) Option {
	return func(c *ScanConfig) error {
		c.targets = append(c.targets, targets...)
		return nil
	}
}

// WithTargetFile sets a file path to read targets from (one per line).
func WithTargetFile(path string) Option {
	return func(c *ScanConfig) error {
		c.targetFile = path
		return nil
	}
}

// WithTargetReader sets an io.Reader to read targets from (one per line).
func WithTargetReader(reader io.Reader) Option {
	return func(c *ScanConfig) error {
		c.targetReader = reader
		return nil
	}
}

// WithOpenAPISpec sets an OpenAPI specification file for API security scanning.
// This is mutually exclusive with WithTargets/WithTargetFile/WithTargetReader.
func WithOpenAPISpec(path string) Option {
	return func(c *ScanConfig) error {
		c.openAPISpec = path
		c.openAPIMode = "openapi"
		return nil
	}
}

// WithSwaggerSpec sets a Swagger specification file for API security scanning.
func WithSwaggerSpec(path string) Option {
	return func(c *ScanConfig) error {
		c.openAPISpec = path
		c.openAPIMode = "swagger"
		return nil
	}
}

// WithExcludeTargets excludes specific hosts from scanning.
func WithExcludeTargets(hosts ...string) Option {
	return func(c *ScanConfig) error {
		c.excludeTargets = append(c.excludeTargets, hosts...)
		return nil
	}
}

// WithHTTPProbe enables HTTP probing for non-URL targets.
// When targets are raw hosts/IPs (without http:// or https://),
// nuclei will probe them via httpx to discover HTTP/HTTPS services.
func WithHTTPProbe() Option {
	return func(c *ScanConfig) error {
		c.httpProbe = true
		return nil
	}
}

// WithProbeConcurrency sets the number of concurrent HTTP probes.
// Default is 50. Only effective when HTTP probing is enabled.
func WithProbeConcurrency(n int) Option {
	return func(c *ScanConfig) error {
		if n <= 0 {
			return fmt.Errorf("probe concurrency must be > 0, got %d", n)
		}
		c.probeConcurrency = n
		return nil
	}
}

// WithScanAllIPs enables scanning all IPs associated with a DNS record.
// By default, only the first resolved IP is scanned.
func WithScanAllIPs() Option {
	return func(c *ScanConfig) error {
		c.scanAllIPs = true
		return nil
	}
}

// WithIPVersion sets which IP versions to scan. Valid values: "4", "6".
// Default is IPv4 only. Pass both to scan dual-stack.
func WithIPVersion(versions ...string) Option {
	return func(c *ScanConfig) error {
		for _, v := range versions {
			if v != "4" && v != "6" {
				return fmt.Errorf("invalid IP version: %s (use \"4\" or \"6\")", v)
			}
		}
		c.ipVersion = versions
		return nil
	}
}

// --- Network Options ---

// WithProxy sets a proxy URL (HTTP or SOCKS5).
func WithProxy(proxy string) Option {
	return func(c *ScanConfig) error {
		c.proxy = append(c.proxy, proxy)
		return nil
	}
}

// WithProxies sets multiple proxy URLs.
func WithProxies(proxies ...string) Option {
	return func(c *ScanConfig) error {
		c.proxy = append(c.proxy, proxies...)
		return nil
	}
}

// WithProxyInternal enables proxy for internal nuclei requests.
func WithProxyInternal(enabled bool) Option {
	return func(c *ScanConfig) error {
		c.proxyInternal = enabled
		return nil
	}
}

// WithTimeout sets the request timeout in seconds.
func WithTimeout(seconds int) Option {
	return func(c *ScanConfig) error {
		if seconds <= 0 {
			return fmt.Errorf("timeout must be positive")
		}
		c.timeout = seconds
		return nil
	}
}

// WithRetries sets the number of retries for failed requests.
func WithRetries(count int) Option {
	return func(c *ScanConfig) error {
		if count < 0 {
			return fmt.Errorf("retries cannot be negative")
		}
		c.retries = count
		return nil
	}
}

// --- Concurrency Options ---

// WithThreads sets the number of concurrent templates to execute.
func WithThreads(count int) Option {
	return func(c *ScanConfig) error {
		if count <= 0 {
			return fmt.Errorf("threads must be positive")
		}
		c.templateThreads = count
		return nil
	}
}

// WithHostConcurrency sets the number of concurrent hosts per template.
func WithHostConcurrency(count int) Option {
	return func(c *ScanConfig) error {
		if count <= 0 {
			return fmt.Errorf("host concurrency must be positive")
		}
		c.hostConcurrency = count
		return nil
	}
}

// WithBulkSize is an alias for WithHostConcurrency.
func WithBulkSize(count int) Option {
	return WithHostConcurrency(count)
}

// WithRateLimit sets the maximum requests per second.
func WithRateLimit(maxPerSecond int) Option {
	return func(c *ScanConfig) error {
		if maxPerSecond <= 0 {
			return fmt.Errorf("rate limit must be positive")
		}
		c.rateLimitCount = maxPerSecond
		c.rateLimitDuration = time.Second
		return nil
	}
}

// WithRateLimitCustom sets a custom rate limit with duration.
func WithRateLimitCustom(count int, duration time.Duration) Option {
	return func(c *ScanConfig) error {
		if count <= 0 {
			return fmt.Errorf("rate limit count must be positive")
		}
		c.rateLimitCount = count
		c.rateLimitDuration = duration
		return nil
	}
}

// WithPayloadConcurrency sets the maximum concurrent payloads per template.
func WithPayloadConcurrency(count int) Option {
	return func(c *ScanConfig) error {
		if count <= 0 {
			return fmt.Errorf("payload concurrency must be positive")
		}
		c.payloadConcurrency = count
		return nil
	}
}

// --- Auth Options ---

// WithAuth adds an authentication configuration.
func WithAuth(auth AuthConfig) Option {
	return func(c *ScanConfig) error {
		c.authConfigs = append(c.authConfigs, auth)
		return nil
	}
}

// WithSecretsFile adds a nuclei secrets/credentials file.
func WithSecretsFile(path string) Option {
	return func(c *ScanConfig) error {
		c.secretsFiles = append(c.secretsFiles, path)
		return nil
	}
}

// WithSecretsFiles adds multiple nuclei secrets/credentials files.
func WithSecretsFiles(paths ...string) Option {
	return func(c *ScanConfig) error {
		c.secretsFiles = append(c.secretsFiles, paths...)
		return nil
	}
}

// --- Header & Variable Options ---

// WithHeaders adds custom headers to all HTTP requests ("Key: Value" format).
func WithHeaders(headers ...string) Option {
	return func(c *ScanConfig) error {
		c.customHeaders = append(c.customHeaders, headers...)
		return nil
	}
}

// WithHeader adds a single custom header.
func WithHeader(key, value string) Option {
	return func(c *ScanConfig) error {
		c.customHeaders = append(c.customHeaders, key+": "+value)
		return nil
	}
}

// WithVars adds custom variables ("key=value" format).
func WithVars(vars ...string) Option {
	return func(c *ScanConfig) error {
		c.customVars = append(c.customVars, vars...)
		return nil
	}
}

// WithVar adds a single custom variable.
func WithVar(key, value string) Option {
	return func(c *ScanConfig) error {
		c.customVars = append(c.customVars, key+"="+value)
		return nil
	}
}

// --- Feature Options ---

// WithHeadless enables headless browser for headless templates.
func WithHeadless(opts *HeadlessConfig) Option {
	return func(c *ScanConfig) error {
		c.headless = true
		c.headlessOpts = opts
		return nil
	}
}

// WithScanStrategy sets the scan strategy ("template-spray" or "host-spray").
func WithScanStrategy(strategy string) Option {
	return func(c *ScanConfig) error {
		strategy = strings.ToLower(strategy)
		if strategy != StrategyTemplateSpray && strategy != StrategyHostSpray {
			return fmt.Errorf("invalid scan strategy: %s (use %q or %q)", strategy, StrategyTemplateSpray, StrategyHostSpray)
		}
		c.scanStrategy = strategy
		return nil
	}
}

// WithDASTMode enables DAST (fuzzing) mode.
func WithDASTMode() Option {
	return func(c *ScanConfig) error {
		c.dastMode = true
		return nil
	}
}

// WithCodeTemplates enables code protocol template execution.
func WithCodeTemplates() Option {
	return func(c *ScanConfig) error {
		c.enableCode = true
		return nil
	}
}

// WithMatcherStatus enables reporting all matcher results (not just matches).
func WithMatcherStatus() Option {
	return func(c *ScanConfig) error {
		c.matcherStatus = true
		return nil
	}
}

// --- Verbosity Options ---

// WithVerbose enables verbose output.
func WithVerbose() Option {
	return func(c *ScanConfig) error {
		c.verbose = true
		return nil
	}
}

// WithDebug enables debug output.
func WithDebug() Option {
	return func(c *ScanConfig) error {
		c.debug = true
		return nil
	}
}

// WithSilent enables silent mode (no output except results).
func WithSilent() Option {
	return func(c *ScanConfig) error {
		c.silent = true
		return nil
	}
}

// WithUpdateCheck enables nuclei update checks (disabled by default in SDK).
func WithUpdateCheck() Option {
	return func(c *ScanConfig) error {
		c.disableUpdateCheck = false
		return nil
	}
}

// --- Interactsh Options ---

// WithNoInteractsh disables interactsh server for OOB testing.
// Use this when you don't need out-of-band interaction testing.
func WithNoInteractsh() Option {
	return func(c *ScanConfig) error {
		c.noInteractsh = true
		return nil
	}
}

// --- Template Execution Mode Options ---

// WithSelfContainedTemplates enables execution of self-contained templates.
func WithSelfContainedTemplates() Option {
	return func(c *ScanConfig) error {
		c.selfContainedTemplates = true
		return nil
	}
}

// WithGlobalMatchersTemplates enables execution of global-matchers templates.
func WithGlobalMatchersTemplates() Option {
	return func(c *ScanConfig) error {
		c.globalMatchersTemplates = true
		return nil
	}
}

// WithDisableTemplateCache disables caching of parsed templates.
func WithDisableTemplateCache() Option {
	return func(c *ScanConfig) error {
		c.disableTemplateCache = true
		return nil
	}
}

// WithFileTemplates enables execution of file protocol templates.
func WithFileTemplates() Option {
	return func(c *ScanConfig) error {
		c.enableFileTemplates = true
		return nil
	}
}

// WithPassiveMode enables passive HTTP response processing mode.
// In this mode, nuclei processes pre-recorded HTTP responses instead of sending requests.
func WithPassiveMode() Option {
	return func(c *ScanConfig) error {
		c.passiveMode = true
		return nil
	}
}

// WithSignedTemplatesOnly restricts execution to signed templates only.
func WithSignedTemplatesOnly() Option {
	return func(c *ScanConfig) error {
		c.signedTemplatesOnly = true
		return nil
	}
}

// --- Response Handling Options ---

// WithResponseReadSize sets the maximum response read size in bytes.
func WithResponseReadSize(size int) Option {
	return func(c *ScanConfig) error {
		if size <= 0 {
			return fmt.Errorf("response read size must be positive")
		}
		c.responseReadSize = size
		return nil
	}
}

// --- Sandbox Options ---

// WithSandboxOptions sets sandbox options for template execution.
// allowLocalFileAccess: allow templates to access local files.
// restrictLocalNetworkAccess: restrict templates from accessing local network.
func WithSandboxOptions(allowLocalFileAccess, restrictLocalNetworkAccess bool) Option {
	return func(c *ScanConfig) error {
		c.sandboxAllowLocalFile = allowLocalFileAccess
		c.sandboxRestrictNetwork = restrictLocalNetworkAccess
		return nil
	}
}

// --- Execution Control Options ---

// WithStopAtFirstMatch stops scanning a host after the first match is found.
func WithStopAtFirstMatch() Option {
	return func(c *ScanConfig) error {
		c.stopAtFirstMatch = true
		return nil
	}
}

// WithDisableMaxHostErr disables skipping hosts that exceed max errors.
func WithDisableMaxHostErr() Option {
	return func(c *ScanConfig) error {
		c.disableMaxHostErr = true
		return nil
	}
}

// --- Advanced Network Options ---

// WithLeaveDefaultPorts preserves default ports in URLs (e.g., :80 for HTTP, :443 for HTTPS).
func WithLeaveDefaultPorts() Option {
	return func(c *ScanConfig) error {
		c.leaveDefaultPorts = true
		return nil
	}
}

// WithNetworkInterface sets the network interface to use for scanning.
func WithNetworkInterface(iface string) Option {
	return func(c *ScanConfig) error {
		c.networkInterface = iface
		return nil
	}
}

// WithSourceIP sets the source IP address to use for scanning.
func WithSourceIP(ip string) Option {
	return func(c *ScanConfig) error {
		c.sourceIP = ip
		return nil
	}
}

// WithSystemResolvers uses system DNS resolvers instead of nuclei's default resolvers.
func WithSystemResolvers() Option {
	return func(c *ScanConfig) error {
		c.systemResolvers = true
		return nil
	}
}

// WithResolvers sets custom DNS resolvers.
func WithResolvers(resolvers ...string) Option {
	return func(c *ScanConfig) error {
		c.resolversList = append(c.resolversList, resolvers...)
		return nil
	}
}

// --- Result Filtering Options ---

// WithResultSeverityFilter filters results by severity after scanning.
// This is a post-scan filter, separate from WithSeverityFilter which filters templates.
func WithResultSeverityFilter(severities ...string) Option {
	return func(c *ScanConfig) error {
		c.resultSeverityFilter = append(c.resultSeverityFilter, severities...)
		return nil
	}
}
