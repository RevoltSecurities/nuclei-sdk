package nucleisdk

import "context"

// APISecurityScanner is a pre-configured scanner for API security testing.
// It focuses on REST API, GraphQL, and OpenAPI/Swagger-related vulnerabilities.
type APISecurityScanner struct {
	*presetScanner
}

// NewAPISecurityScanner creates a new API security scanner with sensible defaults.
// User-provided options override the defaults.
// Note: DAST mode is NOT enabled by default because it filters out detection templates
// (swagger, exposure, misconfig, etc.). Use WithDASTMode() explicitly if you want
// fuzzing-only scanning.
func NewAPISecurityScanner(opts ...Option) (*APISecurityScanner, error) {
	defaults := []Option{
		WithProtocolTypes("http"),
		WithTags(
			"api", "swagger", "openapi", "graphql", "rest",
			"jwt", "auth-bypass", "exposure", "misconfig",
			"token", "cors", "ssrf", "idor", "bola",
			"injection", "sqli", "xss", "rce",
		),
		WithThreads(25),
		WithHostConcurrency(10),
		WithTimeout(15),
		WithRetries(1),
		WithRateLimit(50),
		WithMatcherStatus(),
	}

	ps, err := newPresetScanner(defaults, opts)
	if err != nil {
		return nil, err
	}

	return &APISecurityScanner{presetScanner: ps}, nil
}

// Run executes the API security scan and returns results via a channel.
func (a *APISecurityScanner) Run(ctx context.Context) (<-chan *ScanResult, error) {
	return a.presetScanner.Run(ctx)
}

// RunWithCallback executes the API security scan with a callback.
func (a *APISecurityScanner) RunWithCallback(ctx context.Context, cb func(*ScanResult)) error {
	return a.presetScanner.RunWithCallback(ctx, cb)
}

// Close releases resources.
func (a *APISecurityScanner) Close() error {
	return a.presetScanner.Close()
}
