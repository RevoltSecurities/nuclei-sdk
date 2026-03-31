package nucleisdk

import "context"

// NetworkScanner is a pre-configured scanner for network/infrastructure security testing.
// It focuses on DNS, SSL/TLS, and TCP-based vulnerability detection.
type NetworkScanner struct {
	*presetScanner
}

// NewNetworkScanner creates a new network/infra scanner with sensible defaults.
func NewNetworkScanner(opts ...Option) (*NetworkScanner, error) {
	defaults := []Option{
		WithProtocolTypes("network,dns,ssl"),
		WithTags(
			"network", "dns", "ssl", "tls", "cve",
			"default-login", "exposure", "misconfig",
		),
		WithThreads(25),
		WithHostConcurrency(50),
		WithTimeout(5),
		WithRetries(2),
		WithRateLimit(100),
	}

	ps, err := newPresetScanner(defaults, opts)
	if err != nil {
		return nil, err
	}

	return &NetworkScanner{presetScanner: ps}, nil
}

// Run executes the network scan and returns results via a channel.
func (n *NetworkScanner) Run(ctx context.Context) (<-chan *ScanResult, error) {
	return n.presetScanner.Run(ctx)
}

// RunWithCallback executes the network scan with a callback.
func (n *NetworkScanner) RunWithCallback(ctx context.Context, cb func(*ScanResult)) error {
	return n.presetScanner.RunWithCallback(ctx, cb)
}

// Close releases resources.
func (n *NetworkScanner) Close() error {
	return n.presetScanner.Close()
}
