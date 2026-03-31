package nucleisdk

import "context"

// WebScanner is a pre-configured scanner for general web security testing.
// It runs HTTP-based templates excluding destructive categories.
type WebScanner struct {
	*presetScanner
}

// NewWebScanner creates a new general web scanner with sensible defaults.
func NewWebScanner(opts ...Option) (*WebScanner, error) {
	defaults := []Option{
		WithProtocolTypes("http"),
		WithExcludeTags("dos", "fuzz"),
		WithThreads(50),
		WithHostConcurrency(25),
		WithTimeout(10),
		WithRetries(1),
		WithRateLimit(150),
	}

	ps, err := newPresetScanner(defaults, opts)
	if err != nil {
		return nil, err
	}

	return &WebScanner{presetScanner: ps}, nil
}

// Run executes the web scan and returns results via a channel.
func (w *WebScanner) Run(ctx context.Context) (<-chan *ScanResult, error) {
	return w.presetScanner.Run(ctx)
}

// RunWithCallback executes the web scan with a callback.
func (w *WebScanner) RunWithCallback(ctx context.Context, cb func(*ScanResult)) error {
	return w.presetScanner.RunWithCallback(ctx, cb)
}

// Close releases resources.
func (w *WebScanner) Close() error {
	return w.presetScanner.Close()
}
