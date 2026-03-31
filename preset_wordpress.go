package nucleisdk

import "context"

// WordPressScanner is a pre-configured scanner for WordPress security testing.
// It focuses on WordPress core, plugins, themes, and common misconfigurations.
type WordPressScanner struct {
	*presetScanner
}

// NewWordPressScanner creates a new WordPress scanner with sensible defaults.
func NewWordPressScanner(opts ...Option) (*WordPressScanner, error) {
	defaults := []Option{
		WithProtocolTypes("http"),
		WithTags(
			"wordpress", "wp-plugin", "wp-theme", "wp",
			"woocommerce", "xmlrpc", "wp-config", "wp-cron",
			"wp-admin", "wp-login",
		),
		WithThreads(25),
		WithHostConcurrency(5),
		WithTimeout(10),
		WithRetries(2),
		WithRateLimit(30),
	}

	ps, err := newPresetScanner(defaults, opts)
	if err != nil {
		return nil, err
	}

	return &WordPressScanner{presetScanner: ps}, nil
}

// Run executes the WordPress scan and returns results via a channel.
func (w *WordPressScanner) Run(ctx context.Context) (<-chan *ScanResult, error) {
	return w.presetScanner.Run(ctx)
}

// RunWithCallback executes the WordPress scan with a callback.
func (w *WordPressScanner) RunWithCallback(ctx context.Context, cb func(*ScanResult)) error {
	return w.presetScanner.RunWithCallback(ctx, cb)
}

// Close releases resources.
func (w *WordPressScanner) Close() error {
	return w.presetScanner.Close()
}
