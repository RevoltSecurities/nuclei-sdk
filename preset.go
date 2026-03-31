package nucleisdk

import "context"

// presetScanner is the shared internal implementation for all preset scanners.
type presetScanner struct {
	scanner *Scanner
}

// newPresetScanner creates a preset scanner by merging default options with user overrides.
// User options are applied after defaults, so they take precedence.
func newPresetScanner(defaults []Option, userOpts []Option) (*presetScanner, error) {
	allOpts := make([]Option, 0, len(defaults)+len(userOpts))
	allOpts = append(allOpts, defaults...)
	allOpts = append(allOpts, userOpts...)

	scanner, err := NewScanner(allOpts...)
	if err != nil {
		return nil, err
	}

	return &presetScanner{scanner: scanner}, nil
}

// Run executes the scan and returns results via a channel.
func (p *presetScanner) Run(ctx context.Context) (<-chan *ScanResult, error) {
	return p.scanner.Run(ctx)
}

// RunWithCallback executes the scan and invokes the callback for each result.
func (p *presetScanner) RunWithCallback(ctx context.Context, cb func(*ScanResult)) error {
	return p.scanner.RunWithCallback(ctx, cb)
}

// Close releases resources.
func (p *presetScanner) Close() error {
	return p.scanner.Close()
}

// Scanner returns the underlying Scanner for advanced access.
func (p *presetScanner) Scanner() *Scanner {
	return p.scanner
}
