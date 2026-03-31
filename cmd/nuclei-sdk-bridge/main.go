package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	nucleisdk "github.com/RevoltSecurities/nuclei-sdk"
	"github.com/projectdiscovery/goflags"
)

// Version information — set by goreleaser ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// bridge holds the shared engine state and manages the JSON-line protocol.
type bridge struct {
	engine *nucleisdk.ScanEngine
	pool   *nucleisdk.ScanPool
	ctx    context.Context
	cancel context.CancelFunc

	enc   *json.Encoder
	encMu sync.Mutex // protects stdout writes
}

func main() {
	// Parse CLI flags with goflags before any I/O redirects
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("nuclei-sdk-bridge — JSON-line bridge for the Nuclei SDK")

	var showVersion bool
	flagSet.CreateGroup("info", "Info",
		flagSet.BoolVarP(&showVersion, "version", "v", false, "show bridge version"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Fprintf(os.Stderr, "flag parse error: %v\n", err)
		os.Exit(1)
	}

	if showVersion {
		fmt.Printf("%s\n", version)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Capture real stdout for protocol output BEFORE redirecting
	protocolOut := os.Stdout

	// Redirect os.Stdout to stderr so nuclei's internal logging
	// doesn't pollute the JSON-line protocol on stdout
	os.Stdout = os.Stderr

	b := &bridge{
		ctx:    ctx,
		cancel: cancel,
		enc:    json.NewEncoder(protocolOut),
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			b.sendError("", fmt.Sprintf("invalid JSON: %v", err))
			continue
		}

		shouldExit := b.handleCommand(&req)
		if shouldExit {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "stdin read error: %v\n", err)
	}
}

// handleCommand dispatches a request to the appropriate handler.
// Returns true if the bridge should exit.
func (b *bridge) handleCommand(req *Request) bool {
	switch req.Cmd {
	case "version":
		b.handleVersion(req)
	case "setup":
		b.handleSetup(req)
	case "scan":
		b.handleScan(req)
	case "pool_create":
		b.handlePoolCreate(req)
	case "pool_submit":
		b.handlePoolSubmit(req)
	case "pool_stats":
		b.handlePoolStats(req)
	case "pool_close":
		b.handlePoolClose(req)
	case "close":
		b.handleClose(req)
		return true
	default:
		b.sendError(req.ID, fmt.Sprintf("unknown command: %s", req.Cmd))
	}
	return false
}

// handleVersion returns the bridge version info.
func (b *bridge) handleVersion(req *Request) {
	info := map[string]string{
		"version": version,
		"commit":  commit,
		"date":    date,
	}
	data, _ := json.Marshal(info)
	raw := json.RawMessage(data)
	b.send(Response{ID: req.ID, Type: "version", Data: &raw})
}

// handleSetup creates and sets up the scan engine.
func (b *bridge) handleSetup(req *Request) {
	if b.engine != nil {
		b.sendError(req.ID, "engine already set up")
		return
	}

	var opts []nucleisdk.Option
	if req.Config != nil {
		opts = req.Config.toEngineOptions()
	}

	engine, err := nucleisdk.NewScanEngine(opts...)
	if err != nil {
		b.sendError(req.ID, fmt.Sprintf("creating engine: %v", err))
		return
	}

	if err := engine.Setup(); err != nil {
		b.sendError(req.ID, fmt.Sprintf("engine setup: %v", err))
		return
	}

	b.engine = engine
	b.send(Response{ID: req.ID, Type: "setup_complete"})
}

// handleScan runs a lightweight scan and streams results.
func (b *bridge) handleScan(req *Request) {
	if b.engine == nil {
		b.sendError(req.ID, "engine not set up — send setup first")
		return
	}
	if req.Options == nil {
		b.sendError(req.ID, "scan options required")
		return
	}

	scanOpts := req.Options.toScanOptions()
	results, err := b.engine.Scan(b.ctx, scanOpts)
	if err != nil {
		b.sendError(req.ID, fmt.Sprintf("scan error: %v", err))
		return
	}

	// Stream results in a goroutine so we can handle other commands concurrently
	go func() {
		for r := range results {
			if r.Error != "" {
				b.sendError(req.ID, r.Error)
				continue
			}
			b.sendResult(req.ID, "", r)
		}
		b.send(Response{ID: req.ID, Type: "scan_complete"})
	}()
}

// handlePoolCreate creates a scan pool with the specified number of workers.
func (b *bridge) handlePoolCreate(req *Request) {
	if b.engine == nil {
		b.sendError(req.ID, "engine not set up — send setup first")
		return
	}
	if b.pool != nil {
		b.sendError(req.ID, "pool already created")
		return
	}

	workers := req.Workers
	if workers <= 0 {
		workers = 10
	}

	b.pool = b.engine.NewScanPool(b.ctx, workers)

	// Background goroutine to stream pool results
	go func() {
		for r := range b.pool.Results() {
			if r.Error != "" {
				b.sendError("", fmt.Sprintf("pool job %q: %s", r.Label, r.Error))
				continue
			}
			b.sendResult("", r.Label, r.ScanResult)
		}
	}()

	b.send(Response{ID: req.ID, Type: "pool_created"})
}

// handlePoolSubmit submits a scan job to the pool.
func (b *bridge) handlePoolSubmit(req *Request) {
	if b.pool == nil {
		b.sendError(req.ID, "no pool created — send pool_create first")
		return
	}
	if req.Options == nil {
		b.sendError(req.ID, "scan options required")
		return
	}

	scanOpts := req.Options.toScanOptions()
	if err := b.pool.Submit(req.Label, scanOpts); err != nil {
		b.sendError(req.ID, fmt.Sprintf("pool submit: %v", err))
		return
	}

	b.send(Response{ID: req.ID, Type: "pool_submitted"})
}

// handlePoolStats returns pool statistics.
func (b *bridge) handlePoolStats(req *Request) {
	if b.pool == nil {
		b.sendError(req.ID, "no pool created")
		return
	}

	stats := b.pool.Stats()
	data, _ := json.Marshal(stats)
	raw := json.RawMessage(data)
	b.send(Response{ID: req.ID, Type: "pool_stats", Data: &raw})
}

// handlePoolClose closes the pool and waits for pending jobs.
func (b *bridge) handlePoolClose(req *Request) {
	if b.pool == nil {
		b.sendError(req.ID, "no pool created")
		return
	}

	b.pool.Close()
	b.pool = nil
	b.send(Response{ID: req.ID, Type: "pool_closed"})
}

// handleClose shuts down the engine and exits.
func (b *bridge) handleClose(req *Request) {
	if b.pool != nil {
		b.pool.Close()
		b.pool = nil
	}
	if b.engine != nil {
		b.engine.Close()
		b.engine = nil
	}
	b.send(Response{ID: req.ID, Type: "closed"})
}

// --- Output helpers ---

// send writes a JSON response to stdout (thread-safe).
func (b *bridge) send(resp Response) {
	b.encMu.Lock()
	defer b.encMu.Unlock()
	_ = b.enc.Encode(resp)
}

// sendError sends an error response.
func (b *bridge) sendError(id, msg string) {
	b.send(Response{ID: id, Type: "error", Error: msg})
}

// sendResult sends a scan result response.
func (b *bridge) sendResult(id, label string, r *nucleisdk.ScanResult) {
	rd := scanResultToData(r)
	data, err := json.Marshal(rd)
	if err != nil {
		return
	}
	raw := json.RawMessage(data)

	respType := "result"
	if label != "" {
		respType = "pool_result"
	}

	b.send(Response{
		ID:    id,
		Type:  respType,
		Data:  &raw,
		Label: label,
	})
}
