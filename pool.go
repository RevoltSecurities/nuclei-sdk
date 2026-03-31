package nucleisdk

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// ScanPool manages a pool of concurrent scan workers backed by a shared ScanEngine.
// Jobs can be submitted dynamically at any time, and results stream through a
// unified channel. This is ideal for continuous scanning workflows where new
// targets/templates arrive over time (e.g., from an API, message queue, or webhook).
//
// Usage:
//
//	pool := engine.NewScanPool(ctx, 10)
//
//	pool.Submit("CVE-2024-1234", &nucleisdk.ScanOptions{...})
//	pool.Submit("CVE-2024-5678", &nucleisdk.ScanOptions{...})
//
//	go func() {
//	    for r := range pool.Results() {
//	        fmt.Printf("[%s] %s\n", r.Label, r.TemplateID)
//	    }
//	}()
//
//	pool.Submit("CVE-2024-9999", &nucleisdk.ScanOptions{...})
//
//	pool.Close()
//	fmt.Println(pool.Stats())
type ScanPool struct {
	engine *ScanEngine
	ctx    context.Context
	cancel context.CancelFunc

	jobCh    chan scanJob
	resultCh chan *LabeledResult

	wg        sync.WaitGroup
	closed    atomic.Bool
	closeOnce sync.Once

	// Counters
	submitted atomic.Int64
	completed atomic.Int64
	failed    atomic.Int64
}

// scanJob is an internal job submitted to the worker pool.
type scanJob struct {
	Label   string
	Options *ScanOptions
}

// PoolStats holds scan pool statistics.
type PoolStats struct {
	Submitted int64 `json:"submitted"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Pending   int64 `json:"pending"`
}

// NewScanPool creates a worker pool with the specified number of concurrent
// scan workers. Each worker calls engine.Scan() for each job it picks up,
// so the total concurrency is bounded by the worker count.
//
// The pool starts immediately — workers begin consuming jobs as they are submitted.
// Call Close() when done to signal no more jobs and wait for completion.
//
// The Results() channel MUST be consumed concurrently, otherwise workers will block.
func (se *ScanEngine) NewScanPool(ctx context.Context, workers int) *ScanPool {
	if workers <= 0 {
		workers = 10
	}

	poolCtx, cancel := context.WithCancel(ctx)

	p := &ScanPool{
		engine:   se,
		ctx:      poolCtx,
		cancel:   cancel,
		jobCh:    make(chan scanJob, workers*2),
		resultCh: make(chan *LabeledResult, 100),
	}

	p.startWorkers(workers)
	return p
}

// Submit queues a labeled scan job for execution. Safe to call from multiple
// goroutines concurrently. Blocks if the internal job queue is full.
//
// Returns an error if the pool has been closed or the context is cancelled.
func (p *ScanPool) Submit(label string, opts *ScanOptions) error {
	if p.closed.Load() {
		return fmt.Errorf("scan pool is closed")
	}

	select {
	case p.jobCh <- scanJob{Label: label, Options: opts}:
		p.submitted.Add(1)
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// Results returns the channel that streams all scan results from all jobs.
// Each result is tagged with the job label it belongs to.
//
// The channel is closed after Close() is called and all pending jobs complete.
// This channel MUST be consumed — otherwise workers will block.
func (p *ScanPool) Results() <-chan *LabeledResult {
	return p.resultCh
}

// Close signals that no more jobs will be submitted and waits for all
// active scans to complete. The Results() channel is closed after the
// last result is sent.
//
// Safe to call multiple times.
func (p *ScanPool) Close() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		close(p.jobCh)
	})
	p.wg.Wait()
}

// Stats returns the current pool statistics.
func (p *ScanPool) Stats() PoolStats {
	return PoolStats{
		Submitted: p.submitted.Load(),
		Completed: p.completed.Load(),
		Failed:    p.failed.Load(),
		Pending:   p.submitted.Load() - p.completed.Load() - p.failed.Load(),
	}
}

// startWorkers launches worker goroutines and a cleanup goroutine that
// closes the result channel when all workers finish.
func (p *ScanPool) startWorkers(n int) {
	for i := 0; i < n; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	go func() {
		p.wg.Wait()
		close(p.resultCh)
	}()
}

// worker processes jobs from the job channel until it is closed or the
// context is cancelled.
func (p *ScanPool) worker() {
	defer p.wg.Done()

	for job := range p.jobCh {
		if p.ctx.Err() != nil {
			return
		}
		p.executeJob(job)
	}
}

// executeJob runs a single scan job and forwards all results to the
// result channel with the job's label attached.
func (p *ScanPool) executeJob(job scanJob) {
	results, err := p.engine.Scan(p.ctx, job.Options)
	if err != nil {
		p.failed.Add(1)
		select {
		case p.resultCh <- &LabeledResult{
			Label:      job.Label,
			ScanResult: &ScanResult{Error: err.Error()},
		}:
		case <-p.ctx.Done():
		}
		return
	}

	for r := range results {
		select {
		case p.resultCh <- &LabeledResult{Label: job.Label, ScanResult: r}:
		case <-p.ctx.Done():
			return
		}
	}

	p.completed.Add(1)
}
