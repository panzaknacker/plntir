package webconsole

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	maxPendingExportJobs  = 8
	maxRetainedExportJobs = 128
)

type ExportJob struct {
	ID          string         `json:"id"`
	State       string         `json:"state"`
	Paths       []string       `json:"paths"`
	CurrentPath string         `json:"current_path,omitempty"`
	Results     []ExportResult `json:"results"`
	Error       string         `json:"error,omitempty"`
	CreatedAt   string         `json:"created_at"`
	StartedAt   string         `json:"started_at,omitempty"`
	CompletedAt string         `json:"completed_at,omitempty"`
	Username    string         `json:"username"`
}

type exportJobState struct {
	job    ExportJob
	cancel context.CancelFunc
}

type ExportJobs struct {
	mu     sync.Mutex
	jobs   map[string]*exportJobState
	order  []string
	source *CommandSource
	audit  *AuditLog
	worker chan struct{}
}

func NewExportJobs(source *CommandSource, audit *AuditLog) *ExportJobs {
	return &ExportJobs{
		jobs:   make(map[string]*exportJobState),
		source: source,
		audit:  audit,
		worker: make(chan struct{}, 1),
	}
}

func (jobs *ExportJobs) Start(paths []string, username, remoteIP string) (ExportJob, error) {
	if len(paths) < 1 || len(paths) > 32 {
		return ExportJob{}, errors.New("select between 1 and 32 paths")
	}
	validated := make([]string, 0, len(paths))
	seen := make(map[string]bool)
	for _, path := range paths {
		clean, _, err := jobs.source.pathToken(path)
		if err != nil {
			return ExportJob{}, err
		}
		if !seen[clean] {
			seen[clean] = true
			validated = append(validated, clean)
		}
	}
	id, err := randomToken(18)
	if err != nil {
		return ExportJob{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UTC()
	state := &exportJobState{
		job: ExportJob{
			ID:        id,
			State:     "queued",
			Paths:     validated,
			Results:   []ExportResult{},
			CreatedAt: now.Format(time.RFC3339),
			Username:  username,
		},
		cancel: cancel,
	}
	jobs.mu.Lock()
	jobs.pruneLocked(now)
	pending := 0
	for _, existing := range jobs.jobs {
		if existing.job.State == "queued" || existing.job.State == "running" {
			pending++
			if existing.job.Username == username && samePathSelection(existing.job.Paths, validated) {
				jobs.mu.Unlock()
				cancel()
				return ExportJob{}, errors.New("an identical export job is already pending")
			}
		}
	}
	if pending >= maxPendingExportJobs {
		jobs.mu.Unlock()
		cancel()
		return ExportJob{}, errors.New("too many pending export jobs")
	}
	jobs.jobs[id] = state
	jobs.order = append([]string{id}, jobs.order...)
	copy := cloneExportJob(state.job)
	jobs.mu.Unlock()
	_ = jobs.audit.Write("export.queued", username, remoteIP, true, map[string]any{
		"job_id": id,
		"paths":  validated,
	})
	go jobs.run(ctx, id, remoteIP)
	return copy, nil
}

func (jobs *ExportJobs) List(username string) []ExportJob {
	jobs.mu.Lock()
	defer jobs.mu.Unlock()
	jobs.pruneLocked(time.Now().UTC())
	result := make([]ExportJob, 0, len(jobs.order))
	for _, id := range jobs.order {
		state, ok := jobs.jobs[id]
		if ok && state.job.Username == username {
			result = append(result, cloneExportJob(state.job))
		}
	}
	return result
}

func (jobs *ExportJobs) Cancel(id, username, remoteIP string) error {
	jobs.mu.Lock()
	state, ok := jobs.jobs[id]
	if !ok || state.job.Username != username {
		jobs.mu.Unlock()
		return errors.New("export job not found")
	}
	if state.job.State != "queued" && state.job.State != "running" {
		jobs.mu.Unlock()
		return errors.New("export job is already finished")
	}
	state.cancel()
	jobs.mu.Unlock()
	_ = jobs.audit.Write("export.cancel", username, remoteIP, true, map[string]any{"job_id": id})
	return nil
}

func (jobs *ExportJobs) run(ctx context.Context, id, remoteIP string) {
	select {
	case jobs.worker <- struct{}{}:
		defer func() { <-jobs.worker }()
	case <-ctx.Done():
		jobs.finish(id, "cancelled", nil, remoteIP)
		return
	}
	jobs.mu.Lock()
	state, ok := jobs.jobs[id]
	if !ok {
		jobs.mu.Unlock()
		return
	}
	state.job.State = "running"
	state.job.StartedAt = time.Now().UTC().Format(time.RFC3339)
	paths := append([]string(nil), state.job.Paths...)
	username := state.job.Username
	jobs.mu.Unlock()

	for _, path := range paths {
		jobs.mu.Lock()
		if current, ok := jobs.jobs[id]; ok {
			current.job.CurrentPath = path
		}
		jobs.mu.Unlock()
		result, err := jobs.source.Export(ctx, path)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				jobs.finish(id, "cancelled", nil, remoteIP)
				return
			}
			jobs.finish(id, "failed", err, remoteIP)
			return
		}
		jobs.mu.Lock()
		if current, ok := jobs.jobs[id]; ok {
			current.job.Results = append(current.job.Results, result)
		}
		jobs.mu.Unlock()
	}
	jobs.finish(id, "complete", nil, remoteIP)
	_ = jobs.audit.Write("export.complete", username, remoteIP, true, map[string]any{"job_id": id})
}

func (jobs *ExportJobs) finish(id, state string, failure error, remoteIP string) {
	jobs.mu.Lock()
	current, ok := jobs.jobs[id]
	if !ok {
		jobs.mu.Unlock()
		return
	}
	current.job.State = state
	current.job.CurrentPath = ""
	current.job.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	if failure != nil {
		current.job.Error = failure.Error()
	}
	username := current.job.Username
	jobs.mu.Unlock()
	if failure != nil {
		_ = jobs.audit.Write("export."+state, username, remoteIP, false, map[string]any{
			"job_id": id,
			"error":  failure.Error(),
		})
	}
}

func (jobs *ExportJobs) pruneLocked(now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	kept := jobs.order[:0]
	for _, id := range jobs.order {
		state, ok := jobs.jobs[id]
		if !ok {
			continue
		}
		created, err := time.Parse(time.RFC3339, state.job.CreatedAt)
		finished := state.job.State == "complete" || state.job.State == "failed" || state.job.State == "cancelled"
		if err == nil && finished && created.Before(cutoff) {
			delete(jobs.jobs, id)
			continue
		}
		kept = append(kept, id)
	}
	jobs.order = kept
	if len(jobs.order) > maxRetainedExportJobs {
		trimmed := make([]string, 0, maxRetainedExportJobs)
		for _, id := range jobs.order {
			state := jobs.jobs[id]
			active := state != nil && (state.job.State == "queued" || state.job.State == "running")
			if len(trimmed) < maxRetainedExportJobs || active {
				trimmed = append(trimmed, id)
				continue
			}
			delete(jobs.jobs, id)
		}
		jobs.order = trimmed
	}
}

func samePathSelection(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	wanted := make(map[string]struct{}, len(left))
	for _, path := range left {
		wanted[path] = struct{}{}
	}
	for _, path := range right {
		if _, ok := wanted[path]; !ok {
			return false
		}
	}
	return true
}

func cloneExportJob(job ExportJob) ExportJob {
	job.Paths = append([]string(nil), job.Paths...)
	job.Results = append([]ExportResult(nil), job.Results...)
	return job
}
