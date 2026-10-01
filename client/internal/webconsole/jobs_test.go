package webconsole

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestExportJobPruningRetainsActiveJobs(t *testing.T) {
	audit, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jobs := NewExportJobs(NewCommandSource(Config{ManagedHome: "/Users/managed"}), audit)
	now := time.Now().UTC()
	activeID := "job-129"
	for index := 0; index < 130; index++ {
		id := fmt.Sprintf("job-%03d", index)
		state := "complete"
		if id == activeID {
			state = "running"
		}
		jobs.jobs[id] = &exportJobState{job: ExportJob{ID: id, State: state, CreatedAt: now.Format(time.RFC3339)}}
		jobs.order = append(jobs.order, id)
	}
	jobs.pruneLocked(now)
	if _, ok := jobs.jobs[activeID]; !ok {
		t.Fatal("active export job was pruned")
	}
	found := false
	for _, id := range jobs.order {
		found = found || id == activeID
	}
	if !found {
		t.Fatal("active export job disappeared from display order")
	}
}

func TestExportJobRejectsDuplicateActiveSelection(t *testing.T) {
	audit, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jobs := NewExportJobs(NewCommandSource(Config{ManagedHome: "/Users/managed"}), audit)
	jobs.jobs["active"] = &exportJobState{job: ExportJob{
		ID:        "active",
		State:     "running",
		Paths:     []string{"/Users/managed/Documents", "/Users/managed/Desktop"},
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Username:  "operator",
	}}
	jobs.order = append(jobs.order, "active")

	_, err = jobs.Start(
		[]string{"/Users/managed/Desktop", "/Users/managed/Documents"},
		"operator",
		"100.101.0.10",
	)
	if err == nil || err.Error() != "an identical export job is already pending" {
		t.Fatalf("duplicate active export error = %v", err)
	}
}

func TestExportJobQueueIsBounded(t *testing.T) {
	audit, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jobs := NewExportJobs(NewCommandSource(Config{ManagedHome: "/Users/managed"}), audit)
	now := time.Now().UTC().Format(time.RFC3339)
	for index := 0; index < maxPendingExportJobs; index++ {
		id := fmt.Sprintf("pending-%d", index)
		jobs.jobs[id] = &exportJobState{job: ExportJob{ID: id, State: "queued", CreatedAt: now}}
		jobs.order = append(jobs.order, id)
	}
	if _, err := jobs.Start([]string{"/Users/managed/Documents"}, "operator", "100.101.0.10"); err == nil {
		t.Fatal("unbounded export queue was accepted")
	}
}
