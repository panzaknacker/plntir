package ui

import (
	"strings"
	"testing"
	"time"

	"plntir/client/internal/status"
)

func TestSanitizeRemovesTerminalAndBidiControls(t *testing.T) {
	got := Sanitize("safe\x1b[2J\u202eevil\nnext")
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\u202e') || strings.ContainsRune(got, '\n') {
		t.Fatalf("unsafe output survived: %q", got)
	}
	if got != "safe[2Jevil next" {
		t.Fatalf("unexpected sanitized output: %q", got)
	}
}

func TestRenderMarksExpectedOfflineWithoutAlert(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Mac.Health.State = "offline"
	snapshot.Mac.Health.SSHRC = 255
	options := Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		OfflineReason:  "Transport",
		RefreshSeconds: 10,
	}
	rendered := Render(&snapshot, options)
	if !strings.Contains(rendered, "EXPECTED OFFLINE") {
		t.Fatalf("expected-offline status missing:\n%s", rendered)
	}
	if strings.Contains(rendered, "Mac is unexpectedly offline") {
		t.Fatalf("unexpected-offline alert was not suppressed:\n%s", rendered)
	}
}

func TestRenderNeverEmitsRemoteEscapeSequences(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Node.Hostname = "control-node\x1b[2Jowned"
	snapshot.Events = []status.Event{{Timestamp: "2026-08-28T18:00:00Z", Message: "event\x1b[31mred"}}
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
		Color:          false,
	})
	if strings.ContainsRune(rendered, '\x1b') {
		t.Fatalf("terminal escape reached uncolored output: %q", rendered)
	}
}

func TestRenderTreatsOldOnlineHealthAsStale(t *testing.T) {
	snapshot := fixtureSnapshot()
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 3, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "Mac STALE") {
		t.Fatalf("stale status missing:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Mac health data is older than 150 seconds") {
		t.Fatalf("stale alert missing:\n%s", rendered)
	}
	if strings.Contains(rendered, "● Mac ONLINE") {
		t.Fatalf("stale snapshot was shown as online:\n%s", rendered)
	}
}

func TestRenderUsesStackedLayoutOnNarrowTerminal(t *testing.T) {
	snapshot := fixtureSnapshot()
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          60,
		RefreshSeconds: 10,
	})
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, "PLNTIR CONTROL NODE") && strings.Contains(line, "MANAGED MAC") {
			t.Fatalf("narrow terminal used side-by-side columns: %q", line)
		}
	}
}

func TestRenderWarnsWhenAllUserExportNeedsFullDiskAccess(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.AllUsersExport.State = "blocked"
	snapshot.AllUsersExport.Reason = "full_disk_access_required"
	snapshot.AllUsersExport.UnreadableEntries = 7
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "All-user export needs macOS Full Disk Access (MDM/PPPC)") {
		t.Fatalf("full-disk-access warning missing:\n%s", rendered)
	}
}

func TestRenderTreatsPrivateArchiveAsOnDemandAndIgnoresDiskEncryption(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Timers.ExportReadiness.Enabled = false
	snapshot.Timers.ExportReadiness.Active = false
	snapshot.Mac.Health.Snapshot = strings.Replace(
		snapshot.Mac.Health.Snapshot,
		"filevault=FileVault is On.",
		"filevault=FileVault is Off.",
		1,
	)
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "ON-DEMAND / idle") {
		t.Fatalf("on-demand archive marker missing:\n%s", rendered)
	}
	for _, unexpected := range []string{
		"All-user export readiness timer is inactive",
		"Mac FileVault is off",
		"FileVault     ",
	} {
		if strings.Contains(rendered, unexpected) {
			t.Fatalf("out-of-scope disk or scheduled-archive warning rendered (%q):\n%s", unexpected, rendered)
		}
	}
}

func TestRenderWarnsWhenControlNodeStorageIsInsufficient(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.AllUsersExport.State = "blocked"
	snapshot.AllUsersExport.Reason = "insufficient_control_node_storage"
	snapshot.AllUsersExport.RequiredBytes = 200 * 1024 * 1024 * 1024
	snapshot.AllUsersExport.AvailableBytes = 100 * 1024 * 1024 * 1024
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "All-user export needs 200.0 GiB; Plntir Control Node has 100.0 GiB free") {
		t.Fatalf("storage warning missing:\n%s", rendered)
	}
}

func TestRenderMarksCachedStorageReadiness(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.AllUsersExport.State = "blocked"
	snapshot.AllUsersExport.Reason = "insufficient_control_node_storage"
	snapshot.AllUsersExport.PlanCached = true
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "BLOCKED / storage (cached)") {
		t.Fatalf("cached storage readiness marker missing:\n%s", rendered)
	}
}

func TestRenderWarnsOnAlertOnlyIntegrityDrift(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Mac.Health.Snapshot = strings.Replace(
		snapshot.Mac.Health.Snapshot,
		"integrity_state=healthy",
		"integrity_state=drift",
		1,
	)
	snapshot.Mac.Health.Snapshot = strings.Replace(
		snapshot.Mac.Health.Snapshot,
		"integrity_drift_count=0",
		"integrity_drift_count=2",
		1,
	)
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "DRIFT / 2 finding(s)") {
		t.Fatalf("integrity drift status missing:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Mac Plntir integrity drift detected (2 finding(s), alert-only)") {
		t.Fatalf("integrity drift alert missing:\n%s", rendered)
	}
}

func TestRenderWarnsWhenIntegrityStatusStopsAdvancing(t *testing.T) {
	snapshot := fixtureSnapshot()
	snapshot.Mac.Health.Snapshot = strings.Replace(
		snapshot.Mac.Health.Snapshot,
		"integrity_checked_at=2026-08-28T18:00:00Z",
		"integrity_checked_at=2026-08-28T17:40:00Z",
		1,
	)
	rendered := Render(&snapshot, Options{
		Now:            time.Date(2026, 8, 28, 18, 1, 0, 0, time.UTC),
		Location:       time.UTC,
		Width:          112,
		RefreshSeconds: 10,
	})
	if !strings.Contains(rendered, "Integrity     STALE") {
		t.Fatalf("stale integrity status missing:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Mac Plntir integrity status is older than 10 minutes") {
		t.Fatalf("stale integrity alert missing:\n%s", rendered)
	}
}

func fixtureSnapshot() status.Snapshot {
	return status.Snapshot{
		SchemaVersion: 2,
		CollectedAt:   "2026-08-28T18:00:00Z",
		Connection:    status.Connection{Target: "admin@plntir-control-node", RoundTripMilliseconds: 20},
		Node: status.Node{
			Hostname:           "control_node",
			WarpServiceActive:  true,
			WarpConnected:      true,
			Fail2BanActive:     true,
			NTPSynchronized:    true,
			AutoUpdatesEnabled: true,
			PublicSSH:          "restricted",
		},
		Mac: status.Mac{
			Health: &status.MacHealth{
				Timestamp: "2026-08-28T18:00:00Z",
				State:     "online",
				Snapshot:  "console=worker\nfilevault=FileVault is On.\ngatekeeper=assessments enabled\nintegrity_state=healthy\nintegrity_mode=alert-only\nintegrity_checked_at=2026-08-28T18:00:00Z\nintegrity_drift_count=0\nremote_login=reachable",
			},
			LastOnline: "2026-08-28T18:00:00Z",
			Security: &status.Security{
				Timestamp:   "20260828T180000Z",
				PostureRC:   0,
				TelemetryRC: 0,
			},
		},
		Timers: status.Timers{
			ControlNode:     status.Timer{Active: true, Enabled: true, ServiceResult: "success"},
			Security:        status.Timer{Active: true, Enabled: true, ServiceResult: "success"},
			ExportReadiness: &status.Timer{Active: true, Enabled: true, ServiceResult: "success"},
		},
		AllUsersExport: &status.AllUsersExport{State: "ready", Reason: "ready", SourceBytes: 64 * 1024 * 1024 * 1024},
	}
}
