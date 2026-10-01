package status

import "testing"

func TestValidateRejectsUnknownAllUserExportState(t *testing.T) {
	snapshot := Snapshot{
		SchemaVersion:  1,
		CollectedAt:    "2026-08-28T18:00:00Z",
		Node:           Node{Hostname: "control_node"},
		AllUsersExport: &AllUsersExport{State: "surprise"},
	}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected invalid all-user export state error")
	}
}
