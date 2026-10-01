package status

import (
	"encoding/json"
	"testing"
)

func TestSnapshotFieldsAndLastKnownHealth(t *testing.T) {
	online := &MacHealth{
		Timestamp: "2026-08-28T18:00:00Z",
		State:     "online",
		Snapshot:  "console=worker\nfilevault=FileVault is On.\nmesh=inet 100.101.0.2",
	}
	mac := Mac{
		Health:           &MacHealth{State: "offline", Snapshot: "ssh failed"},
		LastOnlineHealth: online,
	}
	if mac.DisplayHealth() != online {
		t.Fatal("offline Mac did not select last successful snapshot")
	}
	fields := mac.DisplayHealth().SnapshotFields()
	if fields["console"] != "worker" || fields["filevault"] != "FileVault is On." {
		t.Fatalf("unexpected fields: %#v", fields)
	}
}

func TestValidateRejectsUnknownMacState(t *testing.T) {
	snapshot := Snapshot{
		SchemaVersion: 2,
		CollectedAt:   "2026-08-28T18:00:00Z",
		Node:          Node{Hostname: "control_node"},
		Mac:           Mac{Health: &MacHealth{State: "maybe"}},
	}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("expected invalid Mac state error")
	}
}

func TestLegacyTimerNameIsNormalized(t *testing.T) {
	var snapshot Snapshot
	err := json.Unmarshal([]byte(`{
		"schema_version":1,
		"collected_at":"2026-08-28T18:00:00Z",
		"node":{"hostname":"legacy-node"},
		"mac":{},
		"timers":{"watchdog":{"active":true},"security":{}},
		"storage":{},
		"retrieval":{},
		"events":[]
	}`), &snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Timers.ControlNode.Active {
		t.Fatal("legacy timer was not normalized to control_node")
	}
}

func TestParseCompactSecurityTimestamp(t *testing.T) {
	parsed, err := ParseTime("20260828T180430Z")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.UTC().Hour() != 18 || parsed.UTC().Minute() != 4 {
		t.Fatalf("unexpected parsed time: %s", parsed)
	}
}
