package shadow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceConvertsLegacyWithoutInventingControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	data := []byte(`{
		"schema_version":1,
		"collected_at":"2026-09-04T10:00:00Z",
		"connection":{"target":"observer","round_trip_ms":42},
		"node":{"hostname":"watch","uptime_seconds":99,"warp_service_active":true,"warp_connected":true},
		"mac":{"health":{"timestamp":"2026-09-04T09:59:30Z","state":"online","ssh_rc":0,"snapshot":"ok"}},
		"timers":{"watchdog":{"active":true},"security":{"active":true}}
	}`)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	projection, err := New(path).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if projection.SchemaVersion != 3 || projection.Source.Mode != "legacy-read-only" {
		t.Fatalf("unexpected projection: %#v", projection)
	}
	if projection.Devices[0].Management.State != "unavailable" || projection.Devices[0].Wipe.State != "unverified" {
		t.Fatal("legacy source invented MDM or wipe capability")
	}
	if projection.Devices[0].Telemetry.State != "fresh" {
		t.Fatalf("unexpected telemetry state %q", projection.Devices[0].Telemetry.State)
	}
}

func TestSourceRejectsWritableOrUnknownInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":99}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path).Snapshot(context.Background()); err == nil {
		t.Fatal("group/world-writable status unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path).Snapshot(context.Background()); err == nil {
		t.Fatal("unknown schema unexpectedly accepted")
	}
}
