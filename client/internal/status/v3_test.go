package status

import "testing"

func TestLegacyToV3DoesNotClaimUnavailableControls(t *testing.T) {
	legacy := Snapshot{
		SchemaVersion: 2,
		CollectedAt:   "2026-09-04T10:00:00Z",
		Node: Node{
			Hostname:          "watch",
			WarpServiceActive: true,
			WarpConnected:     true,
		},
		Mac: Mac{Health: &MacHealth{
			Timestamp: "2026-09-04T09:59:30Z",
			State:     "online",
		}},
		Timers: Timers{
			ControlNode: Timer{Active: true},
			Security:    Timer{Active: true},
		},
	}

	converted, err := LegacyToV3(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if converted.Source.Mode != "legacy-read-only" || converted.Source.SchemaVersion != 2 {
		t.Fatalf("unexpected source: %#v", converted.Source)
	}
	if got := converted.Devices[0].Management.State; got != "unavailable" {
		t.Fatalf("legacy adapter claimed management state %q", got)
	}
	if got := converted.Devices[0].Wipe.State; got != "unverified" {
		t.Fatalf("legacy adapter claimed wipe state %q", got)
	}
	if got := converted.Devices[0].Telemetry.State; got != "fresh" {
		t.Fatalf("unexpected telemetry state %q", got)
	}
}

func TestPlatformSnapshotSupportsMultipleDevices(t *testing.T) {
	snapshot := validPlatformSnapshot()
	snapshot.Devices = append(snapshot.Devices, DeviceStatus{
		ID:          "ios-pilot",
		DisplayName: "Pilot iPhone",
		Platform:    "ios",
		Version:     2,
		Management:  ManagementStatus{State: "partial"},
		Posture:     PostureStatus{State: "degraded", Failed: []string{"sensor-content-unavailable"}},
		Sensors: []SensorStatus{{
			Kind:     "ai-native",
			Coverage: "unavailable",
		}},
		Telemetry: TelemetryStatus{State: "fresh", LastSeenAt: "2026-09-04T09:59:00Z", MaxAgeSeconds: 900},
		Backup:    BackupStatus{State: "unavailable"},
		Wipe:      WipeCapabilityState{State: "unverified", Reason: "enrollment type not yet proven"},
	})
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformSnapshotRejectsDuplicateAndUnknownReferences(t *testing.T) {
	snapshot := validPlatformSnapshot()
	snapshot.Devices = append(snapshot.Devices, snapshot.Devices[0])
	if err := snapshot.Validate(); err == nil {
		t.Fatal("duplicate device unexpectedly validated")
	}

	snapshot = validPlatformSnapshot()
	snapshot.Incidents = []IncidentSummary{{
		ID:         "incident-1",
		DeviceID:   "missing-device",
		Severity:   "high",
		State:      "open",
		Kind:       "integrity",
		OccurredAt: "2026-09-04T09:59:00Z",
		Summary:    "Integrity drift",
	}}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("incident with an unknown device unexpectedly validated")
	}
}

func validPlatformSnapshot() PlatformSnapshot {
	return PlatformSnapshot{
		SchemaVersion: SchemaVersionV3,
		CollectedAt:   "2026-09-04T10:00:00Z",
		Source:        ProjectionSource{Mode: "native", SchemaVersion: 3},
		Services: []ServiceStatus{{
			ID:         "plntir-core-01",
			Kind:       "core",
			State:      "healthy",
			ObservedAt: "2026-09-04T10:00:00Z",
		}},
		Devices: []DeviceStatus{{
			ID:          "mac-pilot",
			DisplayName: "Pilot Mac",
			Platform:    "macos",
			Version:     1,
			Management:  ManagementStatus{State: "verified", ObservedAt: "2026-09-04T09:59:00Z"},
			Posture:     PostureStatus{State: "passing", Failed: []string{}},
			Sensors:     []SensorStatus{{Kind: "monitoring", Coverage: "full"}},
			Telemetry:   TelemetryStatus{State: "fresh", LastSeenAt: "2026-09-04T09:59:00Z", MaxAgeSeconds: 150},
			Backup:      BackupStatus{State: "unknown"},
			Wipe:        WipeCapabilityState{State: "verified"},
		}},
		Incidents: []IncidentSummary{},
		Budgets: BudgetStatus{
			AWSMonthlyLimitUSD:        50,
			CloudflareMonthlyLimitUSD: 50,
			AWSState:                  "unknown",
			CloudflareState:           "unknown",
		},
	}
}
