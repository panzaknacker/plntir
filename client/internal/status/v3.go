package status

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const SchemaVersionV3 = 3

// PlatformSnapshot is the normalized, multi-device status projection used by
// plntir v1. legacy Snapshot values remain available to the existing console
// through a read-only adapter; writers must emit this schema directly.
type PlatformSnapshot struct {
	SchemaVersion int               `json:"schema_version"`
	CollectedAt   string            `json:"collected_at"`
	Source        ProjectionSource  `json:"source"`
	Services      []ServiceStatus   `json:"services"`
	Devices       []DeviceStatus    `json:"devices"`
	Incidents     []IncidentSummary `json:"incidents"`
	Budgets       BudgetStatus      `json:"budgets"`
}

type ProjectionSource struct {
	Mode          string `json:"mode"`
	SchemaVersion int    `json:"schema_version"`
}

type ServiceStatus struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	ObservedAt string `json:"observed_at"`
	Detail     string `json:"detail,omitempty"`
}

type DeviceStatus struct {
	ID           string              `json:"id"`
	DisplayName  string              `json:"display_name"`
	Platform     string              `json:"platform"`
	Version      int64               `json:"version"`
	Management   ManagementStatus    `json:"management"`
	Posture      PostureStatus       `json:"posture"`
	Sensors      []SensorStatus      `json:"sensors"`
	Telemetry    TelemetryStatus     `json:"telemetry"`
	Backup       BackupStatus        `json:"backup"`
	IncidentRefs []string            `json:"incident_refs"`
	Wipe         WipeCapabilityState `json:"wipe"`
}

type ManagementStatus struct {
	State          string `json:"state"`
	EnrollmentType string `json:"enrollment_type,omitempty"`
	ObservedAt     string `json:"observed_at,omitempty"`
}

type PostureStatus struct {
	State      string   `json:"state"`
	ObservedAt string   `json:"observed_at,omitempty"`
	Failed     []string `json:"failed"`
}

type SensorStatus struct {
	Kind       string `json:"kind"`
	Coverage   string `json:"coverage"`
	ObservedAt string `json:"observed_at,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type TelemetryStatus struct {
	State         string `json:"state"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
	MaxAgeSeconds int64  `json:"max_age_seconds,omitempty"`
}

type BackupStatus struct {
	State          string `json:"state"`
	LastSuccessAt  string `json:"last_success_at,omitempty"`
	LastVerifiedAt string `json:"last_verified_at,omitempty"`
	PendingBytes   int64  `json:"pending_bytes,omitempty"`
}

type WipeCapabilityState struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type IncidentSummary struct {
	ID         string `json:"id"`
	DeviceID   string `json:"device_id,omitempty"`
	Severity   string `json:"severity"`
	State      string `json:"state"`
	Kind       string `json:"kind"`
	OccurredAt string `json:"occurred_at"`
	Summary    string `json:"summary"`
}

type BudgetStatus struct {
	AWSMonthlyLimitUSD        int    `json:"aws_monthly_limit_usd"`
	CloudflareMonthlyLimitUSD int    `json:"cloudflare_monthly_limit_usd"`
	AWSState                  string `json:"aws_state"`
	CloudflareState           string `json:"cloudflare_state"`
}

func (s PlatformSnapshot) Validate() error {
	if s.SchemaVersion != SchemaVersionV3 {
		return fmt.Errorf("unsupported platform status schema %d", s.SchemaVersion)
	}
	if _, err := ParseTime(s.CollectedAt); err != nil {
		return fmt.Errorf("invalid collected_at: %w", err)
	}
	if !oneOf(s.Source.Mode, "native", "legacy-read-only") {
		return fmt.Errorf("invalid projection source mode %q", s.Source.Mode)
	}
	if s.Source.SchemaVersion < 1 || s.Source.SchemaVersion > SchemaVersionV3 {
		return fmt.Errorf("invalid source schema version %d", s.Source.SchemaVersion)
	}
	if err := validateUniqueServices(s.Services); err != nil {
		return err
	}
	if err := validateDevices(s.Devices); err != nil {
		return err
	}
	if err := validateIncidents(s.Incidents, s.Devices); err != nil {
		return err
	}
	if !oneOf(s.Budgets.AWSState, "unknown", "ok", "warning", "blocked") {
		return fmt.Errorf("invalid AWS budget state %q", s.Budgets.AWSState)
	}
	if !oneOf(s.Budgets.CloudflareState, "unknown", "ok", "warning", "blocked") {
		return fmt.Errorf("invalid Cloudflare budget state %q", s.Budgets.CloudflareState)
	}
	if s.Budgets.AWSMonthlyLimitUSD < 0 || s.Budgets.CloudflareMonthlyLimitUSD < 0 {
		return fmt.Errorf("budget limits cannot be negative")
	}
	return nil
}

func validateUniqueServices(services []ServiceStatus) error {
	seen := make(map[string]struct{}, len(services))
	for _, service := range services {
		if !validStableID(service.ID) {
			return fmt.Errorf("invalid service id %q", service.ID)
		}
		if _, exists := seen[service.ID]; exists {
			return fmt.Errorf("duplicate service id %q", service.ID)
		}
		seen[service.ID] = struct{}{}
		if !oneOf(service.Kind, "watch", "core", "mdm", "siem", "edge", "relay", "scanner") {
			return fmt.Errorf("invalid service kind %q", service.Kind)
		}
		if !oneOf(service.State, "healthy", "degraded", "unavailable", "unknown") {
			return fmt.Errorf("invalid service state %q", service.State)
		}
		if service.ObservedAt != "" {
			if _, err := ParseTime(service.ObservedAt); err != nil {
				return fmt.Errorf("service %q has invalid observed_at: %w", service.ID, err)
			}
		}
	}
	return nil
}

func validateDevices(devices []DeviceStatus) error {
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		if !validStableID(device.ID) {
			return fmt.Errorf("invalid device id %q", device.ID)
		}
		if _, exists := seen[device.ID]; exists {
			return fmt.Errorf("duplicate device id %q", device.ID)
		}
		seen[device.ID] = struct{}{}
		if strings.TrimSpace(device.DisplayName) == "" {
			return fmt.Errorf("device %q is missing display_name", device.ID)
		}
		if !oneOf(device.Platform, "macos", "ios", "linux") {
			return fmt.Errorf("device %q has invalid platform %q", device.ID, device.Platform)
		}
		if device.Version < 1 {
			return fmt.Errorf("device %q has invalid version %d", device.ID, device.Version)
		}
		if !oneOf(device.Management.State, "verified", "partial", "unavailable") {
			return fmt.Errorf("device %q has invalid management state %q", device.ID, device.Management.State)
		}
		if !oneOf(device.Posture.State, "passing", "degraded", "failing", "unknown") {
			return fmt.Errorf("device %q has invalid posture state %q", device.ID, device.Posture.State)
		}
		if !oneOf(device.Telemetry.State, "fresh", "stale", "unavailable") {
			return fmt.Errorf("device %q has invalid telemetry state %q", device.ID, device.Telemetry.State)
		}
		if device.Telemetry.MaxAgeSeconds < 0 {
			return fmt.Errorf("device %q has negative telemetry max age", device.ID)
		}
		if !oneOf(device.Backup.State, "verified", "running", "paused", "failed", "unavailable", "unknown") {
			return fmt.Errorf("device %q has invalid backup state %q", device.ID, device.Backup.State)
		}
		if device.Backup.PendingBytes < 0 {
			return fmt.Errorf("device %q has negative pending backup bytes", device.ID)
		}
		if !oneOf(device.Wipe.State, "verified", "unverified", "unavailable") {
			return fmt.Errorf("device %q has invalid wipe state %q", device.ID, device.Wipe.State)
		}
		for _, stamp := range []struct {
			name  string
			value string
		}{
			{"management.observed_at", device.Management.ObservedAt},
			{"posture.observed_at", device.Posture.ObservedAt},
			{"telemetry.last_seen_at", device.Telemetry.LastSeenAt},
			{"backup.last_success_at", device.Backup.LastSuccessAt},
			{"backup.last_verified_at", device.Backup.LastVerifiedAt},
		} {
			if stamp.value == "" {
				continue
			}
			if _, err := ParseTime(stamp.value); err != nil {
				return fmt.Errorf("device %q has invalid %s: %w", device.ID, stamp.name, err)
			}
		}
		seenSensors := make(map[string]struct{}, len(device.Sensors))
		for _, sensor := range device.Sensors {
			if !oneOf(sensor.Kind, "monitoring", "wazuh", "ai-cli", "ai-web", "ai-native", "network") {
				return fmt.Errorf("device %q has invalid sensor kind %q", device.ID, sensor.Kind)
			}
			if _, exists := seenSensors[sensor.Kind]; exists {
				return fmt.Errorf("device %q has duplicate sensor %q", device.ID, sensor.Kind)
			}
			seenSensors[sensor.Kind] = struct{}{}
			if !oneOf(sensor.Coverage, "full", "partial", "unavailable") {
				return fmt.Errorf("device %q sensor %q has invalid coverage %q", device.ID, sensor.Kind, sensor.Coverage)
			}
			if sensor.ObservedAt != "" {
				if _, err := ParseTime(sensor.ObservedAt); err != nil {
					return fmt.Errorf("device %q sensor %q has invalid observed_at: %w", device.ID, sensor.Kind, err)
				}
			}
		}
	}
	return nil
}

func validateIncidents(incidents []IncidentSummary, devices []DeviceStatus) error {
	knownDevices := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		knownDevices[device.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(incidents))
	for _, incident := range incidents {
		if !validStableID(incident.ID) {
			return fmt.Errorf("invalid incident id %q", incident.ID)
		}
		if _, exists := seen[incident.ID]; exists {
			return fmt.Errorf("duplicate incident id %q", incident.ID)
		}
		seen[incident.ID] = struct{}{}
		if incident.DeviceID != "" {
			if _, exists := knownDevices[incident.DeviceID]; !exists {
				return fmt.Errorf("incident %q references unknown device %q", incident.ID, incident.DeviceID)
			}
		}
		if !oneOf(incident.Severity, "info", "low", "medium", "high", "critical") {
			return fmt.Errorf("incident %q has invalid severity %q", incident.ID, incident.Severity)
		}
		if !oneOf(incident.State, "open", "acknowledged", "resolved") {
			return fmt.Errorf("incident %q has invalid state %q", incident.ID, incident.State)
		}
		if _, err := ParseTime(incident.OccurredAt); err != nil {
			return fmt.Errorf("incident %q has invalid occurred_at: %w", incident.ID, err)
		}
		if strings.TrimSpace(incident.Kind) == "" || strings.TrimSpace(incident.Summary) == "" {
			return fmt.Errorf("incident %q is missing kind or summary", incident.ID)
		}
	}
	return nil
}

// LegacyToV3 exposes an existing v1/v2 collector result as an explicitly
// read-only projection. it never invents MDM, wipe, backup, or sensor claims.
func LegacyToV3(legacy Snapshot) (PlatformSnapshot, error) {
	if err := legacy.Validate(); err != nil {
		return PlatformSnapshot{}, err
	}
	now, _ := ParseTime(legacy.CollectedAt)
	device := DeviceStatus{
		ID:          "legacy-primary-mac",
		DisplayName: "Managed Mac (legacy observer)",
		Platform:    "macos",
		Version:     1,
		Management:  ManagementStatus{State: "unavailable"},
		Posture:     PostureStatus{State: "unknown", Failed: []string{}},
		Sensors: []SensorStatus{{
			Kind:       "monitoring",
			Coverage:   "partial",
			ObservedAt: legacy.CollectedAt,
			Detail:     "read-only status-v1/v2 adapter",
		}},
		Telemetry: TelemetryStatus{State: "unavailable"},
		Backup:    BackupStatus{State: "unknown"},
		Wipe:      WipeCapabilityState{State: "unverified", Reason: "legacy observer cannot prove MDM wipe capability"},
	}
	if health := legacy.Mac.Health; health != nil {
		device.Telemetry.LastSeenAt = health.Timestamp
		device.Telemetry.MaxAgeSeconds = 150
		stamp, err := ParseTime(health.Timestamp)
		if err == nil && health.State == "online" && now.Sub(stamp) >= -30*time.Second && now.Sub(stamp) <= 150*time.Second {
			device.Telemetry.State = "fresh"
		} else {
			device.Telemetry.State = "stale"
		}
	}
	services := []ServiceStatus{{
		ID:         "legacy-watch",
		Kind:       "watch",
		State:      "degraded",
		ObservedAt: legacy.CollectedAt,
		Detail:     "legacy read-only projection; v3 management claims unavailable",
	}}
	if legacy.Node.WarpServiceActive && legacy.Node.WarpConnected && legacy.Timers.ControlNode.Active && legacy.Timers.Security.Active {
		services[0].State = "healthy"
	}
	result := PlatformSnapshot{
		SchemaVersion: SchemaVersionV3,
		CollectedAt:   legacy.CollectedAt,
		Source:        ProjectionSource{Mode: "legacy-read-only", SchemaVersion: legacy.SchemaVersion},
		Services:      services,
		Devices:       []DeviceStatus{device},
		Incidents:     []IncidentSummary{},
		Budgets: BudgetStatus{
			AWSMonthlyLimitUSD:        50,
			CloudflareMonthlyLimitUSD: 50,
			AWSState:                  "unknown",
			CloudflareState:           "unknown",
		},
	}
	return result, result.Validate()
}

func SortPlatformSnapshot(snapshot *PlatformSnapshot) {
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].ID < snapshot.Services[j].ID })
	sort.Slice(snapshot.Devices, func(i, j int) bool { return snapshot.Devices[i].ID < snapshot.Devices[j].ID })
	sort.Slice(snapshot.Incidents, func(i, j int) bool {
		if snapshot.Incidents[i].OccurredAt == snapshot.Incidents[j].OccurredAt {
			return snapshot.Incidents[i].ID < snapshot.Incidents[j].ID
		}
		return snapshot.Incidents[i].OccurredAt > snapshot.Incidents[j].OccurredAt
	})
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validStableID(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}
