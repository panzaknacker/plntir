package shadow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const maxStatusBytes = 1 << 20

type Source struct {
	path string
}

type Projection struct {
	SchemaVersion int              `json:"schema_version"`
	CollectedAt   string           `json:"collected_at"`
	Source        ProjectionSource `json:"source"`
	Services      []Service        `json:"services"`
	Devices       []Device         `json:"devices"`
	Incidents     []Incident       `json:"incidents"`
	Budgets       Budgets          `json:"budgets"`
}

type ProjectionSource struct {
	Mode          string `json:"mode"`
	SchemaVersion int    `json:"schema_version"`
}

type Service struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	ObservedAt string `json:"observed_at"`
	Detail     string `json:"detail,omitempty"`
}

type Device struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Platform    string    `json:"platform"`
	Version     int64     `json:"version"`
	Management  State     `json:"management"`
	Posture     State     `json:"posture"`
	Sensors     []Sensor  `json:"sensors"`
	Telemetry   Telemetry `json:"telemetry"`
	Backup      Backup    `json:"backup"`
	Incidents   []string  `json:"incident_refs"`
	Wipe        Wipe      `json:"wipe"`
}

type State struct {
	State string `json:"state"`
}

type Sensor struct {
	Kind       string `json:"kind"`
	Coverage   string `json:"coverage"`
	ObservedAt string `json:"observed_at,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type Telemetry struct {
	State         string `json:"state"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
	MaxAgeSeconds int64  `json:"max_age_seconds,omitempty"`
}

type Backup struct {
	State string `json:"state"`
}

type Wipe struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type Incident struct{}

type Budgets struct {
	AWSMonthlyLimitUSD        int    `json:"aws_monthly_limit_usd"`
	CloudflareMonthlyLimitUSD int    `json:"cloudflare_monthly_limit_usd"`
	AWSState                  string `json:"aws_state"`
	CloudflareState           string `json:"cloudflare_state"`
}

type legacySnapshot struct {
	SchemaVersion int          `json:"schema_version"`
	CollectedAt   string       `json:"collected_at"`
	Node          legacyNode   `json:"node"`
	Mac           legacyMac    `json:"mac"`
	Timers        legacyTimers `json:"timers"`
}

type legacyNode struct {
	Hostname          string `json:"hostname"`
	WarpServiceActive bool   `json:"warp_service_active"`
	WarpConnected     bool   `json:"warp_connected"`
}

type legacyMac struct {
	Health *legacyHealth `json:"health"`
}

type legacyHealth struct {
	Timestamp string `json:"timestamp"`
	State     string `json:"state"`
}

type legacyTimers struct {
	ControlNode *legacyTimer `json:"control_node"`
	Watchdog    *legacyTimer `json:"watchdog"`
	Security    legacyTimer  `json:"security"`
}

type legacyTimer struct {
	Active bool `json:"active"`
}

func New(path string) *Source {
	return &Source{path: path}
}

func (s *Source) Snapshot(_ context.Context) (Projection, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return Projection{}, fmt.Errorf("stat legacy status: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return Projection{}, errors.New("legacy status must be a regular non-symlink file without group/world write permissions")
	}
	if info.Size() <= 0 || info.Size() > maxStatusBytes {
		return Projection{}, errors.New("legacy status has an invalid size")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return Projection{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxStatusBytes+1))
	// the legacy v1/v2 status document contains fields that are intentionally
	// outside this read-only adapter. Decode only the small, explicitly used
	// projection instead of coupling shadow mode to every legacy field.
	var legacy legacySnapshot
	if err := decoder.Decode(&legacy); err != nil {
		return Projection{}, fmt.Errorf("decode legacy status: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Projection{}, errors.New("legacy status contains trailing JSON data")
	}
	return convert(legacy)
}

func convert(legacy legacySnapshot) (Projection, error) {
	if legacy.SchemaVersion != 1 && legacy.SchemaVersion != 2 {
		return Projection{}, fmt.Errorf("unsupported legacy schema %d", legacy.SchemaVersion)
	}
	collected, err := time.Parse(time.RFC3339Nano, legacy.CollectedAt)
	if err != nil || legacy.Node.Hostname == "" {
		return Projection{}, errors.New("legacy status lacks a valid timestamp or hostname")
	}
	if legacy.Timers.ControlNode != nil && legacy.Timers.Watchdog != nil {
		return Projection{}, errors.New("legacy status includes both current and legacy timer names")
	}
	controlTimer := legacy.Timers.ControlNode
	if controlTimer == nil {
		controlTimer = legacy.Timers.Watchdog
	}
	serviceState := "degraded"
	if legacy.Node.WarpServiceActive && legacy.Node.WarpConnected && controlTimer != nil && controlTimer.Active && legacy.Timers.Security.Active {
		serviceState = "healthy"
	}
	telemetry := Telemetry{State: "unavailable"}
	if legacy.Mac.Health != nil {
		if legacy.Mac.Health.State != "online" && legacy.Mac.Health.State != "offline" {
			return Projection{}, fmt.Errorf("invalid legacy Mac state %q", legacy.Mac.Health.State)
		}
		telemetry.LastSeenAt = legacy.Mac.Health.Timestamp
		telemetry.MaxAgeSeconds = 150
		observed, parseErr := time.Parse(time.RFC3339Nano, legacy.Mac.Health.Timestamp)
		if parseErr == nil && legacy.Mac.Health.State == "online" {
			age := collected.Sub(observed)
			if age >= -30*time.Second && age <= 150*time.Second {
				telemetry.State = "fresh"
			} else {
				telemetry.State = "stale"
			}
		} else {
			telemetry.State = "stale"
		}
	}
	return Projection{
		SchemaVersion: 3,
		CollectedAt:   legacy.CollectedAt,
		Source:        ProjectionSource{Mode: "legacy-read-only", SchemaVersion: legacy.SchemaVersion},
		Services: []Service{{
			ID:         "legacy-watch",
			Kind:       "watch",
			State:      serviceState,
			ObservedAt: legacy.CollectedAt,
			Detail:     "legacy status-v1/v2 read-only adapter",
		}},
		Devices: []Device{{
			ID:          "legacy-primary-mac",
			DisplayName: "Managed Mac (legacy observer)",
			Platform:    "macos",
			Version:     1,
			Management:  State{State: "unavailable"},
			Posture:     State{State: "unknown"},
			Sensors: []Sensor{{
				Kind: "monitoring", Coverage: "partial", ObservedAt: legacy.CollectedAt,
				Detail: "legacy observer does not prove MDM or complete sensor coverage",
			}},
			Telemetry: telemetry,
			Backup:    Backup{State: "unknown"},
			Incidents: []string{},
			Wipe:      Wipe{State: "unverified", Reason: "legacy observer cannot prove MDM wipe capability"},
		}},
		Incidents: []Incident{},
		Budgets: Budgets{
			AWSMonthlyLimitUSD: 50, CloudflareMonthlyLimitUSD: 50,
			AWSState: "unknown", CloudflareState: "unknown",
		},
	}, nil
}

func Sanitize(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, value)
}
