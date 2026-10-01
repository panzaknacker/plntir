package archive

import (
	"errors"
	"fmt"
	"time"
)

const (
	MinimumFreeBytes         = int64(15 << 30)
	HighLoadPercent          = 90
	HighLoadMinimumDuration  = 5 * time.Minute
	NetworkFailurePauseCount = 3
)

type NetworkClass string

const (
	NetworkUnmetered NetworkClass = "unmetered"
	NetworkMetered   NetworkClass = "metered"
	NetworkHotspot   NetworkClass = "hotspot"
	NetworkUnknown   NetworkClass = "unknown"
)

type ThermalState string

const (
	ThermalNominal  ThermalState = "nominal"
	ThermalFair     ThermalState = "fair"
	ThermalSerious  ThermalState = "serious"
	ThermalCritical ThermalState = "critical"
	ThermalUnknown  ThermalState = "unknown"
)

type PolicySnapshot struct {
	ObservedAt               time.Time    `json:"observed_at"`
	OnACPower                bool         `json:"on_ac_power"`
	BatteryPercent           int          `json:"battery_percent"`
	CPUPercent               int          `json:"cpu_percent"`
	HighLoadSince            *time.Time   `json:"high_load_since,omitempty"`
	Thermal                  ThermalState `json:"thermal"`
	FreeBytes                int64        `json:"free_bytes"`
	Network                  NetworkClass `json:"network"`
	ConsecutiveNetworkErrors int          `json:"consecutive_network_errors"`
}

type PolicyDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func EvaluatePolicy(snapshot PolicySnapshot, now time.Time) (PolicyDecision, error) {
	if now.IsZero() || snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.After(now.Add(30*time.Second)) {
		return PolicyDecision{}, errors.New("policy timestamps are invalid")
	}
	if now.Sub(snapshot.ObservedAt) > 2*time.Minute {
		return PolicyDecision{Reason: "stale_policy_probe"}, nil
	}
	if snapshot.BatteryPercent < 0 || snapshot.BatteryPercent > 100 || snapshot.CPUPercent < 0 || snapshot.CPUPercent > 1000 || snapshot.FreeBytes < 0 || snapshot.ConsecutiveNetworkErrors < 0 {
		return PolicyDecision{}, errors.New("policy measurement is out of range")
	}
	switch snapshot.Network {
	case NetworkMetered:
		return PolicyDecision{Reason: "metered_network"}, nil
	case NetworkHotspot:
		return PolicyDecision{Reason: "hotspot_network"}, nil
	case NetworkUnknown:
		return PolicyDecision{Reason: "network_cost_unknown"}, nil
	case NetworkUnmetered:
	default:
		return PolicyDecision{}, fmt.Errorf("unsupported network class %q", snapshot.Network)
	}
	if !snapshot.OnACPower && snapshot.BatteryPercent < 20 {
		return PolicyDecision{Reason: "battery_below_20_percent"}, nil
	}
	if snapshot.FreeBytes < MinimumFreeBytes {
		return PolicyDecision{Reason: "less_than_15_gib_free"}, nil
	}
	switch snapshot.Thermal {
	case ThermalSerious, ThermalCritical:
		return PolicyDecision{Reason: "thermal_pressure"}, nil
	case ThermalUnknown:
		return PolicyDecision{Reason: "thermal_state_unknown"}, nil
	case ThermalNominal, ThermalFair:
	default:
		return PolicyDecision{}, fmt.Errorf("unsupported thermal state %q", snapshot.Thermal)
	}
	if snapshot.CPUPercent > HighLoadPercent && snapshot.HighLoadSince != nil && now.Sub(*snapshot.HighLoadSince) >= HighLoadMinimumDuration {
		return PolicyDecision{Reason: "cpu_above_90_percent_for_5_minutes"}, nil
	}
	if snapshot.ConsecutiveNetworkErrors >= NetworkFailurePauseCount {
		return PolicyDecision{Reason: "repeated_network_failures"}, nil
	}
	return PolicyDecision{Allowed: true, Reason: "ready"}, nil
}

type BudgetDecision struct {
	Warn             bool `json:"warn"`
	BlockNewDevices  bool `json:"block_new_devices"`
	HardAlarm        bool `json:"hard_alarm"`
	ContinueExisting bool `json:"continue_existing_backups"`
}

func EvaluateS3Budget(percentUsed int) (BudgetDecision, error) {
	if percentUsed < 0 {
		return BudgetDecision{}, errors.New("budget percentage cannot be negative")
	}
	return BudgetDecision{
		Warn:             percentUsed >= 50,
		BlockNewDevices:  percentUsed >= 80,
		HardAlarm:        percentUsed >= 100,
		ContinueExisting: true,
	}, nil
}
