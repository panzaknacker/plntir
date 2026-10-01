package status

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Snapshot struct {
	SchemaVersion  int             `json:"schema_version"`
	CollectedAt    string          `json:"collected_at"`
	Connection     Connection      `json:"connection"`
	Node           Node            `json:"node"`
	Mac            Mac             `json:"mac"`
	Timers         Timers          `json:"timers"`
	Storage        Storage         `json:"storage"`
	Retrieval      Retrieval       `json:"retrieval"`
	AllUsersExport *AllUsersExport `json:"all_users_export"`
	Events         []Event         `json:"events"`
}

type Connection struct {
	Target                string `json:"target"`
	RoundTripMilliseconds int64  `json:"round_trip_ms"`
}

type Node struct {
	Hostname             string  `json:"hostname"`
	UptimeSeconds        int64   `json:"uptime_seconds"`
	Load1                float64 `json:"load_1"`
	Load5                float64 `json:"load_5"`
	Load15               float64 `json:"load_15"`
	MemoryTotalBytes     int64   `json:"memory_total_bytes"`
	MemoryAvailableBytes int64   `json:"memory_available_bytes"`
	RootTotalBytes       int64   `json:"root_total_bytes"`
	RootUsedBytes        int64   `json:"root_used_bytes"`
	RootUsedPercent      int     `json:"root_used_percent"`
	WarpServiceActive    bool    `json:"warp_service_active"`
	WarpConnected        bool    `json:"warp_connected"`
	WarpNetwork          string  `json:"warp_network"`
	MeshIP               string  `json:"mesh_ip"`
	Fail2BanActive       bool    `json:"fail2ban_active"`
	NTPSynchronized      bool    `json:"ntp_synchronized"`
	AutoUpdatesEnabled   bool    `json:"auto_updates_enabled"`
	RebootRequired       bool    `json:"reboot_required"`
	PublicSSH            string  `json:"public_ssh"`
}

type Mac struct {
	Health           *MacHealth `json:"health"`
	LastOnline       string     `json:"last_online"`
	LastOffline      string     `json:"last_offline"`
	LastOnlineHealth *MacHealth `json:"last_online_health"`
	Security         *Security  `json:"security"`
}

type MacHealth struct {
	Timestamp string `json:"timestamp"`
	State     string `json:"state"`
	SSHRC     int    `json:"ssh_rc"`
	Snapshot  string `json:"snapshot"`
}

type Security struct {
	Timestamp   string `json:"timestamp"`
	PostureRC   int    `json:"posture_rc"`
	TelemetryRC int    `json:"telemetry_rc"`
}

type Timers struct {
	ControlNode     Timer  `json:"control_node"`
	Security        Timer  `json:"security"`
	ExportReadiness *Timer `json:"export_readiness"`
}

// UnmarshalJSON accepts the version 1 timer name during the controlled
// migration. all newly marshalled status uses the version 2 control_node key.
func (t *Timers) UnmarshalJSON(data []byte) error {
	type wireTimers struct {
		ControlNode       *Timer `json:"control_node"`
		LegacyControlNode *Timer `json:"watchdog"`
		Security          Timer  `json:"security"`
		ExportReadiness   *Timer `json:"export_readiness"`
	}

	var wire wireTimers
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.ControlNode != nil && wire.LegacyControlNode != nil {
		return fmt.Errorf("timers contains both current and legacy control-node fields")
	}

	*t = Timers{
		Security:        wire.Security,
		ExportReadiness: wire.ExportReadiness,
	}
	if wire.ControlNode != nil {
		t.ControlNode = *wire.ControlNode
	} else if wire.LegacyControlNode != nil {
		t.ControlNode = *wire.LegacyControlNode
	}
	return nil
}

type AllUsersExport struct {
	State              string `json:"state"`
	Reason             string `json:"reason"`
	CheckedAt          string `json:"checked_at"`
	SourceCheckedAt    string `json:"source_checked_at"`
	PlanCached         bool   `json:"plan_cached"`
	LocalUserCount     int    `json:"local_user_count"`
	HomeDirectoryCount int    `json:"home_directory_count"`
	SourceBytes        int64  `json:"source_bytes"`
	RequiredBytes      int64  `json:"required_bytes"`
	AvailableBytes     int64  `json:"available_bytes"`
	ReserveBytes       int64  `json:"reserve_bytes"`
	UnreadableEntries  int    `json:"unreadable_entries"`
	Archive            string `json:"archive"`
	ArchiveBytes       int64  `json:"archive_bytes"`
	SHA256             string `json:"sha256"`
	CompletedAt        string `json:"completed_at"`
}

type Timer struct {
	Active         bool   `json:"active"`
	Enabled        bool   `json:"enabled"`
	LastTrigger    string `json:"last_trigger"`
	NextTrigger    string `json:"next_trigger"`
	ServiceResult  string `json:"service_result"`
	ExecMainStatus int    `json:"exec_main_status"`
}

type Storage struct {
	MonitorBytes   int64 `json:"monitor_bytes"`
	RetrievedBytes int64 `json:"retrieved_bytes"`
}

type Retrieval struct {
	ArchiveCount       int     `json:"archive_count"`
	ArchiveBytes       int64   `json:"archive_bytes"`
	LatestEpoch        float64 `json:"latest_epoch"`
	LatestArchiveBytes int64   `json:"latest_archive_bytes"`
}

type Event struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

func (s Snapshot) Validate() error {
	if s.SchemaVersion != 1 && s.SchemaVersion != 2 {
		return fmt.Errorf("unsupported status schema %d", s.SchemaVersion)
	}
	if _, err := ParseTime(s.CollectedAt); err != nil {
		return fmt.Errorf("invalid collected_at: %w", err)
	}
	if s.Node.Hostname == "" {
		return fmt.Errorf("status is missing node hostname")
	}
	if s.Mac.Health != nil {
		switch s.Mac.Health.State {
		case "online", "offline":
		default:
			return fmt.Errorf("invalid Mac state %q", s.Mac.Health.State)
		}
	}
	if s.AllUsersExport != nil {
		switch s.AllUsersExport.State {
		case "not_configured", "ready", "blocked", "unreachable", "exporting", "complete", "failed":
		default:
			return fmt.Errorf("invalid all-user export state %q", s.AllUsersExport.State)
		}
	}
	return nil
}

// SnapshotFields parses the collector's deliberately small key=value payload.
// the values are display-only and are never evaluated as shell input.
func (h *MacHealth) SnapshotFields() map[string]string {
	fields := make(map[string]string)
	if h == nil {
		return fields
	}
	for _, line := range strings.Split(h.Snapshot, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		fields[key] = strings.TrimSpace(value)
	}
	return fields
}

func (m Mac) DisplayHealth() *MacHealth {
	if m.Health != nil && m.Health.State == "online" {
		return m.Health
	}
	if m.LastOnlineHealth != nil {
		return m.LastOnlineHealth
	}
	return m.Health
}

func ParseTime(value string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		"20060102T150405Z",
		"Mon 2006-01-02 15:04:05 MST",
	}
	var last error
	for _, format := range formats {
		parsed, err := time.Parse(format, value)
		if err == nil {
			return parsed, nil
		}
		last = err
	}
	return time.Time{}, last
}
