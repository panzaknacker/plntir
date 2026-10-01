package ui

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"plntir/client/internal/status"
)

type Options struct {
	Now                 time.Time
	Location            *time.Location
	Color               bool
	Width               int
	OfflineReason       string
	RefreshSeconds      int
	LastCollectionError error
}

type severity int

const (
	neutral severity = iota
	good
	warning
	critical
	info
)

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const macHealthStaleAfter = 150 * time.Second

func Render(snapshot *status.Snapshot, options Options) string {
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.Location == nil {
		options.Location = time.UTC
	}
	if options.Width <= 0 {
		options.Width = 100
	} else if options.Width < 40 {
		options.Width = 40
	}

	var output strings.Builder
	localNow := options.Now.In(options.Location)
	title := fmt.Sprintf("PLNTIR OPERATIONS CONSOLE  %s  %s", localNow.Format("2006-01-02 15:04:05"), localNow.Format("MST"))
	output.WriteString(style(title, info, options.Color))
	output.WriteByte('\n')

	if snapshot == nil {
		output.WriteString(indicator("Plntir Control Node", false, critical, options.Color))
		output.WriteString("   ")
		output.WriteString(indicator("Mesh", false, neutral, options.Color))
		output.WriteString("   ")
		output.WriteString(indicator("Mac", false, neutral, options.Color))
		output.WriteString("\n\n")
		message := "Noch kein Status empfangen"
		if options.LastCollectionError != nil {
			message = Sanitize(options.LastCollectionError.Error())
		}
		output.WriteString(style("ERROR: "+message, critical, options.Color))
		output.WriteString("\n\nCtrl+C beendet das Dashboard.\n")
		return output.String()
	}

	meshOK := snapshot.Node.WarpServiceActive && snapshot.Node.WarpConnected
	macOnline, macStale := macHealthStatus(snapshot.Mac.Health, options.Now)
	macSeverity := critical
	macLabel := "Mac OFFLINE"
	if macOnline {
		macSeverity = good
		macLabel = "Mac ONLINE"
	} else if macStale {
		macLabel = "Mac STALE"
	} else if options.OfflineReason != "" {
		macSeverity = info
		macLabel = "Mac EXPECTED OFFLINE"
	}
	output.WriteString(indicator("Plntir Control Node ONLINE", true, good, options.Color))
	output.WriteString("   ")
	output.WriteString(indicator("Mesh "+onOff(meshOK), meshOK, choose(meshOK, good, critical), options.Color))
	output.WriteString("   ")
	output.WriteString(indicator(macLabel, macOnline, macSeverity, options.Color))
	output.WriteByte('\n')
	output.WriteString(style(fmt.Sprintf("Target %s  SSH %d ms  Snapshot %s", Sanitize(snapshot.Connection.Target), snapshot.Connection.RoundTripMilliseconds, localTimestamp(snapshot.CollectedAt, options.Location)), neutral, options.Color))
	output.WriteByte('\n')

	if options.LastCollectionError != nil {
		message := truncate(Sanitize(options.LastCollectionError.Error()), options.Width-18)
		output.WriteString(style("REFRESH ERROR: "+message+" (showing last good snapshot)", critical, options.Color))
		output.WriteByte('\n')
	}

	left := nodeLines(snapshot, options)
	right := macLines(snapshot, options)
	output.WriteByte('\n')
	output.WriteString(renderColumns("PLNTIR CONTROL NODE", left, "MANAGED MAC", right, options))

	alerts := alerts(snapshot, options)
	if len(alerts) > 0 {
		output.WriteByte('\n')
		output.WriteString(style(fmt.Sprintf("ATTENTION (%d)", len(alerts)), warning, options.Color))
		output.WriteByte('\n')
		for _, alert := range alerts {
			output.WriteString("  ")
			output.WriteString(style("! "+alert, warning, options.Color))
			output.WriteByte('\n')
		}
	}

	output.WriteByte('\n')
	output.WriteString(style("RECENT STATE CHANGES", info, options.Color))
	output.WriteByte('\n')
	events := snapshot.Events
	shown := 0
	for i := len(events) - 1; i >= 0 && shown < 6; i-- {
		event := events[i]
		output.WriteString("  ")
		output.WriteString(localTimestamp(event.Timestamp, options.Location))
		output.WriteString("  ")
		output.WriteString(truncate(Sanitize(event.Message), options.Width-24))
		output.WriteByte('\n')
		shown++
	}
	if shown == 0 {
		output.WriteString("  No state changes recorded\n")
	}

	output.WriteByte('\n')
	footer := fmt.Sprintf("Auto-refresh %ds | read-only | Ctrl+C quit", options.RefreshSeconds)
	if options.OfflineReason != "" && !macOnline && !macStale {
		footer += " | expected offline: " + Sanitize(options.OfflineReason)
	}
	output.WriteString(style(footer, neutral, options.Color))
	output.WriteByte('\n')
	return output.String()
}

func nodeLines(snapshot *status.Snapshot, options Options) []string {
	node := snapshot.Node
	memoryUsed := int64(0)
	if node.MemoryTotalBytes > node.MemoryAvailableBytes {
		memoryUsed = node.MemoryTotalBytes - node.MemoryAvailableBytes
	}
	memoryPercent := percentage(memoryUsed, node.MemoryTotalBytes)
	warpValue := "disconnected"
	warpSeverity := critical
	if node.WarpServiceActive && node.WarpConnected {
		warpValue = "connected"
		if node.WarpNetwork != "" {
			warpValue += " / " + Sanitize(node.WarpNetwork)
		}
		warpSeverity = good
	}
	healthyTimers := 0
	totalTimers := 2
	if timerHealthy(snapshot.Timers.ControlNode) {
		healthyTimers++
	}
	if timerHealthy(snapshot.Timers.Security) {
		healthyTimers++
	}
	timersOK := healthyTimers == totalTimers
	timerValue := fmt.Sprintf("%d/%d healthy", healthyTimers, totalTimers)
	archiveSummary := exportReadinessSummary(snapshot.AllUsersExport)
	archiveSeverity := exportReadinessSeverity(snapshot.AllUsersExport)
	if snapshot.Timers.ExportReadiness != nil && !snapshot.Timers.ExportReadiness.Enabled {
		switch {
		case snapshot.AllUsersExport != nil && snapshot.AllUsersExport.State == "exporting":
			archiveSummary = "ON-DEMAND / EXPORTING"
			archiveSeverity = info
		case snapshot.AllUsersExport != nil && snapshot.AllUsersExport.State == "complete":
			archiveSummary = "ON-DEMAND / " + exportReadinessSummary(snapshot.AllUsersExport)
			archiveSeverity = good
		case snapshot.AllUsersExport != nil && snapshot.AllUsersExport.State == "failed":
			archiveSummary = "ON-DEMAND / FAILED"
			archiveSeverity = critical
		default:
			archiveSummary = "ON-DEMAND / idle"
			archiveSeverity = neutral
		}
	}
	publicValue := strings.ToUpper(strings.ReplaceAll(node.PublicSSH, "_", " "))
	publicSeverity := good
	if node.PublicSSH == "open_bootstrap" {
		publicSeverity = warning
	}
	if node.PublicSSH == "unknown" {
		publicSeverity = warning
	}
	return []string{
		item("Host", Sanitize(node.Hostname), neutral, options.Color),
		item("Uptime", formatDuration(time.Duration(node.UptimeSeconds)*time.Second), neutral, options.Color),
		item("Load", fmt.Sprintf("%.2f / %.2f / %.2f", node.Load1, node.Load5, node.Load15), neutral, options.Color),
		item("Memory", fmt.Sprintf("%d%% (%s/%s)", memoryPercent, formatBytes(memoryUsed), formatBytes(node.MemoryTotalBytes)), severityForPercent(memoryPercent), options.Color),
		item("Root disk", fmt.Sprintf("%d%% (%s/%s)", node.RootUsedPercent, formatBytes(node.RootUsedBytes), formatBytes(node.RootTotalBytes)), severityForPercent(node.RootUsedPercent), options.Color),
		item("WARP", warpValue, warpSeverity, options.Color),
		item("Mesh IP", emptyDash(Sanitize(node.MeshIP)), neutral, options.Color),
		item("Timers", timerValue, choose(timersOK, good, critical), options.Color),
		item("Fail2ban", enabled(node.Fail2BanActive), choose(node.Fail2BanActive, good, warning), options.Color),
		item("Time sync", enabled(node.NTPSynchronized), choose(node.NTPSynchronized, good, warning), options.Color),
		item("Auto updates", enabled(node.AutoUpdatesEnabled), choose(node.AutoUpdatesEnabled, good, warning), options.Color),
		item("Reboot", yesNo(node.RebootRequired), choose(!node.RebootRequired, good, warning), options.Color),
		item("Public SSH", publicValue, publicSeverity, options.Color),
		item("Monitor data", formatBytes(snapshot.Storage.MonitorBytes), neutral, options.Color),
		item("Retrievals", fmt.Sprintf("%d archives / %s", snapshot.Retrieval.ArchiveCount, formatBytes(snapshot.Retrieval.ArchiveBytes)), neutral, options.Color),
		item("All-user export", archiveSummary, archiveSeverity, options.Color),
	}
}

func macLines(snapshot *status.Snapshot, options Options) []string {
	mac := snapshot.Mac
	online, stale := macHealthStatus(mac.Health, options.Now)
	state := "OFFLINE"
	stateSeverity := critical
	if online {
		state = "ONLINE"
		stateSeverity = good
	} else if stale {
		state = "STALE"
		if mac.Health != nil {
			state += " (reported " + strings.ToUpper(Sanitize(mac.Health.State)) + ")"
		}
	} else if options.OfflineReason != "" {
		state = "EXPECTED OFFLINE (" + Sanitize(options.OfflineReason) + ")"
		stateSeverity = info
	}
	health := mac.DisplayHealth()
	fields := health.SnapshotFields()
	lastKnown := ""
	if !online && health != nil {
		lastKnown = " (last known)"
	}
	check := "-"
	sshRC := "-"
	if mac.Health != nil {
		check = timeAndAge(mac.Health.Timestamp, options.Now, options.Location)
		sshRC = strconv.Itoa(mac.Health.SSHRC)
	}
	lastOnline := timeAndAge(mac.LastOnline, options.Now, options.Location)
	gatekeeper := emptyDash(fields["gatekeeper"])
	gatekeeperSeverity := choose(strings.Contains(strings.ToLower(gatekeeper), "enabled"), good, warning)
	remoteLogin := emptyDash(fields["remote_login"])
	remoteSeverity := choose(remoteLogin == "reachable", good, warning)
	integrityState := fields["integrity_state"]
	integrityValue := "not reported"
	integritySeverity := warning
	integrityIsFresh := integrityFresh(fields, options.Now)
	switch integrityState {
	case "healthy":
		if integrityIsFresh {
			integrityValue = "HEALTHY / " + emptyDash(fields["integrity_mode"])
			integritySeverity = good
		} else {
			integrityValue = "STALE / last " + timeAndAge(fields["integrity_checked_at"], options.Now, options.Location)
			integritySeverity = critical
		}
	case "drift":
		integrityValue = "DRIFT / " + emptyDash(fields["integrity_drift_count"]) + " finding(s)"
		integritySeverity = critical
	case "error":
		integrityValue = "CHECK ERROR"
		integritySeverity = critical
	case "not_installed":
		integrityValue = "not installed"
	}
	security := "missing"
	securitySeverity := warning
	if mac.Security != nil {
		security = timeAndAge(mac.Security.Timestamp, options.Now, options.Location)
		if mac.Security.PostureRC == 0 && mac.Security.TelemetryRC == 0 {
			securitySeverity = good
		} else {
			security += fmt.Sprintf(" (rc %d/%d)", mac.Security.PostureRC, mac.Security.TelemetryRC)
			securitySeverity = critical
		}
	}
	return []string{
		item("State", state, stateSeverity, options.Color),
		item("Last check", check, neutral, options.Color),
		item("SSH rc", sshRC, choose(online, good, warning), options.Color),
		item("Last online", lastOnline, neutral, options.Color),
		item("Console", emptyDash(fields["console"])+lastKnown, neutral, options.Color),
		item("Users", emptyDash(strings.TrimSuffix(fields["users"], ","))+lastKnown, neutral, options.Color),
		item("Uptime", emptyDash(fields["uptime"])+lastKnown, neutral, options.Color),
		item("Root disk", macDisk(fields["disk"])+lastKnown, neutral, options.Color),
		item("Mesh", meshAddress(fields["mesh"])+lastKnown, neutral, options.Color),
		item("Gatekeeper", gatekeeper+lastKnown, gatekeeperSeverity, options.Color),
		item("Remote login", remoteLogin+lastKnown, remoteSeverity, options.Color),
		item("Integrity", integrityValue+lastKnown, integritySeverity, options.Color),
		item("Security", security, securitySeverity, options.Color),
		item("Health job", timerSummary(snapshot.Timers.ControlNode), choose(timerHealthy(snapshot.Timers.ControlNode), good, critical), options.Color),
		item("Security job", timerSummary(snapshot.Timers.Security), choose(timerHealthy(snapshot.Timers.Security), good, critical), options.Color),
	}
}

func alerts(snapshot *status.Snapshot, options Options) []string {
	var result []string
	if !snapshot.Node.WarpServiceActive || !snapshot.Node.WarpConnected {
		result = append(result, "Plntir Control Node WARP mesh is disconnected")
	}
	if !timerHealthy(snapshot.Timers.ControlNode) {
		result = append(result, "Mac health timer is inactive, disabled, or failing")
	}
	if !timerHealthy(snapshot.Timers.Security) {
		result = append(result, "Security collection timer is inactive, disabled, or failing")
	}
	archiveOnDemand := snapshot.Timers.ExportReadiness != nil &&
		!snapshot.Timers.ExportReadiness.Enabled
	if export := snapshot.AllUsersExport; export != nil &&
		(!archiveOnDemand || export.State == "failed") {
		switch export.State {
		case "blocked":
			switch export.Reason {
			case "full_disk_access_required":
				result = append(result, "All-user export needs macOS Full Disk Access (MDM/PPPC)")
			case "insufficient_control_node_storage":
				result = append(result, fmt.Sprintf("All-user export needs %s; Plntir Control Node has %s free", formatBytes(export.RequiredBytes), formatBytes(export.AvailableBytes)))
			default:
				result = append(result, "All-user export is blocked: "+Sanitize(export.Reason))
			}
		case "not_configured":
			result = append(result, "All-user export is not activated")
		case "unreachable":
			result = append(result, "All-user export readiness cannot reach the Mac")
		case "failed":
			result = append(result, "All-user export readiness failed: "+Sanitize(export.Reason))
		}
	}
	if !snapshot.Node.Fail2BanActive {
		result = append(result, "Fail2ban is inactive")
	}
	if !snapshot.Node.NTPSynchronized {
		result = append(result, "Plntir Control Node clock is not synchronized")
	}
	if snapshot.Node.RebootRequired {
		result = append(result, "Plntir Control Node requires a reboot")
	}
	if snapshot.Node.PublicSSH == "open_bootstrap" {
		result = append(result, "Public SSH bootstrap port is still open")
	}
	online, stale := macHealthStatus(snapshot.Mac.Health, options.Now)
	if stale {
		result = append(result, "Mac health data is older than 150 seconds")
	} else if !online && options.OfflineReason == "" {
		result = append(result, "Mac is unexpectedly offline")
	}
	displayHealth := snapshot.Mac.DisplayHealth()
	if displayHealth != nil {
		fields := displayHealth.SnapshotFields()
		switch fields["integrity_state"] {
		case "drift":
			result = append(result, "Mac Plntir integrity drift detected ("+Sanitize(fields["integrity_drift_count"])+" finding(s), alert-only)")
		case "error":
			result = append(result, "Mac Plntir integrity check failed")
		case "not_installed", "":
			result = append(result, "Mac Plntir integrity monitor is not installed or not reporting")
		case "healthy":
			if online && !integrityFresh(fields, options.Now) {
				result = append(result, "Mac Plntir integrity status is older than 10 minutes")
			}
		}
	}
	if online && snapshot.Mac.Security != nil {
		if snapshot.Mac.Security.PostureRC != 0 || snapshot.Mac.Security.TelemetryRC != 0 {
			result = append(result, "Latest Mac security collection failed")
		} else if stamp, err := status.ParseTime(snapshot.Mac.Security.Timestamp); err == nil && options.Now.Sub(stamp) > 15*time.Minute {
			result = append(result, "Mac security telemetry is older than 15 minutes")
		}
	}
	return result
}

func integrityFresh(fields map[string]string, now time.Time) bool {
	stamp, err := status.ParseTime(fields["integrity_checked_at"])
	if err != nil {
		return false
	}
	age := now.Sub(stamp)
	return age >= -time.Minute && age <= 10*time.Minute
}

func exportReadinessSummary(export *status.AllUsersExport) string {
	if export == nil {
		return "not installed"
	}
	switch export.State {
	case "ready":
		return fmt.Sprintf("READY / %s source", formatBytes(export.SourceBytes))
	case "complete":
		return fmt.Sprintf("COMPLETE / %s encrypted", formatBytes(export.ArchiveBytes))
	case "exporting":
		return "EXPORTING"
	case "blocked":
		if export.Reason == "full_disk_access_required" {
			return fmt.Sprintf("BLOCKED / FDA (%d)", export.UnreadableEntries)
		}
		if export.Reason == "insufficient_control_node_storage" {
			if export.PlanCached {
				return "BLOCKED / storage (cached)"
			}
			return "BLOCKED / storage"
		}
		return "BLOCKED / " + Sanitize(export.Reason)
	default:
		return strings.ToUpper(strings.ReplaceAll(Sanitize(export.State), "_", " "))
	}
}

func exportReadinessSeverity(export *status.AllUsersExport) severity {
	if export == nil {
		return warning
	}
	switch export.State {
	case "ready", "complete":
		return good
	case "exporting":
		return info
	case "failed", "unreachable":
		return critical
	default:
		return warning
	}
}

func macHealthStatus(health *status.MacHealth, now time.Time) (online bool, stale bool) {
	if health == nil {
		return false, false
	}
	stamp, err := status.ParseTime(health.Timestamp)
	if err != nil {
		return false, true
	}
	age := now.Sub(stamp)
	if age < -30*time.Second || age > macHealthStaleAfter {
		return false, true
	}
	return health.State == "online", false
}

func renderColumns(leftTitle string, left []string, rightTitle string, right []string, options Options) string {
	if options.Width < 96 {
		var builder strings.Builder
		builder.WriteString(style(leftTitle, info, options.Color))
		builder.WriteByte('\n')
		for _, line := range left {
			builder.WriteString("  " + line + "\n")
		}
		builder.WriteByte('\n')
		builder.WriteString(style(rightTitle, info, options.Color))
		builder.WriteByte('\n')
		for _, line := range right {
			builder.WriteString("  " + line + "\n")
		}
		return builder.String()
	}

	columnWidth := (options.Width - 3) / 2
	var builder strings.Builder
	builder.WriteString(padRight(style(leftTitle, info, options.Color), columnWidth))
	builder.WriteString("   ")
	builder.WriteString(style(rightTitle, info, options.Color))
	builder.WriteByte('\n')
	rows := len(left)
	if len(right) > rows {
		rows = len(right)
	}
	for index := 0; index < rows; index++ {
		leftLine := ""
		rightLine := ""
		if index < len(left) {
			leftLine = left[index]
		}
		if index < len(right) {
			rightLine = right[index]
		}
		builder.WriteString(padRight(truncateANSI(leftLine, columnWidth), columnWidth))
		builder.WriteString("   ")
		builder.WriteString(truncateANSI(rightLine, columnWidth))
		builder.WriteByte('\n')
	}
	return builder.String()
}

func item(label, value string, level severity, color bool) string {
	return fmt.Sprintf("%-13s %s", label, style(truncate(Sanitize(value), 42), level, color))
}

func indicator(label string, active bool, level severity, color bool) string {
	marker := "○"
	if active {
		marker = "●"
	}
	return style(marker+" "+label, level, color)
}

func timerHealthy(timer status.Timer) bool {
	return timer.Active && timer.Enabled && timer.ServiceResult == "success" && timer.ExecMainStatus == 0
}

func timerSummary(timer status.Timer) string {
	state := "inactive"
	if timer.Active && timer.Enabled {
		state = "healthy"
	}
	if timer.ServiceResult != "" && timer.ServiceResult != "success" {
		state = timer.ServiceResult
	}
	if timer.ExecMainStatus != 0 {
		state += fmt.Sprintf(" rc=%d", timer.ExecMainStatus)
	}
	return state
}

func localTimestamp(value string, location *time.Location) string {
	parsed, err := status.ParseTime(value)
	if err != nil {
		return emptyDash(Sanitize(value))
	}
	return parsed.In(location).Format("2006-01-02 15:04:05 MST")
}

func timeAndAge(value string, now time.Time, location *time.Location) string {
	if value == "" {
		return "-"
	}
	parsed, err := status.ParseTime(value)
	if err != nil {
		return Sanitize(value)
	}
	age := now.Sub(parsed)
	if age < 0 {
		age = 0
	}
	return fmt.Sprintf("%s (%s ago)", parsed.In(location).Format("15:04:05 MST"), formatDuration(age))
}

func macDisk(value string) string {
	parts := strings.Fields(value)
	if len(parts) < 5 {
		return emptyDash(value)
	}
	totalKB, totalErr := strconv.ParseInt(parts[1], 10, 64)
	usedKB, usedErr := strconv.ParseInt(parts[2], 10, 64)
	if totalErr != nil || usedErr != nil {
		return parts[4]
	}
	return fmt.Sprintf("%s (%s/%s)", parts[4], formatBytes(usedKB*1024), formatBytes(totalKB*1024))
}

func meshAddress(value string) string {
	parts := strings.Fields(value)
	for index, part := range parts {
		if part == "inet" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return emptyDash(value)
}

func formatDuration(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	seconds := int64(duration.Round(time.Second) / time.Second)
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds%60)
	}
	return fmt.Sprintf("%ds", seconds)
}

func formatBytes(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	divisor := int64(unit)
	exponent := 0
	for value := bytes / unit; value >= unit && exponent < 4; value /= unit {
		divisor *= unit
		exponent++
	}
	units := "KMGTPE"
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(divisor), units[exponent])
}

func percentage(used, total int64) int {
	if total <= 0 {
		return 0
	}
	return int(math.Round(float64(used) * 100 / float64(total)))
}

func severityForPercent(value int) severity {
	if value >= 90 {
		return critical
	}
	if value >= 80 {
		return warning
	}
	return good
}

func style(value string, level severity, enabled bool) string {
	if !enabled {
		return value
	}
	code := ""
	switch level {
	case good:
		code = ansiGreen
	case warning:
		code = ansiYellow
	case critical:
		code = ansiRed
	case info:
		code = ansiCyan
	default:
		code = ansiDim
	}
	return code + value + ansiReset
}

func choose(condition bool, yes, no severity) severity {
	if condition {
		return yes
	}
	return no
}

func onOff(value bool) string {
	if value {
		return "OK"
	}
	return "DOWN"
}

func enabled(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

func yesNo(value bool) string {
	if value {
		return "required"
	}
	return "not required"
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func padRight(value string, width int) string {
	missing := width - visibleWidth(value)
	if missing <= 0 {
		return value
	}
	return value + strings.Repeat(" ", missing)
}

func visibleWidth(value string) int {
	return utf8.RuneCountInString(ansiPattern.ReplaceAllString(value, ""))
}

func truncateANSI(value string, width int) string {
	if visibleWidth(value) <= width {
		return value
	}
	plain := ansiPattern.ReplaceAllString(value, "")
	return truncate(plain, width)
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

// Sanitize removes terminal control characters, bidi controls, and line breaks
// from all remote text before it reaches an interactive terminal.
func Sanitize(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' {
			builder.WriteByte(' ')
			continue
		}
		if unicode.Is(unicode.C, r) {
			continue
		}
		builder.WriteRune(r)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

// StableAlerts is useful for JSON consumers and tests that need deterministic
// ordering without duplicating alert policy.
func StableAlerts(snapshot *status.Snapshot, options Options) []string {
	result := alerts(snapshot, options)
	sort.Strings(result)
	return result
}
