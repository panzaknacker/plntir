package archive

import (
	"testing"
	"time"
)

func TestPolicyHardPauseGates(t *testing.T) {
	t.Parallel()
	highLoadSince := testNow.Add(-HighLoadMinimumDuration)
	cases := []struct {
		name   string
		mutate func(*PolicySnapshot)
		reason string
	}{
		{"metered", func(p *PolicySnapshot) { p.Network = NetworkMetered }, "metered_network"},
		{"hotspot", func(p *PolicySnapshot) { p.Network = NetworkHotspot }, "hotspot_network"},
		{"unknown-network", func(p *PolicySnapshot) { p.Network = NetworkUnknown }, "network_cost_unknown"},
		{"battery", func(p *PolicySnapshot) { p.OnACPower = false; p.BatteryPercent = 19 }, "battery_below_20_percent"},
		{"disk", func(p *PolicySnapshot) { p.FreeBytes = MinimumFreeBytes - 1 }, "less_than_15_gib_free"},
		{"thermal", func(p *PolicySnapshot) { p.Thermal = ThermalSerious }, "thermal_pressure"},
		{"unknown-thermal", func(p *PolicySnapshot) { p.Thermal = ThermalUnknown }, "thermal_state_unknown"},
		{"cpu", func(p *PolicySnapshot) { p.CPUPercent = 91; p.HighLoadSince = &highLoadSince }, "cpu_above_90_percent_for_5_minutes"},
		{"network-errors", func(p *PolicySnapshot) { p.ConsecutiveNetworkErrors = 3 }, "repeated_network_failures"},
		{"stale", func(p *PolicySnapshot) { p.ObservedAt = testNow.Add(-3 * time.Minute) }, "stale_policy_probe"},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			probe := readyPolicy()
			test.mutate(&probe)
			decision, err := EvaluatePolicy(probe, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed || decision.Reason != test.reason {
				t.Fatalf("got %+v, want pause %q", decision, test.reason)
			}
		})
	}
}

func TestS3BudgetGatesDoNotStopExistingBackups(t *testing.T) {
	t.Parallel()
	for percent, want := range map[int]BudgetDecision{
		49:  {ContinueExisting: true},
		50:  {Warn: true, ContinueExisting: true},
		80:  {Warn: true, BlockNewDevices: true, ContinueExisting: true},
		100: {Warn: true, BlockNewDevices: true, HardAlarm: true, ContinueExisting: true},
	} {
		got, err := EvaluateS3Budget(percent)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("at %d%% got %+v, want %+v", percent, got, want)
		}
	}
}
