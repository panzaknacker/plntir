package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"plntir/client/internal/collector"
	"plntir/client/internal/config"
	"plntir/client/internal/status"
	"plntir/client/internal/ui"
)

const version = "0.1.0"

type commonFlags struct {
	configPath    string
	hostOverride  string
	interval      time.Duration
	offlineReason string
	colorMode     string
	width         int
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "plntirctl:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 1 {
		switch arguments[0] {
		case "--version", "-version":
			fmt.Println("plntirctl", version)
			return nil
		case "--help", "-h":
			printUsage()
			return nil
		}
	}
	command := "dashboard"
	if len(arguments) > 0 && !strings.HasPrefix(arguments[0], "-") {
		command = arguments[0]
		arguments = arguments[1:]
	}
	switch command {
	case "dashboard":
		return runDashboard(arguments)
	case "status":
		return runStatus(arguments)
	case "doctor":
		return runDoctor(arguments)
	case "version", "--version", "-version":
		fmt.Println("plntirctl", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (use plntirctl help)", command)
	}
}

func runDashboard(arguments []string) error {
	flags := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	common := addCommonFlags(flags)
	once := flags.Bool("once", false, "render one snapshot and exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("dashboard takes no positional arguments")
	}

	cfg, location, client, err := prepare(common)
	if err != nil {
		return err
	}
	refresh := cfg.RefreshInterval()
	if common.interval > 0 {
		refresh = common.interval
	}
	color, err := colorEnabled(common.colorMode)
	if err != nil {
		return err
	}
	isTerminal := stdoutIsTerminal()
	if common.colorMode == "auto" && !isTerminal {
		color = false
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if isTerminal && !*once {
		fmt.Print("\x1b[?25l")
		defer fmt.Print("\x1b[?25h\n")
	}

	var lastGood *status.Snapshot
	for {
		current, collectErr := client.Collect(ctx)
		if collectErr == nil {
			lastGood = &current
		}
		if ctx.Err() != nil {
			return nil
		}
		if isTerminal && !*once {
			fmt.Print("\x1b[2J\x1b[H")
		}
		fmt.Print(ui.Render(lastGood, ui.Options{
			Now:                 time.Now(),
			Location:            location,
			Color:               color,
			Width:               common.width,
			OfflineReason:       common.offlineReason,
			RefreshSeconds:      int(refresh.Round(time.Second) / time.Second),
			LastCollectionError: collectErr,
		}))
		if *once {
			return collectErr
		}

		timer := time.NewTimer(refresh)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func runStatus(arguments []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	common := addCommonFlags(flags)
	jsonOutput := flags.Bool("json", false, "print structured JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("status takes no positional arguments")
	}

	cfg, location, client, err := prepare(common)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ConnectTimeoutSeconds+20)*time.Second)
	defer cancel()
	snapshot, err := client.Collect(ctx)
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(true)
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	}
	color, err := colorEnabled(common.colorMode)
	if err != nil {
		return err
	}
	if common.colorMode == "auto" && !stdoutIsTerminal() {
		color = false
	}
	fmt.Print(ui.Render(&snapshot, ui.Options{
		Now:            time.Now(),
		Location:       location,
		Color:          color,
		Width:          common.width,
		OfflineReason:  common.offlineReason,
		RefreshSeconds: cfg.RefreshSeconds,
	}))
	return nil
}

func runDoctor(arguments []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	common := addCommonFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("doctor takes no positional arguments")
	}
	cfg, _, client, err := prepare(common)
	if err != nil {
		return err
	}
	fmt.Printf("PASS config: %s\n", cfg.Path)
	fmt.Printf("PASS identity permissions: %s\n", cfg.IdentityFile)
	fmt.Printf("PASS pinned known_hosts: %s\n", cfg.KnownHostsFile)
	fmt.Printf("INFO target: %s port %d\n", cfg.Target(), cfg.Port)
	fmt.Printf("INFO collector mode: %s\n", cfg.CollectorMode)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ConnectTimeoutSeconds+20)*time.Second)
	defer cancel()
	snapshot, err := client.Collect(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("PASS SSH read-only collector: %d ms\n", snapshot.Connection.RoundTripMilliseconds)
	fmt.Printf("PASS schema: v%d\n", snapshot.SchemaVersion)
	if snapshot.Node.WarpServiceActive && snapshot.Node.WarpConnected {
		fmt.Printf("PASS Plntir Control Node WARP: connected (%s)\n", snapshot.Node.MeshIP)
	} else {
		fmt.Println("WARN Plntir Control Node WARP: disconnected")
	}
	if snapshot.Timers.ControlNode.Active && snapshot.Timers.Security.Active {
		fmt.Println("PASS monitoring timers: active")
	} else {
		fmt.Println("WARN monitoring timers: degraded")
	}
	return nil
}

func addCommonFlags(flags *flag.FlagSet) *commonFlags {
	common := &commonFlags{}
	flags.StringVar(&common.configPath, "config", "", "path to dashboard JSON config")
	flags.StringVar(&common.hostOverride, "host", "", "override configured SSH host")
	flags.DurationVar(&common.interval, "interval", 0, "dashboard refresh interval (minimum 2s)")
	flags.StringVar(&common.offlineReason, "offline-reason", "", "mark a currently offline Mac as expected")
	flags.StringVar(&common.colorMode, "color", "auto", "color mode: auto, always, or never")
	flags.IntVar(&common.width, "width", 112, "dashboard width; below 96 uses stacked panels")
	return common
}

func prepare(common *commonFlags) (config.Config, *time.Location, *collector.SSH, error) {
	if common.interval != 0 && (common.interval < 2*time.Second || common.interval > time.Hour) {
		return config.Config{}, nil, nil, errors.New("--interval must be between 2s and 1h")
	}
	cfg, err := config.Load(common.configPath)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	if common.hostOverride != "" {
		cfg.Host = common.hostOverride
		if err := cfg.Validate(); err != nil {
			return config.Config{}, nil, nil, err
		}
	}
	location, err := cfg.Location()
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	client, err := collector.NewSSH(collector.Options{
		Target:                cfg.Target(),
		Port:                  cfg.Port,
		IdentityFile:          cfg.IdentityFile,
		KnownHostsFile:        cfg.KnownHostsFile,
		ConnectTimeoutSeconds: cfg.ConnectTimeoutSeconds,
		Mode:                  collector.Mode(cfg.CollectorMode),
	})
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	return cfg, location, client, nil
}

func colorEnabled(mode string) (bool, error) {
	switch mode {
	case "auto":
		return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb", nil
	case "always":
		return true, nil
	case "never":
		return false, nil
	default:
		return false, fmt.Errorf("invalid --color %q; use auto, always, or never", mode)
	}
}

func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func printUsage() {
	fmt.Print(`plntirctl - read-only terminal dashboard for Plntir Secure Agent Control Plane

Secure agent workflows. Privacy-preserving oversight. Resilient endpoint and network control.

Usage:
  plntirctl dashboard [options]     continuously refresh the terminal dashboard
  plntirctl status [--json]         collect and print one snapshot
  plntirctl doctor                  validate local security and live connectivity
  plntirctl version                 print the version

Common options:
  --config PATH                  dashboard config (or PLNTIRCTL_CONFIG)
  --host HOST                    override host, e.g. 100.101.0.5 on mesh
  --offline-reason TEXT          mark offline as expected, e.g. Transport
  --color auto|always|never
  --width COLUMNS
`)
}
