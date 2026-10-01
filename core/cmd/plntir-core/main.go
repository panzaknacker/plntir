package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"plntir/core/internal/access"
	"plntir/core/internal/config"
	"plntir/core/internal/httpapi"
	"plntir/core/internal/shadow"
	sqlitestore "plntir/core/internal/store/sqlite"
)

const version = "1.0.0-shadow"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "plntir-core:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	command := "serve"
	if len(arguments) > 0 && !strings.HasPrefix(arguments[0], "-") {
		command = arguments[0]
		arguments = arguments[1:]
	}
	switch command {
	case "serve":
		return serve(arguments)
	case "check-config":
		return checkConfig(arguments)
	case "version", "--version", "-version":
		fmt.Println("plntir-core", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func load(arguments []string) (config.Config, error) {
	flags := flag.NewFlagSet("plntir-core", flag.ContinueOnError)
	path := flags.String("config", "/etc/plntir/core.json", "Core configuration")
	if err := flags.Parse(arguments); err != nil {
		return config.Config{}, err
	}
	if flags.NArg() != 0 {
		return config.Config{}, errors.New("unexpected positional arguments")
	}
	return config.Load(*path)
}

func checkConfig(arguments []string) error {
	cfg, err := load(arguments)
	if err != nil {
		return err
	}
	fmt.Printf("PASS config: %s\n", cfg.Path)
	fmt.Printf("PASS fail-closed mode: %s\n", cfg.Mode)
	fmt.Printf("PASS loopback listen: %s\n", cfg.Listen)
	fmt.Println("PASS Cloudflare Access issuer and audience configured")
	return nil
}

func serve(arguments []string) error {
	cfg, err := load(arguments)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := sqlitestore.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	verifier, err := access.NewCloudflareVerifier(ctx, cfg.CloudflareAccessIssuer, cfg.CloudflareAccessAudience)
	if err != nil {
		return err
	}
	api, err := httpapi.New(httpapi.Options{
		AllowedHosts: cfg.AllowedHosts,
		Mode:         cfg.Mode,
		Access:       verifier,
		Projection:   shadow.New(cfg.LegacyStatusPath),
		Store:        store,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
