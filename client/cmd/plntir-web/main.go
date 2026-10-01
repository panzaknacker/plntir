package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"plntir/client/internal/webconsole"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "plntir-web:", err)
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
	case "hash-password":
		return hashPassword(arguments)
	case "check-config":
		return checkConfig(arguments)
	case "version", "--version", "-version":
		fmt.Println("plntir-web", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func serve(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/plntir/web-console.json", "web console config")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve accepts no positional arguments")
	}
	config, err := webconsole.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	server, err := webconsole.NewServer(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx)
}

func hashPassword(arguments []string) error {
	flags := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	username := flags.String("username", "operator", "dashboard username")
	iterations := flags.Int("iterations", 0, "PBKDF2 iterations (zero uses the secure default)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("hash-password accepts no positional arguments")
	}
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return errors.New("pipe one password line on stdin; interactive echo is intentionally unsupported")
	}
	reader := bufio.NewReader(io.LimitReader(os.Stdin, 2049))
	password, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
		if len(password) > 0 && password[len(password)-1] == '\r' {
			password = password[:len(password)-1]
		}
	}
	remainder, remainderErr := io.ReadAll(reader)
	if remainderErr != nil {
		webconsole.ClearPassword(password)
		webconsole.ClearPassword(remainder)
		return remainderErr
	}
	hasRemainder := len(remainder) > 0
	webconsole.ClearPassword(remainder)
	if hasRemainder || len(password) > 1024 || strings.ContainsAny(string(password), "\r\n") {
		webconsole.ClearPassword(password)
		return errors.New("password must be one line and at most 1024 bytes")
	}
	hash, err := webconsole.HashPassword(password, *iterations)
	webconsole.ClearPassword(password)
	if err != nil {
		return err
	}
	auth := webconsole.AuthFile{
		SchemaVersion: 1,
		Username:      *username,
		PasswordHash:  hash,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(auth)
}

func checkConfig(arguments []string) error {
	flags := flag.NewFlagSet("check-config", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/plntir/web-console.json", "web console config")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("check-config accepts no positional arguments")
	}
	config, err := webconsole.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if _, err := webconsole.NewServer(config); err != nil {
		return err
	}
	fmt.Printf("PASS config: %s\n", config.Path)
	fmt.Printf("PASS mesh-only listen: %s in %s\n", config.Listen, config.AllowedMeshCIDR)
	fmt.Println("PASS TLS, authentication, monitor and retrieval paths")
	if config.LocalMeshAddressPresent() {
		fmt.Println("PASS configured Mesh address is assigned locally")
	} else {
		fmt.Println("WARN configured Mesh address is not assigned on this host")
	}
	return nil
}

func usage() {
	fmt.Print(`plntir-web - private Plntir Operations web console

Usage:
  plntir-web serve --config PATH
  plntir-web check-config --config PATH
  plntir-web hash-password --username operator < password-line
  plntir-web version
`)
}
