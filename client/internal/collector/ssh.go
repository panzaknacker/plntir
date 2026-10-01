package collector

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"

	"plntir/client/internal/status"
)

const (
	maxStdoutBytes  = 1 << 20
	maxStderrBytes  = 32 << 10
	observerCommand = "status-v2"
)

type Mode string

const (
	ModeLegacyScript    Mode = "legacy-script"
	ModeObserverCommand Mode = "observer-command"
)

type Options struct {
	SSHBinary             string
	Target                string
	Port                  int
	IdentityFile          string
	KnownHostsFile        string
	ConnectTimeoutSeconds int
	Mode                  Mode
}

type SSH struct {
	options Options
}

func NewSSH(options Options) (*SSH, error) {
	if options.SSHBinary == "" {
		options.SSHBinary = "ssh"
	}
	if options.Target == "" || strings.HasPrefix(options.Target, "-") || strings.ContainsAny(options.Target, " \t\r\n") {
		return nil, fmt.Errorf("invalid SSH target")
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, fmt.Errorf("invalid SSH port")
	}
	if options.ConnectTimeoutSeconds < 1 || options.ConnectTimeoutSeconds > 120 {
		return nil, fmt.Errorf("invalid SSH connect timeout")
	}
	if options.IdentityFile == "" || options.KnownHostsFile == "" {
		return nil, fmt.Errorf("identity and known_hosts paths are required")
	}
	if options.Mode == "" {
		options.Mode = ModeObserverCommand
	}
	if options.Mode != ModeLegacyScript && options.Mode != ModeObserverCommand {
		return nil, fmt.Errorf("invalid collector mode %q", options.Mode)
	}
	return &SSH{options: options}, nil
}

func (s *SSH) Collect(parent context.Context) (status.Snapshot, error) {
	timeout := time.Duration(s.options.ConnectTimeoutSeconds+15) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	stdout := &cappedBuffer{max: maxStdoutBytes}
	stderr := &cappedBuffer{max: maxStderrBytes}
	cmd := exec.CommandContext(ctx, s.options.SSHBinary, s.Arguments()...)
	if s.options.Mode == ModeLegacyScript {
		cmd.Stdin = strings.NewReader(remoteScript)
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	started := time.Now()
	err := cmd.Run()
	elapsed := time.Since(started)
	if ctx.Err() != nil {
		return status.Snapshot{}, fmt.Errorf("SSH status collection timed out after %s", timeout)
	}
	if err != nil {
		message := cleanError(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return status.Snapshot{}, fmt.Errorf("SSH status collection failed: %s", message)
	}
	if stdout.truncated {
		return status.Snapshot{}, errors.New("SSH status response exceeded 1 MiB")
	}

	var snapshot status.Snapshot
	if err := json.Unmarshal(stdout.Bytes(), &snapshot); err != nil {
		return status.Snapshot{}, fmt.Errorf("decode SSH status response: %w", err)
	}
	snapshot.Connection.Target = s.options.Target
	snapshot.Connection.RoundTripMilliseconds = elapsed.Milliseconds()
	if err := snapshot.Validate(); err != nil {
		return status.Snapshot{}, fmt.Errorf("validate SSH status response: %w", err)
	}
	return snapshot, nil
}

func (s *SSH) Arguments() []string {
	arguments := []string{
		"-F", "/dev/null",
		"-p", strconv.Itoa(s.options.Port),
		"-i", s.options.IdentityFile,
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + s.options.KnownHostsFile,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "VerifyHostKeyDNS=no",
		"-o", "AddKeysToAgent=no",
		"-o", "ForwardAgent=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "RequestTTY=no",
		"-o", "EscapeChar=none",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ConnectionAttempts=1",
		"-o", "ConnectTimeout=" + strconv.Itoa(s.options.ConnectTimeoutSeconds),
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=2",
		"-o", "LogLevel=ERROR",
		s.options.Target,
	}
	if s.options.Mode == ModeLegacyScript {
		return append(arguments, "bash", "-s", "--")
	}
	return append(arguments, observerCommand)
}

type cappedBuffer struct {
	bytes.Buffer
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.max - b.Len()
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p)
	return original, nil
}

func cleanError(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if unicode.Is(unicode.C, r) {
			if r == '\n' || r == '\r' || r == '\t' {
				builder.WriteByte(' ')
			}
			continue
		}
		builder.WriteRune(r)
		if builder.Len() >= 500 {
			break
		}
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

//go:embed plntir-status-v2.sh
var remoteScript string
