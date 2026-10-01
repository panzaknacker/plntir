package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHArgumentsAreLockedDown(t *testing.T) {
	client, err := NewSSH(Options{
		Target:                "observer@100.101.0.5",
		Port:                  22,
		IdentityFile:          "/safe/operator-key",
		KnownHostsFile:        "/safe/known-hosts",
		ConnectTimeoutSeconds: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(client.Arguments(), " ")
	required := []string{
		"-F /dev/null",
		"BatchMode=yes",
		"PasswordAuthentication=no",
		"KbdInteractiveAuthentication=no",
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=/safe/known-hosts",
		"UpdateHostKeys=no",
		"ForwardAgent=no",
		"ClearAllForwardings=yes",
		"PermitLocalCommand=no",
		"RequestTTY=no",
		"observer@100.101.0.5 status-v2",
	}
	for _, value := range required {
		if !strings.Contains(joined, value) {
			t.Errorf("SSH arguments missing %q: %s", value, joined)
		}
	}
	for _, forbidden := range []string{"accept-new", "ProxyCommand", "StrictHostKeyChecking=no"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("SSH arguments contain forbidden value %q", forbidden)
		}
	}
	if strings.Contains(remoteScript, "--accept-tos") {
		t.Fatal("read-only collector must not accept terms or mutate WARP state")
	}
}

func TestLegacySSHArgumentsUseEmbeddedReadOnlyScript(t *testing.T) {
	client, err := NewSSH(Options{
		Target:                "admin@127.0.0.1",
		Port:                  22,
		IdentityFile:          "/safe/operator-key",
		KnownHostsFile:        "/safe/known-hosts",
		ConnectTimeoutSeconds: 8,
		Mode:                  ModeLegacyScript,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(client.Arguments(), " ")
	if !strings.Contains(joined, "admin@127.0.0.1 bash -s --") {
		t.Fatalf("legacy transport command missing: %s", joined)
	}
}

func TestNewSSHRejectsUnknownCollectorMode(t *testing.T) {
	_, err := NewSSH(Options{
		Target:                "observer@127.0.0.1",
		Port:                  22,
		IdentityFile:          "/safe/operator-key",
		KnownHostsFile:        "/safe/known-hosts",
		ConnectTimeoutSeconds: 8,
		Mode:                  Mode("shell"),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid collector mode") {
		t.Fatalf("expected invalid collector mode, got %v", err)
	}
}

func TestRemoteCollectorContainsNoMutationCommands(t *testing.T) {
	forbidden := []string{
		"systemctl restart",
		"systemctl stop",
		"systemctl disable",
		"/bin/rm ",
		"/bin/mv ",
		"chmod ",
		"chown ",
		"apt-get ",
		"curl ",
		"wget ",
		" tee ",
	}
	for _, value := range forbidden {
		if strings.Contains(remoteScript, value) {
			t.Errorf("remote collector contains mutation command %q", value)
		}
	}
	if strings.Count(remoteScript, "sudo -n ") != 3 {
		t.Fatalf("sudo use must be limited to three exact read-only checks")
	}
	for _, allowed := range []string{
		"sudo -n /usr/sbin/nft list chain inet host_filter input",
		"sudo -n /usr/bin/journalctl -t plntir-endpoint-health -n 12 --no-pager -o json",
	} {
		if !strings.Contains(remoteScript, allowed) {
			t.Errorf("remote collector is missing allowed sudo command %q", allowed)
		}
	}
}

func TestCollectParsesBoundedFixture(t *testing.T) {
	directory := t.TempDir()
	fakeSSH := filepath.Join(directory, "fake-ssh")
	script := `#!/bin/sh
cat >/dev/null
printf '%s' '{"schema_version":2,"collected_at":"2026-08-28T18:00:00Z","connection":{"target":"","round_trip_ms":0},"node":{"hostname":"control_node"},"mac":{"health":{"timestamp":"2026-08-28T18:00:00Z","state":"offline","ssh_rc":255,"snapshot":"offline"}},"timers":{"control_node":{},"security":{}},"storage":{},"retrieval":{},"events":[]}'
`
	if err := os.WriteFile(fakeSSH, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	client, err := NewSSH(Options{
		SSHBinary:             fakeSSH,
		Target:                "observer@127.0.0.1",
		Port:                  22,
		IdentityFile:          "/unused/key",
		KnownHostsFile:        "/unused/known-hosts",
		ConnectTimeoutSeconds: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Node.Hostname != "control_node" || snapshot.Connection.Target != "observer@127.0.0.1" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestCleanErrorRemovesTerminalControls(t *testing.T) {
	got := cleanError("ssh: bad\x1b[2J\nnext\u202e")
	if strings.ContainsAny(got, "\x1b\n\r") || strings.ContainsRune(got, '\u202e') {
		t.Fatalf("unsafe error survived sanitization: %q", got)
	}
}
