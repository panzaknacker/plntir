package config

import "testing"

func TestConfigRejectsActiveOrNonLoopbackServer(t *testing.T) {
	valid := Config{
		SchemaVersion:            1,
		Mode:                     "shadow",
		Listen:                   "127.0.0.1:8080",
		AllowedHosts:             []string{"admin.plntir.example"},
		DatabasePath:             "/var/lib/plntir/core.db",
		LegacyStatusPath:         "/var/lib/plntir/shadow/status.json",
		CloudflareAccessIssuer:   "https://plntir.cloudflareaccess.com",
		CloudflareAccessAudience: "aud",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Mode = "active"
	if err := invalid.Validate(); err == nil {
		t.Fatal("active mode unexpectedly accepted before seal")
	}
	invalid = valid
	invalid.Listen = "0.0.0.0:8080"
	if err := invalid.Validate(); err == nil {
		t.Fatal("non-loopback shadow listener unexpectedly accepted")
	}
}
