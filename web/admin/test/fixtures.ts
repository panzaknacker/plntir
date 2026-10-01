export const healthFixture = {
  schema_version: 3,
  collected_at: "2026-09-04T12:00:00Z",
  source: { mode: "legacy-read-only", schema_version: 2 },
  services: [{ id: "legacy-watch", kind: "watch", state: "healthy", observed_at: "2026-09-04T12:00:00Z", detail: "read only" }],
  devices: [{
    id: "legacy-primary-mac", display_name: "Managed Mac", platform: "macos", version: 1,
    management: { state: "unavailable" }, posture: { state: "unknown" },
    sensors: [{ kind: "monitoring", coverage: "partial" }],
    telemetry: { state: "fresh", last_seen_at: "2026-09-04T11:59:30Z", max_age_seconds: 150 },
    backup: { state: "unknown" }, incident_refs: [], wipe: { state: "unverified", reason: "not proven" },
  }],
  incidents: [],
  budgets: { aws_monthly_limit_usd: 50, cloudflare_monthly_limit_usd: 50, aws_state: "unknown", cloudflare_state: "unknown" },
};
