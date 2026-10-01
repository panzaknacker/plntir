import { asRecord, requiredArray, requiredInteger, requiredString } from "../../shared/http";

export type HealthState = "healthy" | "degraded" | "unavailable" | "unknown";
export type ManagementState = "verified" | "partial" | "unavailable";
export type PostureState = "passing" | "degraded" | "failing" | "unknown";
export type TelemetryState = "fresh" | "stale" | "unavailable";
export type BackupState = "verified" | "running" | "paused" | "failed" | "unavailable" | "unknown";
export type WipeState = "verified" | "unverified" | "unavailable";
export type BudgetState = "unknown" | "ok" | "warning" | "blocked";
export type IncidentSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface Service {
  id: string;
  kind: string;
  state: HealthState;
  observedAt: string | null;
  detail: string | null;
}

export interface Device {
  id: string;
  displayName: string;
  platform: "macos" | "ios" | "linux";
  management: ManagementState;
  posture: PostureState;
  telemetry: TelemetryState;
  lastSeenAt: string | null;
  backup: BackupState;
  wipe: WipeState;
  sensorSummary: string;
  incidentRefs: string[];
}

export interface Incident {
  id: string;
  deviceId: string | null;
  severity: IncidentSeverity;
  state: "open" | "acknowledged" | "resolved";
  kind: string;
  occurredAt: string;
  summary: string;
}

export interface HealthProjection {
  collectedAt: string;
  source: { mode: "native" | "legacy-read-only"; schemaVersion: number };
  services: Service[];
  devices: Device[];
  incidents: Incident[];
  budgets: {
    awsMonthlyLimitUSD: number;
    cloudflareMonthlyLimitUSD: number;
    awsState: BudgetState;
    cloudflareState: BudgetState;
  };
}

const SERVICE_STATES = ["healthy", "degraded", "unavailable", "unknown"] as const;
const MANAGEMENT_STATES = ["verified", "partial", "unavailable"] as const;
const POSTURE_STATES = ["passing", "degraded", "failing", "unknown"] as const;
const TELEMETRY_STATES = ["fresh", "stale", "unavailable"] as const;
const BACKUP_STATES = ["verified", "running", "paused", "failed", "unavailable", "unknown"] as const;
const WIPE_STATES = ["verified", "unverified", "unavailable"] as const;
const BUDGET_STATES = ["unknown", "ok", "warning", "blocked"] as const;
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const INCIDENT_STATES = ["open", "acknowledged", "resolved"] as const;

export function parseHealth(value: unknown): HealthProjection {
  const root = asRecord(value);
  if (requiredInteger(root, "schema_version", 3) !== 3) throw new Error("Nicht unterstützte Statusversion.");
  const collectedAt = timestamp(root, "collected_at");
  const sourceRecord = asRecord(root.source);
  const sourceMode = oneOf(
    requiredString(sourceRecord, "mode", 32),
    ["native", "legacy-read-only"] as const,
    "source.mode",
  );
  const sourceVersion = requiredInteger(sourceRecord, "schema_version", 1);
  if (sourceVersion > 3) throw new Error("Ungültiges API-Feld: source.schema_version");

  const services = requiredArray(root, "services", 50).map((entry) => {
    const record = asRecord(entry);
    return {
      id: requiredString(record, "id", 128),
      kind: requiredString(record, "kind", 64),
      state: oneOf(requiredString(record, "state", 32), SERVICE_STATES, "service.state"),
      observedAt: optionalTimestamp(record, "observed_at"),
      detail: optionalString(record, "detail", 500),
    };
  });

  const devices = requiredArray(root, "devices", 25).map(parseDevice);
  const knownDevices = new Set(devices.map((device) => device.id));
  const incidents = requiredArray(root, "incidents", 2_000).map((entry) => parseIncident(entry, knownDevices));
  const budgets = asRecord(root.budgets);

  return {
    collectedAt,
    source: { mode: sourceMode, schemaVersion: sourceVersion },
    services,
    devices,
    incidents,
    budgets: {
      awsMonthlyLimitUSD: boundedInteger(budgets, "aws_monthly_limit_usd", 100_000),
      cloudflareMonthlyLimitUSD: boundedInteger(budgets, "cloudflare_monthly_limit_usd", 100_000),
      awsState: oneOf(requiredString(budgets, "aws_state", 32), BUDGET_STATES, "budgets.aws_state"),
      cloudflareState: oneOf(
        requiredString(budgets, "cloudflare_state", 32),
        BUDGET_STATES,
        "budgets.cloudflare_state",
      ),
    },
  };
}

function parseDevice(value: unknown): Device {
  const record = asRecord(value);
  const management = asRecord(record.management);
  const posture = asRecord(record.posture);
  const telemetry = asRecord(record.telemetry);
  const backup = asRecord(record.backup);
  const wipe = asRecord(record.wipe);
  const sensors = requiredArray(record, "sensors", 24).map((entry) => {
    const sensor = asRecord(entry);
    const kind = requiredString(sensor, "kind", 64);
    const coverage = oneOf(
      requiredString(sensor, "coverage", 32),
      ["full", "partial", "unavailable"] as const,
      "sensor.coverage",
    );
    return `${kind}: ${coverageLabel(coverage)}`;
  });
  const incidentRefs = requiredArray(record, "incident_refs", 2_000).map((entry) => {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > 128)
      throw new Error("Ungültige Incident-Referenz.");
    return entry;
  });
  return {
    id: requiredString(record, "id", 128),
    displayName: requiredString(record, "display_name", 256),
    platform: oneOf(requiredString(record, "platform", 32), ["macos", "ios", "linux"] as const, "device.platform"),
    management: oneOf(requiredString(management, "state", 32), MANAGEMENT_STATES, "management.state"),
    posture: oneOf(requiredString(posture, "state", 32), POSTURE_STATES, "posture.state"),
    telemetry: oneOf(requiredString(telemetry, "state", 32), TELEMETRY_STATES, "telemetry.state"),
    lastSeenAt: optionalTimestamp(telemetry, "last_seen_at"),
    backup: oneOf(requiredString(backup, "state", 32), BACKUP_STATES, "backup.state"),
    wipe: oneOf(requiredString(wipe, "state", 32), WIPE_STATES, "wipe.state"),
    sensorSummary: sensors.length === 0 ? "Keine Sensoren gemeldet" : sensors.join(" · "),
    incidentRefs,
  };
}

function parseIncident(value: unknown, knownDevices: Set<string>): Incident {
  const record = asRecord(value);
  const deviceId = optionalString(record, "device_id", 128);
  if (deviceId !== null && !knownDevices.has(deviceId)) throw new Error("Incident verweist auf ein unbekanntes Gerät.");
  return {
    id: requiredString(record, "id", 128),
    deviceId,
    severity: oneOf(requiredString(record, "severity", 32), SEVERITIES, "incident.severity"),
    state: oneOf(requiredString(record, "state", 32), INCIDENT_STATES, "incident.state"),
    kind: requiredString(record, "kind", 128),
    occurredAt: timestamp(record, "occurred_at"),
    summary: requiredString(record, "summary", 1_000),
  };
}

function optionalString(record: Record<string, unknown>, field: string, maximum: number): string | null {
  const value = record[field];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > maximum) throw new Error(`Ungültiges API-Feld: ${field}`);
  return value;
}

function timestamp(record: Record<string, unknown>, field: string): string {
  const value = requiredString(record, field, 64);
  if (Number.isNaN(Date.parse(value))) throw new Error(`Ungültiger Zeitpunkt: ${field}`);
  return value;
}

function optionalTimestamp(record: Record<string, unknown>, field: string): string | null {
  const value = optionalString(record, field, 64);
  if (value !== null && Number.isNaN(Date.parse(value))) throw new Error(`Ungültiger Zeitpunkt: ${field}`);
  return value;
}

function boundedInteger(record: Record<string, unknown>, field: string, maximum: number): number {
  const value = requiredInteger(record, field, 0);
  if (value > maximum) throw new Error(`Ungültiges API-Feld: ${field}`);
  return value;
}

function oneOf<const T extends readonly string[]>(value: string, choices: T, field: string): T[number] {
  if (!choices.includes(value)) throw new Error(`Ungültiges API-Feld: ${field}`);
  return value as T[number];
}

function coverageLabel(value: "full" | "partial" | "unavailable"): string {
  return value === "full" ? "voll" : value === "partial" ? "teilweise" : "nicht verfügbar";
}
