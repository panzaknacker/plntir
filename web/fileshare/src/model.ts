import { asRecord, requiredArray, requiredInteger, requiredString } from "../../shared/http";

export interface Session {
  accountId: string;
  deviceId: string;
  expiresAt: string;
  idleExpiresAt: string;
  stepUpActive: boolean;
}

export interface SharedFile {
  id: string;
  filename: string;
  ownerAccountId: string;
  logicalSizeBytes: number;
  scanState: "pending_upload" | "queued" | "scanning" | "clean" | "malware" | "unscannable" | "failed";
  state: "uploading" | "active" | "trashed" | "deletion_pending" | "purged";
  version: number;
}

export interface FilesPage {
  items: SharedFile[];
  nextCursor: string | null;
}

const SCAN_STATES = ["pending_upload", "queued", "scanning", "clean", "malware", "unscannable", "failed"] as const;
const FILE_STATES = ["uploading", "active", "trashed", "deletion_pending", "purged"] as const;

export function parseSession(value: unknown): Session {
  const record = asRecord(value);
  const stepUp = record.step_up_active;
  if (typeof stepUp !== "boolean") throw new Error("Ungültiges API-Feld: step_up_active");
  return {
    accountId: requiredString(record, "account_id", 128),
    deviceId: requiredString(record, "device_id", 128),
    expiresAt: timestamp(record, "expires_at"),
    idleExpiresAt: timestamp(record, "idle_expires_at"),
    stepUpActive: stepUp,
  };
}

export function parseFiles(value: unknown): FilesPage {
  const root = asRecord(value);
  const items = requiredArray(root, "items", 1_000).map((entry) => {
    const record = asRecord(entry);
    return {
      id: requiredString(record, "id", 128),
      filename: requiredString(record, "filename", 1_024),
      ownerAccountId: requiredString(record, "owner_account_id", 128),
      logicalSizeBytes: boundedInteger(record, "logical_size_bytes", 500_000_000_000),
      scanState: oneOf(requiredString(record, "scan_state", 32), SCAN_STATES, "scan_state"),
      state: oneOf(requiredString(record, "state", 32), FILE_STATES, "state"),
      version: boundedInteger(record, "version", Number.MAX_SAFE_INTEGER, 1),
    };
  });
  const cursor = root.next_cursor;
  if (cursor !== undefined && cursor !== null && (typeof cursor !== "string" || cursor.length > 2_048)) {
    throw new Error("Ungültiges API-Feld: next_cursor");
  }
  return { items, nextCursor: typeof cursor === "string" ? cursor : null };
}

function boundedInteger(record: Record<string, unknown>, field: string, maximum: number, minimum = 0): number {
  const value = requiredInteger(record, field, minimum);
  if (value > maximum) throw new Error(`Ungültiges API-Feld: ${field}`);
  return value;
}

function timestamp(record: Record<string, unknown>, field: string): string {
  const value = requiredString(record, field, 64);
  if (Number.isNaN(Date.parse(value))) throw new Error(`Ungültiger Zeitpunkt: ${field}`);
  return value;
}

function oneOf<const T extends readonly string[]>(value: string, choices: T, field: string): T[number] {
  if (!choices.includes(value)) throw new Error(`Ungültiges API-Feld: ${field}`);
  return value as T[number];
}
