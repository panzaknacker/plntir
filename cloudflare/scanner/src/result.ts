import { decodeBase64URL, type ScanJob } from "./model";

const encoder = new TextEncoder();

export interface ScanVerdict {
  verdict: "clean" | "malware" | "unscannable" | "failed";
  engineVersion: string;
  ruleVersion: string;
  contentSHA256: string;
  detectedType: string;
  reason: string;
  scannedAt: string;
}

export interface ScanResultPayload {
  scan_job_id: string;
  file_version_id: string;
  object_key: string;
  event_time: string;
  verdict: ScanVerdict["verdict"];
  engine_version: string;
  rule_version: string;
  content_sha256: string;
  detected_type: string;
  reason: string;
  scanned_at: string;
}

export interface SignedScanResult {
  version: 1;
  kind: "scan-result";
  source: string;
  sequence: 1;
  timestamp: string;
  deduplication_id: string;
  payload: ScanResultPayload;
  signature: string;
}

export async function signScanResult(
  job: ScanJob,
  verdict: ScanVerdict,
  privateKeyPKCS8: string,
): Promise<SignedScanResult> {
  validateVerdict(verdict);
  const payload: ScanResultPayload = {
    scan_job_id: job.jobID,
    file_version_id: job.fileVersionID,
    object_key: job.objectKey,
    event_time: job.eventTime,
    verdict: verdict.verdict,
    engine_version: verdict.engineVersion,
    rule_version: verdict.ruleVersion,
    content_sha256: verdict.contentSHA256,
    detected_type: verdict.detectedType,
    reason: verdict.reason,
    scanned_at: verdict.scannedAt,
  };
  const unsigned: Omit<SignedScanResult, "signature"> = {
    version: 1,
    kind: "scan-result",
    source: `scanner-${job.jobID}`,
    sequence: 1,
    timestamp: verdict.scannedAt,
    deduplication_id: job.jobID,
    payload,
  };
  const keyBytes = decodeBase64URL(privateKeyPKCS8, undefined, "result signing key", 40, 128);
  let privateKey: CryptoKey;
  try {
    privateKey = await crypto.subtle.importKey("pkcs8", keyBytes, { name: "Ed25519" }, false, ["sign"]);
  } catch {
    throw new Error("result signing key is not an Ed25519 PKCS8 key");
  }
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, canonicalResultEnvelope(unsigned));
  return { ...unsigned, signature: base64URL(new Uint8Array(signature)) };
}

export function canonicalResultEnvelope(value: Omit<SignedScanResult, "signature">): Uint8Array {
  const output: number[] = [...encoder.encode("plntir-internal-envelope-v1\0")];
  appendUint64(output, BigInt(value.version));
  appendField(output, encoder.encode(value.kind));
  appendField(output, encoder.encode(value.source));
  appendUint64(output, BigInt(value.sequence));
  appendField(output, encoder.encode(value.timestamp));
  appendField(output, encoder.encode(value.deduplication_id));
  appendField(output, encoder.encode(JSON.stringify(value.payload)));
  return Uint8Array.from(output);
}

function appendField(target: number[], field: Uint8Array): void {
  appendUint64(target, BigInt(field.byteLength));
  target.push(...field);
}

function appendUint64(target: number[], value: bigint): void {
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setBigUint64(0, value, false);
  target.push(...new Uint8Array(buffer));
}

function validateVerdict(verdict: ScanVerdict): void {
  if (!["clean", "malware", "unscannable", "failed"].includes(verdict.verdict)) {
    throw new Error("scan verdict is invalid");
  }
  if (
    verdict.engineVersion.length < 1 ||
    verdict.engineVersion.length > 256 ||
    verdict.ruleVersion.length > 256 ||
    verdict.detectedType.length > 256 ||
    verdict.reason.length > 1024 ||
    /[\u0000\r\n]/.test(verdict.engineVersion + verdict.ruleVersion + verdict.detectedType + verdict.reason)
  ) {
    throw new Error("scan verdict metadata is invalid");
  }
  if ((verdict.verdict === "clean" || verdict.verdict === "malware") && !/^[a-f0-9]{64}$/.test(verdict.contentSHA256)) {
    throw new Error("complete scan verdict requires a SHA-256");
  }
  if (verdict.contentSHA256 !== "" && !/^[a-f0-9]{64}$/.test(verdict.contentSHA256)) {
    throw new Error("scan verdict SHA-256 is invalid");
  }
  if (!Number.isFinite(Date.parse(verdict.scannedAt))) {
    throw new Error("scan verdict timestamp is invalid");
  }
}

function base64URL(value: Uint8Array): string {
  let raw = "";
  for (const byte of value) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
