export const MAX_CIPHERTEXT_BYTES = 500_200_000_000;
export const MAX_PLAINTEXT_BYTES = 500_000_000_000;
export const MAX_STANDARD_BYTES = 5_000_000_000;
export const MIN_MEDIA_CHUNK_BYTES = 64 * 1024 * 1024;
export const MAX_CHUNKS = 10_000;

const SAFE_ID = /^[a-z][a-z0-9]{0,15}_[0-9a-hjkmnp-tv-z]{32}$/;
const ACCOUNT_ID = /^[a-f0-9]{32}$/;
const BUCKET = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
const OBJECT_KEY = /^objects\/obj_[0-9a-hjkmnp-tv-z]{32}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ETAG = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,256}$/;
const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export type MediaKind = "standard" | "image" | "video";

export interface R2EventNotification {
  account: string;
  action: string;
  bucket: string;
  object: {
    key: string;
    size: number;
    eTag: string;
  };
  eventTime: string;
}

export interface ObjectMetadata {
  jobID: string;
  fileVersionID: string;
  mediaKind: MediaKind;
  manifestSHA256: string;
  kmsCiphertext: string;
  kmsCiphertextSHA256: string;
  plaintextSize: number;
  chunkSize: number;
  noncePrefix: string;
  signedAt: string;
  signature: string;
}

export interface ScanJob extends ObjectMetadata {
  account: string;
  action: "PutObject" | "CompleteMultipartUpload";
  bucket: string;
  objectKey: string;
  ciphertextSize: number;
  eTag: string;
  eventTime: string;
}

export class PermanentEventError extends Error {
  override readonly name = "PermanentEventError";
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PermanentEventError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new PermanentEventError(`${label} is invalid`);
  }
  return value;
}

function requiredInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new PermanentEventError(`${label} is invalid`);
  }
  return value as number;
}

export function parseR2Event(value: unknown): R2EventNotification {
  const input = record(value, "event");
  const object = record(input.object, "event.object");
  const result: R2EventNotification = {
    account: requiredString(input.account, "event.account", 64),
    action: requiredString(input.action, "event.action", 64),
    bucket: requiredString(input.bucket, "event.bucket", 128),
    object: {
      key: requiredString(object.key, "event.object.key", 256),
      size: requiredInteger(object.size, "event.object.size", 1, MAX_CIPHERTEXT_BYTES),
      eTag: requiredString(object.eTag, "event.object.eTag", 256),
    },
    eventTime: requiredString(input.eventTime, "event.eventTime", 64),
  };
  if (result.action !== "PutObject" && result.action !== "CompleteMultipartUpload") {
    throw new PermanentEventError("event action cannot produce a scan job");
  }
  if (!ACCOUNT_ID.test(result.account) || !BUCKET.test(result.bucket)) {
    throw new PermanentEventError("event account or bucket is invalid");
  }
  if (!OBJECT_KEY.test(result.object.key) || !ETAG.test(result.object.eTag)) {
    throw new PermanentEventError("event object identity is invalid");
  }
  if (!Number.isFinite(Date.parse(result.eventTime))) {
    throw new PermanentEventError("event time is invalid");
  }
  return result;
}

export function parseObjectMetadata(customMetadata: Record<string, string> | undefined): ObjectMetadata {
  if (customMetadata === undefined) {
    throw new PermanentEventError("object has no signed metadata");
  }
  const jobID = requiredString(customMetadata["plntir-job-id"], "job id", 64);
  const fileVersionID = requiredString(customMetadata["plntir-file-version-id"], "file version id", 64);
  const mediaKind = requiredString(customMetadata["plntir-media-kind"], "media kind", 16);
  const manifestSHA256 = requiredString(customMetadata["plntir-manifest-sha256"], "manifest hash", 64);
  const kmsCiphertext = requiredString(customMetadata["plntir-kms-ciphertext"], "KMS ciphertext", 8192);
  const kmsCiphertextSHA256 = requiredString(customMetadata["plntir-kms-ciphertext-sha256"], "KMS ciphertext hash", 64);
  const plaintextSize = Number(requiredString(customMetadata["plntir-plaintext-size"], "plaintext size", 16));
  const chunkSize = Number(requiredString(customMetadata["plntir-chunk-size"], "chunk size", 16));
  const noncePrefix = requiredString(customMetadata["plntir-nonce-prefix"], "nonce prefix", 16);
  const signedAt = requiredString(customMetadata["plntir-signed-at"], "signed at", 64);
  const signature = requiredString(customMetadata["plntir-signature"], "metadata signature", 128);
  if (!SAFE_ID.test(jobID) || !jobID.startsWith("scan_")) {
    throw new PermanentEventError("scan job id is invalid");
  }
  if (!SAFE_ID.test(fileVersionID) || !fileVersionID.startsWith("fver_")) {
    throw new PermanentEventError("file version id is invalid");
  }
  if (mediaKind !== "standard" && mediaKind !== "image" && mediaKind !== "video") {
    throw new PermanentEventError("media kind is invalid");
  }
  if (!SHA256.test(manifestSHA256) || !SHA256.test(kmsCiphertextSHA256)) {
    throw new PermanentEventError("metadata hash is invalid");
  }
  if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 1 || plaintextSize > MAX_PLAINTEXT_BYTES) {
    throw new PermanentEventError("plaintext size is invalid");
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1 || chunkSize > 1024 * 1024 * 1024) {
    throw new PermanentEventError("chunk size is invalid");
  }
  if (mediaKind === "standard" && plaintextSize > MAX_STANDARD_BYTES) {
    throw new PermanentEventError("standard object exceeds 5 GB");
  }
  if (plaintextSize > MAX_STANDARD_BYTES && chunkSize < MIN_MEDIA_CHUNK_BYTES) {
    throw new PermanentEventError("large media chunk is smaller than 64 MiB");
  }
  if (Math.ceil(plaintextSize / chunkSize) > MAX_CHUNKS) {
    throw new PermanentEventError("object exceeds multipart chunk limit");
  }
  if (!CANONICAL_TIMESTAMP.test(signedAt) || !Number.isFinite(Date.parse(signedAt))) {
    throw new PermanentEventError("signed-at timestamp is invalid");
  }
  decodeBase64URL(noncePrefix, 4, "nonce prefix");
  decodeBase64URL(kmsCiphertext, undefined, "KMS ciphertext", 1, 6144);
  decodeBase64URL(signature, 64, "metadata signature");
  return {
    jobID,
    fileVersionID,
    mediaKind,
    manifestSHA256,
    kmsCiphertext,
    kmsCiphertextSHA256,
    plaintextSize,
    chunkSize,
    noncePrefix,
    signedAt,
    signature,
  };
}

export function decodeBase64URL(
  input: string,
  exactLength: number | undefined,
  label: string,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw new PermanentEventError(`${label} is not base64url`);
  }
  const padded = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(input.length / 4) * 4, "=");
  let raw: string;
  try {
    raw = atob(padded);
  } catch {
    throw new PermanentEventError(`${label} is not base64url`);
  }
  const bytes = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  if (
    (exactLength !== undefined && bytes.byteLength !== exactLength) ||
    bytes.byteLength < minimum ||
    bytes.byteLength > maximum
  ) {
    throw new PermanentEventError(`${label} has an invalid decoded length`);
  }
  let canonical = "";
  for (const byte of bytes) {
    canonical += String.fromCharCode(byte);
  }
  canonical = btoa(canonical).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (canonical !== input) {
    throw new PermanentEventError(`${label} is not canonical base64url`);
  }
  return bytes;
}
