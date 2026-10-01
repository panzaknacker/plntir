const MAX_BODY_BYTES = 16 * 1024;
const MAXIMUM_AGE_MS = 48 * 60 * 60 * 1000;
const MAXIMUM_FUTURE_MS = 5 * 60 * 1000;
const TOKEN = /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const UTC_SECOND =
  /^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const UTC_DATE = /^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_64 = /^[A-Za-z0-9_-]{86}$/;

const EXPECTED_KEYS = [
  "chain_hash",
  "created_at",
  "date",
  "deduplication_id",
  "kind",
  "sequence",
  "signature",
  "source",
  "version",
];

function response(status) {
  return new Response(null, {
    status,
    headers: {
      "Cache-Control": "no-store, max-age=0",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
      "Cross-Origin-Resource-Policy": "same-origin",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function sealed(environment) {
  return (
    typeof environment.EXPECTED_HOSTNAME === "string" &&
    /^[a-z0-9.-]{3,253}$/.test(environment.EXPECTED_HOSTNAME) &&
    environment.EXPECTED_HOSTNAME !== "SET_AT_PRODUCTION_SEAL" &&
    typeof environment.WAZUH_ANCHOR_VERIFY_KEY === "string" &&
    BASE64URL_32.test(environment.WAZUH_ANCHOR_VERIFY_KEY) &&
    typeof environment.WAZUH_MTLS_CERT_SHA256 === "string" &&
    SHA256_HEX.test(environment.WAZUH_MTLS_CERT_SHA256) &&
    environment.WAZUH_ANCHORS &&
    typeof environment.WAZUH_ANCHORS.put === "function" &&
    typeof environment.WAZUH_ANCHORS.get === "function"
  );
}

function hasBoundClientCertificate(request, environment) {
  const tls = request.cf?.tlsClientAuth;
  const fingerprint = String(tls?.certFingerprintSHA256 ?? "")
    .replaceAll(":", "")
    .toLowerCase();
  return tls?.certVerify === "SUCCESS" && fingerprint === environment.WAZUH_MTLS_CERT_SHA256;
}

export function decodeBase64URL(value, expectedBytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid base64url");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("invalid base64url");
  }
  const result = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (result.byteLength !== expectedBytes || encodeBase64URL(result) !== value) {
    throw new Error("non-canonical base64url");
  }
  return result;
}

export function encodeBase64URL(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function appendUint64(target, value) {
  const encoded = new Uint8Array(8);
  new DataView(encoded.buffer).setBigUint64(0, BigInt(value), false);
  target.push(...encoded);
}

function appendField(target, value) {
  const encoded = new TextEncoder().encode(value);
  appendUint64(target, encoded.byteLength);
  target.push(...encoded);
}

export function canonicalUnsigned(anchor) {
  const result = [...new TextEncoder().encode("plntir-wazuh-hash-anchor-v1\0")];
  appendUint64(result, anchor.version);
  for (const field of [
    anchor.kind,
    anchor.source,
    anchor.date,
    String(anchor.sequence),
    anchor.chain_hash,
    anchor.created_at,
    anchor.deduplication_id,
  ]) {
    appendField(result, field);
  }
  return new Uint8Array(result);
}

function canonicalJSON(anchor) {
  const ordered = {};
  for (const key of EXPECTED_KEYS) ordered[key] = anchor[key];
  return `${JSON.stringify(ordered)}\n`;
}

function validateAnchor(value, raw, now) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid root");
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(EXPECTED_KEYS)) throw new Error("invalid fields");
  if (canonicalJSON(value) !== raw) throw new Error("non-canonical JSON");
  if (value.version !== 1 || value.kind !== "wazuh-daily-hash-anchor" || value.source !== "plntir-siem-01") {
    throw new Error("invalid identity");
  }
  if (!Number.isSafeInteger(value.sequence) || value.sequence <= 0) throw new Error("invalid sequence");
  if (!UTC_DATE.test(value.date) || !UTC_SECOND.test(value.created_at)) throw new Error("invalid time syntax");
  const timestamp = Date.parse(value.created_at);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value.created_at.replace("Z", ".000Z")) {
    throw new Error("invalid calendar time");
  }
  if (value.date !== value.created_at.slice(0, 10)) throw new Error("date mismatch");
  if (timestamp < now - MAXIMUM_AGE_MS || timestamp > now + MAXIMUM_FUTURE_MS) throw new Error("stale anchor");
  if (!TOKEN.test(value.deduplication_id) || value.deduplication_id !== `anchor-${value.date}-${value.sequence}`) {
    throw new Error("invalid deduplication id");
  }
  if (!BASE64URL_32.test(value.chain_hash) || !BASE64URL_64.test(value.signature)) throw new Error("invalid encoding");
  decodeBase64URL(value.chain_hash, 32);
  decodeBase64URL(value.signature, 64);
}

async function verifyAnchor(anchor, encodedKey) {
  const key = await crypto.subtle.importKey("raw", decodeBase64URL(encodedKey, 32), { name: "Ed25519" }, false, [
    "verify",
  ]);
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    decodeBase64URL(anchor.signature, 64),
    canonicalUnsigned(anchor),
  );
}

async function equalStoredObject(object, raw) {
  if (!object || typeof object.arrayBuffer !== "function") return false;
  const stored = new Uint8Array(await object.arrayBuffer());
  const expected = new TextEncoder().encode(raw);
  if (stored.byteLength !== expected.byteLength) return false;
  let different = 0;
  for (let index = 0; index < stored.byteLength; index += 1) different |= stored[index] ^ expected[index];
  return different === 0;
}

export async function handle(request, environment, now = Date.now()) {
  if (!sealed(environment)) return response(503);
  const url = new URL(request.url);
  if (
    request.method !== "POST" ||
    url.protocol !== "https:" ||
    url.hostname !== environment.EXPECTED_HOSTNAME ||
    url.pathname !== "/internal/v1/wazuh/hash-anchor" ||
    url.search !== ""
  ) {
    return response(404);
  }
  if (!hasBoundClientCertificate(request, environment)) return response(404);
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType !== "application/json") return response(415);
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isSafeInteger(declaredLength) || declaredLength < 1 || declaredLength > MAX_BODY_BYTES) {
    return response(413);
  }
  let rawBytes;
  try {
    rawBytes = new Uint8Array(await request.arrayBuffer());
  } catch {
    return response(400);
  }
  if (rawBytes.byteLength !== declaredLength || rawBytes.byteLength > MAX_BODY_BYTES) return response(400);
  let raw;
  let anchor;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
    anchor = JSON.parse(raw);
    validateAnchor(anchor, raw, now);
  } catch {
    return response(400);
  }
  try {
    if (!(await verifyAnchor(anchor, environment.WAZUH_ANCHOR_VERIFY_KEY))) return response(401);
  } catch {
    return response(401);
  }
  const key = `anchors/${anchor.date}.json`;
  const digest = await crypto.subtle.digest("SHA-256", rawBytes);
  const stored = await environment.WAZUH_ANCHORS.put(key, rawBytes, {
    onlyIf: new Headers({ "If-None-Match": "*" }),
    httpMetadata: { contentType: "application/json", cacheControl: "no-store" },
    customMetadata: {
      chain_hash: anchor.chain_hash,
      sequence: String(anchor.sequence),
      source: anchor.source,
    },
    sha256: digest,
  });
  if (stored) return response(201);
  const existing = await environment.WAZUH_ANCHORS.get(key);
  return response((await equalStoredObject(existing, raw)) ? 204 : 409);
}

export default {
  fetch(request, environment) {
    return handle(request, environment);
  },
};
